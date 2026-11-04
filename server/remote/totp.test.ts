import { describe, expect, it } from 'vitest';
import { base32Decode, base32Encode, findRecovery, generateRecoveryCodes, generateSecret, hashRecovery, hotp, isRecoveryHash, isTotpSecret, matchStep, otpauthUri, stepAt, totpAt } from './totp';

// Segredo dos vetores de teste das RFCs: "12345678901234567890" em ASCII.
const RFC_KEY = Buffer.from('12345678901234567890');
const RFC_SECRET = base32Encode(RFC_KEY);

describe('TOTP', () => {
  it('confere os vetores da RFC 4226 (HOTP)', () => {
    const expected = ['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489'];
    expected.forEach((code, counter) => expect(hotp(RFC_KEY, counter)).toBe(code));
  });

  it('confere os vetores da RFC 6238 (SHA-1, com 8 dígitos como na tabela)', () => {
    const table: Array<[number, string]> = [
      [59, '94287082'],
      [1111111109, '07081804'],
      [1111111111, '14050471'],
      [1234567890, '89005924'],
      [2000000000, '69279037'],
      [20000000000, '65353130'],
    ];
    for (const [seconds, code] of table) expect(hotp(RFC_KEY, stepAt(seconds * 1000), 8)).toBe(code);
  });

  it('6 dígitos, com zero à esquerda quando preciso', () => {
    expect(totpAt(RFC_SECRET, 1111111109 * 1000)).toBe('081804');
  });

  it('base32 vai e volta e recusa o que não é base32', () => {
    expect(RFC_SECRET).toBe('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
    expect(base32Decode(RFC_SECRET)?.equals(RFC_KEY)).toBe(true);
    expect(base32Decode('abc1!')).toBeUndefined();
  });

  it('segredo novo tem 160 bits e o formato aceito', () => {
    const secret = generateSecret();
    expect(secret).toHaveLength(32);
    expect(isTotpSecret(secret)).toBe(true);
    expect(generateSecret()).not.toBe(secret);
  });

  it('aceita o passo anterior e o seguinte, e nada além', () => {
    const t = 1_700_000_000_000;
    const step = stepAt(t);
    const code = (s: number) => hotp(RFC_KEY, s);
    expect(matchStep(RFC_SECRET, code(step), t, 0)).toBe(step);
    expect(matchStep(RFC_SECRET, code(step - 1), t, 0)).toBe(step - 1);
    expect(matchStep(RFC_SECRET, code(step + 1), t, 0)).toBe(step + 1);
    expect(matchStep(RFC_SECRET, code(step - 2), t, 0)).toBeUndefined();
    expect(matchStep(RFC_SECRET, code(step + 2), t, 0)).toBeUndefined();
  });

  it('não aceita de novo um passo já usado nem um mais antigo', () => {
    const t = 1_700_000_000_000;
    const step = stepAt(t);
    expect(matchStep(RFC_SECRET, hotp(RFC_KEY, step), t, step)).toBeUndefined();
    expect(matchStep(RFC_SECRET, hotp(RFC_KEY, step - 1), t, step)).toBeUndefined();
    expect(matchStep(RFC_SECRET, hotp(RFC_KEY, step + 1), t, step)).toBe(step + 1);
  });

  it('recusa código fora do formato', () => {
    for (const bad of ['', '12345', '1234567', 'abcdef', '12 456']) expect(matchStep(RFC_SECRET, bad, 0, -1)).toBeUndefined();
  });

  it('o endereço otpauth traz o que o Google Authenticator espera', () => {
    const uri = new URL(otpauthUri('GEZDGNBVGY3TQOJQ', 'ana maria'));
    expect(uri.protocol).toBe('otpauth:');
    expect(uri.host).toBe('totp');
    expect(uri.pathname).toBe('/Habblaud:ana%20maria');
    expect(Object.fromEntries(uri.searchParams)).toEqual({ secret: 'GEZDGNBVGY3TQOJQ', issuer: 'Habblaud', algorithm: 'SHA1', digits: '6', period: '30' });
  });
});

describe('códigos de recuperação', () => {
  it('são 10, diferentes, e só o hash fica guardado', () => {
    const { codes, hashes } = generateRecoveryCodes();
    expect(codes).toHaveLength(10);
    expect(new Set(codes).size).toBe(10);
    for (const code of codes) expect(code).toMatch(/^[A-Z2-7]{4}(-[A-Z2-7]{4}){3}$/);
    expect(hashes.every(isRecoveryHash)).toBe(true);
    expect(hashes.join()).not.toContain(codes[0].replace(/-/g, ''));
  });

  it('são achados sem importar hífen, espaço ou caixa', () => {
    const { codes, hashes } = generateRecoveryCodes(3);
    expect(findRecovery(hashes, codes[1])).toBe(1);
    expect(findRecovery(hashes, ` ${codes[2].replace(/-/g, ' ').toLowerCase()} `)).toBe(2);
    expect(findRecovery(hashes, 'AAAA-AAAA-AAAA-AAAA')).toBe(-1);
    expect(hashRecovery(codes[0])).toBe(hashes[0]);
  });
});
