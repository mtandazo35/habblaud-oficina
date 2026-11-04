// Segundo fator do acesso remoto: TOTP (RFC 6238, com o HOTP da RFC 4226) e códigos de recuperação, só com node:crypto.
//
// Compatível com Google Authenticator e parecidos: SHA-1, 6 dígitos, 30 s; aceita o passo anterior e o seguinte para
// tolerar relógio torto. Quem guarda o estado (segredo e último passo usado) é a loja de contas, remote/users.ts.
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

export const TOTP_PERIOD_S = 30;
const DIGITS = 6;
const WINDOW = 1;
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const RECOVERY_COUNT = 10;
/** 10 bytes = 80 bits aleatórios: com essa entropia um SHA-256 basta, ninguém testa todas as combinações. */
const RECOVERY_BYTES = 10;

export function base32Encode(data: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of data) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
    value &= (1 << bits) - 1;
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(text: string): Buffer | undefined {
  const clean = text.replace(/=+$/, '').toUpperCase();
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const char of clean) {
    const v = B32.indexOf(char);
    if (v < 0) return undefined;
    value = (value << 5) | v;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
    value &= (1 << bits) - 1;
  }
  return Buffer.from(out);
}

/** Segredo novo: 20 bytes, o tamanho que a RFC 4226 recomenda para SHA-1. */
export function generateSecret(): string {
  return base32Encode(randomBytes(20));
}

export function isTotpSecret(value: unknown): value is string {
  return typeof value === 'string' && /^[A-Z2-7]{16,128}$/.test(value);
}

export function hotp(secret: Buffer, counter: number, digits = DIGITS): string {
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const mac = createHmac('sha1', secret).update(message).digest();
  const offset = mac[mac.length - 1] & 15;
  const code = mac.readUInt32BE(offset) & 0x7fffffff;
  return String(code % 10 ** digits).padStart(digits, '0');
}

export function stepAt(ms: number): number {
  return Math.floor(ms / 1000 / TOTP_PERIOD_S);
}

/** O código de um instante (o que o aplicativo mostraria). */
export function totpAt(secret: string, ms: number): string {
  return hotp(base32Decode(secret) ?? Buffer.alloc(0), stepAt(ms));
}

function sameText(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

/**
 * O passo em que este código vale, dentro da janela e depois de `lastStep`; undefined se não valer. Antes de `lastStep`
 * não vale nada: é o que impede usar de novo o mesmo código, ou um mais antigo, enquanto ele ainda estaria na janela.
 */
export function matchStep(secret: string, code: string, nowMs: number, lastStep: number): number | undefined {
  if (!/^\d{6}$/.test(code)) return undefined;
  const key = base32Decode(secret);
  if (!key) return undefined;
  const current = stepAt(nowMs);
  let found: number | undefined;
  // Confere a janela inteira, sem sair no primeiro acerto.
  for (let step = current - WINDOW; step <= current + WINDOW; step++) {
    if (sameText(hotp(key, step), code) && step > lastStep && found === undefined) found = step;
  }
  return found;
}

export function otpauthUri(secret: string, account: string, issuer = 'Habblaud'): string {
  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(account)}`;
  return `otpauth://totp/${label}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=${DIGITS}&period=${TOTP_PERIOD_S}`;
}

/** O que a pessoa digitou, sem espaços e hifens e em maiúsculas. */
export function normalizeCode(raw: string): string {
  return raw.slice(0, 64).replace(/[\s-]/g, '').toUpperCase();
}

export function hashRecovery(code: string): string {
  return createHash('sha256').update(normalizeCode(code), 'utf8').digest('hex');
}

export function isRecoveryHash(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

/** Códigos para mostrar uma única vez, e os hashes que ficam guardados. */
export function generateRecoveryCodes(count = RECOVERY_COUNT): { codes: string[]; hashes: string[] } {
  const codes: string[] = [];
  for (let i = 0; i < count; i++) codes.push((base32Encode(randomBytes(RECOVERY_BYTES)).match(/.{4}/g) ?? []).join('-'));
  return { codes, hashes: codes.map(hashRecovery) };
}

/** Em qual posição da lista está este código (-1 = em nenhuma). Compara todos, sem sair no primeiro acerto. */
export function findRecovery(hashes: readonly string[], code: string): number {
  const wanted = hashRecovery(code);
  let found = -1;
  hashes.forEach((h, i) => {
    if (sameText(h, wanted) && found < 0) found = i;
  });
  return found;
}
