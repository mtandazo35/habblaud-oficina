import { chmodSync, existsSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { tempDir } from '../test/fixtures';
import { AuditLog, cleanField } from './audit';

const closers: Array<() => void> = [];
afterEach(() => {
  for (const c of closers.splice(0)) c();
});

function setup(opts: ConstructorParameters<typeof AuditLog>[1] = {}) {
  const tmp = tempDir();
  closers.push(() => tmp.cleanup());
  const file = join(tmp.dir, 'sub', 'remote-audit.log');
  return { file, audit: new AuditLog(file, opts) };
}

describe('registro de acessos', () => {
  it('grava uma linha JSON por evento, com data e permissão 600', () => {
    const { file, audit } = setup({ now: () => Date.UTC(2026, 0, 2, 3, 4, 5) });
    audit.write('login.ok', { user: 'ana', ip: '192.0.2.1', via: 'totp' });
    audit.write('logout', { user: 'ana', ip: '192.0.2.1' });
    const lines = readFileSync(file, 'utf8').trim().split('\n');
    expect(lines).toHaveLength(2);
    expect(JSON.parse(lines[0])).toEqual({ t: '2026-01-02T03:04:05.000Z', ev: 'login.ok', user: 'ana', ip: '192.0.2.1', via: 'totp' });
    if (process.platform !== 'win32') expect(statSync(file).mode & 0o777).toBe(0o600);
  });

  it('corrige um arquivo que já existia com permissão frouxa', () => {
    const { file, audit } = setup();
    audit.write('logout', { user: 'a' });
    if (process.platform === 'win32') return;
    chmodSync(file, 0o644);
    const again = new AuditLog(file);
    again.write('logout', { user: 'b' });
    expect(statSync(file).mode & 0o777).toBe(0o600);
  });

  it('um usuário digitado não forja linhas nem leva controle ao terminal', () => {
    const { file, audit } = setup();
    const evil = 'ana\n{"t":"x","ev":"login.ok","user":"chefe"}\r \u001b[31mfim';
    audit.write('login.fail', { user: evil, ip: '192.0.2.1', reason: 'credentials' });
    const lines = readFileSync(file, 'utf8').trim().split('\n');
    expect(lines).toHaveLength(1);
    const entry = JSON.parse(lines[0]) as { user: string; ev: string };
    expect(entry.ev).toBe('login.fail');
    // eslint-disable-next-line no-control-regex
    expect(entry.user).not.toMatch(/[\u0000-\u001f  \u007f]/);
    expect(readFileSync(file, 'utf8')).not.toMatch(/ |\u001b/);
  });

  it('corta campos compridos e ignora o que não é campo conhecido', () => {
    const { audit } = setup();
    expect(cleanField('x'.repeat(500))).toHaveLength(64);
    audit.write('login.fail', { user: 'y'.repeat(500), password: 'segredo', code: '123456' } as never);
    const [entry] = audit.read();
    expect(entry.user).toHaveLength(64);
    expect(JSON.stringify(entry)).not.toContain('segredo');
    expect(JSON.stringify(entry)).not.toContain('123456');
  });

  it('roda por tamanho, guarda um arquivo antigo e a leitura junta os dois', () => {
    const { file, audit } = setup({ maxBytes: 200 });
    for (let i = 0; i < 20; i++) audit.write('logout', { user: `u${i}` });
    expect(existsSync(`${file}.1`)).toBe(true);
    expect(statSync(file).size).toBeLessThan(300);
    expect(statSync(`${file}.1`).size).toBeLessThan(300);
    if (process.platform !== 'win32') expect(statSync(`${file}.1`).mode & 0o777).toBe(0o600);
    const read = audit.read(5);
    expect(read.map((e) => e.user)).toEqual(['u19', 'u18', 'u17', 'u16', 'u15']);
    expect(audit.read(1000).length).toBeGreaterThan(new AuditLog(file).read(1).length);
  });

  it('a leitura mostra o mais novo primeiro, pula lixo e limpa o que estiver no arquivo', () => {
    const { file, audit } = setup();
    audit.write('logout', { user: 'a' });
    writeFileSync(file, `${readFileSync(file, 'utf8')}nao e json\n{"t":"2026-01-01T00:00:00Z","ev":"logout","user":"b\\u001b[31m"}\n{"sem":"data"}\n`);
    const read = audit.read();
    expect(read.map((e) => e.user)).toEqual(['b?[31m', 'a']);
  });

  it('sem arquivo a leitura é vazia, e falha ao gravar não derruba quem chamou', () => {
    const tmp = tempDir();
    closers.push(() => tmp.cleanup());
    const errors: string[] = [];
    expect(new AuditLog(join(tmp.dir, 'nada.log')).read()).toEqual([]);
    // O "arquivo pai" é um arquivo: não dá para criar a pasta nem gravar.
    writeFileSync(join(tmp.dir, 'pai'), '');
    const broken = new AuditLog(join(tmp.dir, 'pai', 'x.log'), { onError: (m) => errors.push(m) });
    expect(() => broken.write('logout', { user: 'a' })).not.toThrow();
    broken.write('logout', { user: 'a' });
    expect(errors).toHaveLength(1);
  });
});
