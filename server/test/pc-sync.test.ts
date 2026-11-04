import { spawn } from 'node:child_process';
import { appendFileSync, existsSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { encodeCwd, maskLine, maskRegistry, MAX_INITIAL_BYTES, MAX_STRING, Tail } from '../../scripts/pc-sync';
import { encodeCwd as serverEncodeCwd } from '../sources/watcher';
import { tempDir } from './fixtures';

const closers: Array<() => void> = [];
afterEach(() => {
  for (const c of closers.splice(0)) c();
});
const tmp = () => {
  const t = tempDir();
  closers.push(() => t.cleanup());
  return t.dir;
};

describe('o que sai do computador', () => {
  it('nenhuma senha sai do computador, em nenhum nível do transcript', () => {
    const line = JSON.stringify({
      type: 'assistant',
      message: { content: [{ type: 'tool_use', name: 'Bash', input: { command: 'sshpass -p segredo123 ssh root@192.0.2.10 uptime' } }] },
      extra: ['mysql -uroot -psegredo456 db', { deep: 'echo root:segredo789 | chpasswd' }],
    });
    const out = maskLine(line) as string;
    for (const secret of ['segredo123', 'segredo456', 'segredo789']) expect(out).not.toContain(secret);
    expect(JSON.parse(out).type).toBe('assistant');
    expect(out).toContain('root@192.0.2.10');
  });

  it('corta texto gigante (imagem em base64) e recusa o que não é JSON', () => {
    const out = maskLine(JSON.stringify({ data: 'A'.repeat(MAX_STRING * 3) })) as string;
    expect(out.length).toBeLessThan(MAX_STRING + 100);
    expect(maskLine('{ quebrado')).toBeUndefined();
  });

  it('o registro leva só os campos do escritório: socket e domínio do PID ficam', () => {
    const raw = JSON.stringify({ pid: 7, sessionId: 's', cwd: 'c:\\x', status: 'busy', messagingSocketPath: '\\\\.\\pipe\\x', pidDomain: 'win32:maquina', name: 'token=abc123' });
    const out = JSON.parse(maskRegistry(raw)?.text ?? '{}');
    expect(out).toEqual({ pid: 7, sessionId: 's', cwd: 'c:\\x', status: 'busy', name: 'token=***' });
    expect(maskRegistry('{}')).toBeUndefined();
  });

  it('a pasta de um cwd do Windows é a mesma que o servidor procura', () => {
    const cwd = 'c:\\Users\\alguem\\Documents\\repo';
    expect(encodeCwd(cwd)).toBe('c--Users-alguem-Documents-repo');
    expect(serverEncodeCwd(cwd)).toBe(encodeCwd(cwd));
  });
});

describe('Tail', () => {
  it('só entrega linhas completas e continua de onde parou', () => {
    const file = join(tmp(), 'a.jsonl');
    writeFileSync(file, '{"n":1}\n{"n":2}\n{"n"');
    const tail = new Tail(file);
    expect(tail.read()).toEqual(['{"n":1}', '{"n":2}']);
    expect(tail.read()).toEqual([]);
    appendFileSync(file, ':3}\n');
    expect(tail.read()).toEqual(['{"n":3}']);
  });

  it('de conversa grande vai só o fim, a partir de uma linha inteira', () => {
    const file = join(tmp(), 'b.jsonl');
    const line = `${JSON.stringify({ text: 'x'.repeat(1000) })}\n`;
    writeFileSync(file, line.repeat(Math.ceil((MAX_INITIAL_BYTES * 2) / line.length)));
    const lines = new Tail(file).read();
    expect(lines.length).toBeGreaterThan(100);
    expect(lines.length * line.length).toBeLessThanOrEqual(MAX_INITIAL_BYTES);
    for (const l of lines) expect(() => JSON.parse(l)).not.toThrow();
  });

  it('arquivo que diminuiu recomeça e avisa', () => {
    const file = join(tmp(), 'c.jsonl');
    writeFileSync(file, '{"n":1}\n{"n":2}\n');
    const tail = new Tail(file);
    tail.read();
    tail.fresh = false;
    writeFileSync(file, '{"n":9}\n');
    expect(tail.read()).toEqual(['{"n":9}']);
    expect(tail.fresh).toBe(true);
  });
});

describe('pc-receive', () => {
  const receiver = resolve(__dirname, '../../scripts/pc-receive.mjs');
  const start = (dir: string, heartbeatMs = 5000) => {
    const child = spawn(process.execPath, [receiver], { env: { ...process.env, HB_PC_DIR: dir, HB_PC_HEARTBEAT_MS: String(heartbeatMs) } });
    const exited = new Promise<number | null>((ok) => child.once('exit', (code) => ok(code)));
    const send = (m: unknown) => child.stdin.write(`${JSON.stringify(m)}\n`);
    return { child, exited, send };
  };
  const until = async (fn: () => boolean) => {
    for (let i = 0; i < 100 && !fn(); i++) await new Promise((ok) => setTimeout(ok, 30));
    expect(fn()).toBe(true);
  };

  it('grava a sessão e o transcript e apaga tudo ao fechar a conexão', async () => {
    const dir = join(tmp(), 'pc');
    const r = start(dir);
    r.send({ t: 'open', path: 'projects/c--x/abc.jsonl' });
    r.send({ t: 'append', path: 'projects/c--x/abc.jsonl', data: '{"n":1}\n' });
    r.send({ t: 'session', name: '123.json', data: '{"pid":123}' });
    await until(() => existsSync(join(dir, 'sessions', '123.json')));
    expect(readFileSync(join(dir, 'projects/c--x/abc.jsonl'), 'utf8')).toBe('{"n":1}\n');
    expect(existsSync(join(dir, '.habblaud-remote'))).toBe(true);
    r.send({ t: 'close', name: '123.json' });
    await until(() => !existsSync(join(dir, 'sessions', '123.json')));
    r.child.stdin.end();
    await r.exited;
    expect(existsSync(join(dir, 'projects'))).toBe(false);
    expect(existsSync(join(dir, 'sessions'))).toBe(false);
  });

  it('recusa caminho que sai da pasta e nome de sessão estranho', async () => {
    const base = tmp();
    const dir = join(base, 'pc');
    const r = start(dir);
    for (const path of ['../../fora.jsonl', '/etc/fora.jsonl', 'projects/../../fora.jsonl', 'projects/a/../../../fora.jsonl', 'sessions/1.json', 'projects/a/b.sh']) {
      r.send({ t: 'open', path });
      r.send({ t: 'append', path, data: 'x' });
      r.send({ t: 'write', path, data: 'x' });
    }
    r.send({ t: 'session', name: '../../fora.json', data: 'x' });
    r.send({ t: 'open', path: 'projects/ok/fim.jsonl' });
    await until(() => existsSync(join(dir, 'projects/ok/fim.jsonl')));
    expect(readdirSync(base)).toEqual(['pc']);
    expect(readdirSync(join(dir, 'projects'))).toEqual(['ok']);
    expect(readdirSync(join(dir, 'sessions'))).toEqual([]);
    r.child.stdin.end();
    await r.exited;
  });

  it('sem mensagens (computador desligou), termina e apaga', async () => {
    const dir = join(tmp(), 'pc');
    const r = start(dir, 150);
    r.send({ t: 'session', name: '5.json', data: '{}' });
    expect(await r.exited).toBe(3);
    expect(existsSync(join(dir, 'sessions'))).toBe(false);
    expect(existsSync(join(dir, 'projects'))).toBe(false);
  });

  it('dados de uma conexão anterior que morreu são apagados ao começar', async () => {
    const dir = join(tmp(), 'pc');
    const first = start(dir, 100);
    first.send({ t: 'session', name: '1.json', data: '{}' });
    await first.exited;
    const second = start(dir);
    await until(() => existsSync(join(dir, 'sessions')));
    expect(readdirSync(join(dir, 'sessions'))).toEqual([]);
    second.child.stdin.end();
    await second.exited;
  });
});
