// Mostra no escritório de um servidor as sessões do Claude Code de OUTRO computador (ex.: a extensão do VS Code no PC).
// Roda no computador das sessões, sem instalar nada além deste arquivo: `npm run build:pc-sync` gera dist/pc-sync.cjs.
//
//   node pc-sync.cjs usuario@servidor [--ssh-opt Opcao=valor]...
//
// Só vão as sessões ABERTAS, e cada texto passa por maskSecrets ANTES de sair daqui: o servidor nunca recebe o original.
// Do outro lado está scripts/pc-receive.mjs, que apaga tudo quando a conexão acaba. É só para ver: aprovar permissões e
// mandar mensagens não atravessam de um computador para o outro.
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { once } from 'node:events';
import { closeSync, fstatSync, openSync, readdirSync, readFileSync, readSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { maskSecrets } from '../shared/activity';

const TICK_MS = 1500;
const RETRY_MS = 10_000;
/** Da conversa que já estava aberta vai só o fim: o começo não muda o que o escritório mostra. */
export const MAX_INITIAL_BYTES = 3 * 1024 * 1024;
const MAX_READ_BYTES = 4 * 1024 * 1024;
/** Um texto maior que isto é imagem em base64 ou arquivo inteiro: o escritório não precisa dele. */
export const MAX_STRING = 32 * 1024;
const REGISTRY_FIELDS = ['pid', 'sessionId', 'cwd', 'startedAt', 'version', 'kind', 'entrypoint', 'name', 'status', 'waitingFor', 'agent', 'updatedAt', 'statusUpdatedAt'];

export function encodeCwd(cwd: string): string {
  return cwd.replace(/[^a-zA-Z0-9]/g, '-');
}

export function maskValue(value: unknown): unknown {
  if (typeof value === 'string') return maskSecrets(value.length > MAX_STRING ? `${value.slice(0, MAX_STRING)}…` : value);
  if (Array.isArray(value)) return value.map(maskValue);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, maskValue(v)]));
  }
  return value;
}

/** Uma linha do transcript pronta para sair; undefined = não é JSON, e o que não dá para mascarar não vai. */
export function maskLine(line: string): string | undefined {
  try {
    return JSON.stringify(maskValue(JSON.parse(line)));
  } catch {
    return undefined;
  }
}

/** Só os campos que o escritório lê, mascarados (fica de fora o socket de mensagens, por exemplo). */
export function maskRegistry(raw: string): { pid: number; text: string } | undefined {
  try {
    const entry = JSON.parse(raw) as Record<string, unknown>;
    if (typeof entry.pid !== 'number' || typeof entry.sessionId !== 'string' || typeof entry.cwd !== 'string') return undefined;
    const kept = Object.fromEntries(REGISTRY_FIELDS.filter((k) => entry[k] !== undefined).map((k) => [k, entry[k]]));
    return { pid: entry.pid, text: JSON.stringify(maskValue(kept)) };
  } catch {
    return undefined;
  }
}

/** Acompanha um arquivo de linhas: devolve as linhas completas novas, mascaradas, a cada leitura. */
export class Tail {
  private offset = -1;
  /** O arquivo diminuiu ou é a primeira leitura: quem recebe precisa recomeçar. */
  fresh = true;

  constructor(private readonly path: string) {}

  read(): string[] {
    let fd: number;
    try {
      fd = openSync(this.path, 'r');
    } catch {
      return [];
    }
    try {
      const size = fstatSync(fd).size;
      let skipPartial = false;
      if (this.offset < 0 || size < this.offset) {
        this.fresh = true;
        skipPartial = size > MAX_INITIAL_BYTES;
        this.offset = skipPartial ? size - MAX_INITIAL_BYTES : 0;
      }
      if (size <= this.offset) return [];
      const buffer = Buffer.alloc(Math.min(size - this.offset, MAX_READ_BYTES));
      const got = readSync(fd, buffer, 0, buffer.length, this.offset);
      let start = 0;
      if (skipPartial) {
        const first = buffer.indexOf(0x0a);
        if (first < 0) return [];
        start = first + 1;
      }
      const end = buffer.lastIndexOf(0x0a, got - 1);
      if (end < start) {
        // Uma linha maior que o limite de leitura nunca terminaria aqui: pula para não travar a sessão inteira.
        if (got === MAX_READ_BYTES) this.offset += got;
        return [];
      }
      this.offset += end + 1;
      return buffer
        .subarray(start, end)
        .toString('utf8')
        .split('\n')
        .map((line) => maskLine(line))
        .filter((line): line is string => line !== undefined);
    } finally {
      closeSync(fd);
    }
  }
}

function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === 'EPERM';
  }
}

function listDir(dir: string): string[] {
  try {
    return readdirSync(dir);
  } catch {
    return [];
  }
}

const SAFE = /^[A-Za-z0-9._-]+$/;

class Connection {
  private readonly tails = new Map<string, Tail>();
  private readonly sentRegistry = new Map<string, string>();
  private readonly sentMeta = new Map<string, string>();

  constructor(
    private readonly child: ChildProcessWithoutNullStreams,
    private readonly configDir: string,
  ) {}

  private async send(message: object): Promise<void> {
    if (!this.child.stdin.write(`${JSON.stringify(message)}\n`)) await once(this.child.stdin, 'drain');
  }

  private async pump(remote: string, local: string): Promise<void> {
    let tail = this.tails.get(remote);
    if (!tail) this.tails.set(remote, (tail = new Tail(local)));
    const lines = tail.read();
    if (tail.fresh) {
      await this.send({ t: 'open', path: remote });
      tail.fresh = false;
    }
    if (lines.length) await this.send({ t: 'append', path: remote, data: `${lines.join('\n')}\n` });
  }

  private async pumpSession(cwd: string, sessionId: string): Promise<void> {
    const project = encodeCwd(cwd);
    if (!SAFE.test(sessionId)) return;
    const root = join(this.configDir, 'projects', project);
    await this.pump(`projects/${project}/${sessionId}.jsonl`, join(root, `${sessionId}.jsonl`));
    const subDir = join(root, sessionId, 'subagents');
    for (const name of listDir(subDir)) {
      if (!SAFE.test(name)) continue;
      const remote = `projects/${project}/${sessionId}/subagents/${name}`;
      if (name.endsWith('.jsonl')) await this.pump(remote, join(subDir, name));
      else if (name.endsWith('.meta.json')) {
        try {
          const text = maskLine(readFileSync(join(subDir, name), 'utf8'));
          if (text !== undefined && this.sentMeta.get(remote) !== text) {
            await this.send({ t: 'write', path: remote, data: text });
            this.sentMeta.set(remote, text);
          }
        } catch {
          // o arquivo sumiu no meio: fica para a próxima
        }
      }
    }
  }

  async tick(): Promise<void> {
    const open = new Set<string>();
    const sessionsDir = join(this.configDir, 'sessions');
    for (const name of listDir(sessionsDir)) {
      if (!/^\d+\.json$/.test(name)) continue;
      let entry: ReturnType<typeof maskRegistry>;
      let raw: Record<string, string>;
      try {
        const text = readFileSync(join(sessionsDir, name), 'utf8');
        entry = maskRegistry(text);
        raw = JSON.parse(text) as Record<string, string>;
      } catch {
        continue;
      }
      if (!entry || !pidAlive(entry.pid)) continue;
      open.add(name);
      // O transcript antes do registro: o escritório procura o arquivo assim que vê a sessão.
      await this.pumpSession(raw.cwd, raw.sessionId);
      if (this.sentRegistry.get(name) !== entry.text) {
        await this.send({ t: 'session', name, data: entry.text });
        this.sentRegistry.set(name, entry.text);
      }
    }
    for (const name of [...this.sentRegistry.keys()]) {
      if (open.has(name)) continue;
      await this.send({ t: 'close', name });
      this.sentRegistry.delete(name);
    }
    await this.send({ t: 'ping' });
  }
}

function parseArgs(argv: string[]): { target: string; sshOpts: string[] } {
  const sshOpts: string[] = [];
  let target = '';
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--ssh-opt') sshOpts.push('-o', argv[++i] ?? '');
    else target = argv[i];
  }
  if (!target) throw new Error('Uso: node pc-sync.cjs usuario@servidor [--ssh-opt Opcao=valor]...');
  return { target, sshOpts };
}

async function connect(target: string, sshOpts: string[], configDir: string): Promise<void> {
  const child = spawn('ssh', ['-o', 'BatchMode=yes', '-o', 'ServerAliveInterval=15', ...sshOpts, target, 'node habblaud/scripts/pc-receive.mjs'], {
    stdio: 'pipe',
    windowsHide: true,
  });
  let alive = true;
  const ended = new Promise<void>((ok) => {
    child.once('close', (code) => {
      alive = false;
      console.log(`${new Date().toISOString()} conexión cerrada (código ${code})`);
      ok();
    });
    child.once('error', (err) => {
      alive = false;
      console.log(`${new Date().toISOString()} no se pudo abrir ssh: ${err.message}`);
      ok();
    });
  });
  child.stdin.on('error', () => undefined);
  child.stderr.on('data', (d: Buffer) => console.log(d.toString().trim().slice(0, 300)));
  const connection = new Connection(child, configDir);
  while (alive) {
    try {
      await Promise.race([connection.tick(), ended]);
    } catch (err) {
      console.log(`${new Date().toISOString()} error: ${String(err).slice(0, 200)}`);
    }
    if (alive) await Promise.race([new Promise((ok) => setTimeout(ok, TICK_MS)), ended]);
  }
}

async function main(): Promise<void> {
  const { target, sshOpts } = parseArgs(process.argv.slice(2));
  const configDir = process.env.CLAUDE_CONFIG_DIR?.trim() || join(homedir(), '.claude');
  for (;;) {
    await connect(target, sshOpts, configDir);
    await new Promise((ok) => setTimeout(ok, RETRY_MS));
  }
}

if (process.argv[1] && /pc-sync(\.cjs|\.ts)$/.test(process.argv[1])) {
  main().catch((err: unknown) => {
    console.error(String((err as Error).message ?? err));
    process.exitCode = 1;
  });
}
