// Recebe, no servidor, as sessões que scripts/pc-sync.ts manda de outro computador. Roda por SSH, uma mensagem JSON por
// linha na entrada padrão, e grava numa pasta de conta separada (padrão ~/.claude-pc), que o escritório lê como as outras.
//
// Nada fica para trás: a pasta é apagada ao começar e ao terminar a conexão. Sem nenhuma mensagem por HEARTBEAT_MS (o
// computador desligou sem fechar a conexão), o processo termina: os agentes saem do escritório e os dados somem.
import { appendFileSync, mkdirSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { createInterface } from 'node:readline';

const HEARTBEAT_MS = Number(process.env.HB_PC_HEARTBEAT_MS) || 30_000;
const BASE = process.env.HB_PC_DIR || join(process.env.HOME || homedir(), '.claude-pc');
const TRANSCRIPT = /^projects\/[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+\.jsonl$/;
const SUBAGENT = /^projects\/[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+\/subagents\/[A-Za-z0-9._-]+\.(jsonl|meta\.json)$/;
const SESSION = /^\d+\.json$/;

process.umask(0o077);

function validPath(path) {
  return typeof path === 'string' && !path.split('/').includes('..') && (TRANSCRIPT.test(path) || SUBAGENT.test(path));
}

function wipe() {
  for (const dir of ['sessions', 'projects']) rmSync(join(BASE, dir), { recursive: true, force: true });
}

function prepare() {
  wipe();
  mkdirSync(join(BASE, 'sessions'), { recursive: true, mode: 0o700 });
  mkdirSync(join(BASE, 'projects'), { recursive: true, mode: 0o700 });
  // A marca diz ao escritório que os PIDs daqui são de outro computador (server/sources/watcher.ts).
  writeFileSync(join(BASE, '.habblaud-remote'), '');
}

function atomicWrite(file, data) {
  mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.tmp`;
  writeFileSync(tmp, data);
  renameSync(tmp, file);
}

function handle(message) {
  switch (message.t) {
    case 'ping':
      return;
    case 'open':
      if (!validPath(message.path)) return;
      atomicWrite(join(BASE, message.path), '');
      return;
    case 'append':
      if (!validPath(message.path) || typeof message.data !== 'string') return;
      mkdirSync(dirname(join(BASE, message.path)), { recursive: true, mode: 0o700 });
      appendFileSync(join(BASE, message.path), message.data);
      return;
    case 'write':
      if (!validPath(message.path) || typeof message.data !== 'string') return;
      atomicWrite(join(BASE, message.path), message.data);
      return;
    case 'session':
      if (!SESSION.test(message.name) || typeof message.data !== 'string') return;
      atomicWrite(join(BASE, 'sessions', message.name), message.data);
      return;
    case 'close':
      if (SESSION.test(message.name)) rmSync(join(BASE, 'sessions', message.name), { force: true });
      return;
    default:
  }
}

let finished = false;
function finish(code) {
  if (finished) return;
  finished = true;
  wipe();
  process.exit(code);
}

prepare();
let timer;
const beat = () => {
  clearTimeout(timer);
  timer = setTimeout(() => finish(3), HEARTBEAT_MS);
};
beat();

const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
lines.on('line', (line) => {
  beat();
  try {
    handle(JSON.parse(line));
  } catch (err) {
    process.stderr.write(`mensagem recusada: ${String(err.message).slice(0, 120)}\n`);
  }
});
lines.on('close', () => finish(0));
process.on('SIGTERM', () => finish(0));
process.on('SIGHUP', () => finish(0));
process.on('SIGINT', () => finish(0));
