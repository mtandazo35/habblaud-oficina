// Sessões privadas (http/privacy.ts). A prova que importa é a de ponta a ponta: o servidor de verdade, com usuários de
// login de verdade, e um marcador único nas sessões privadas que não pode aparecer em nenhum byte recebido por quem não é
// o dono, nem nos arquivos gravados para a visão dele. O dono e a porta local servem de controle: se eles não recebessem
// o marcador, a prova não diria nada.
import { spawn, type ChildProcess } from 'node:child_process';
import { appendFileSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import net, { type AddressInfo } from 'node:net';
import { join } from 'node:path';
import type { ServerResponse } from 'node:http';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { FeedItem, Notice, OfficeSnapshot } from '../../shared/types';
import { setQuiet } from '../log';
import type { Office } from '../model/office';
import { hashPassword } from '../remote/password';
import { L, tempDir } from '../test/fixtures';
import { createPrivacy, parsePrivateDirs, PrivacyView, type PrivacyOptions } from './privacy';
import { Hub } from './sse';

setQuiet(true);

const PRIV = 'SEGREDOPRIVADOX7Q';
const PUB = 'VISIVELPUBLICOK3';
const ADMIN_PASS = 'senha do admin 123';
const USER_PASS = 'senha de teste 456';

// ------------------------------------------------------------------ peças soltas

describe('parsePrivateDirs', () => {
  it('lê pasta=usuário, normaliza o nome e expande o ~', () => {
    const { dirs, warnings } = parsePrivateDirs(' ~/.claude-pc = Dono , /srv/outra=ana ', '/home/x');
    expect(dirs).toEqual([
      { dir: '/home/x/.claude-pc', owner: 'dono' },
      { dir: '/srv/outra', owner: 'ana' },
    ]);
    expect(warnings).toEqual([]);
  });

  it('vazio não liga nada', () => {
    expect(parsePrivateDirs(undefined, '/h').dirs).toEqual([]);
    expect(parsePrivateDirs('  ', '/h').dirs).toEqual([]);
  });

  it('na dúvida esconde: sem usuário, usuário inválido ou dois donos ficam sem dono e avisam', () => {
    for (const raw of ['/srv/a', '/srv/a=', '/srv/a=não vale!', '/srv/a=ana,/srv/a=bia']) {
      const { dirs, warnings } = parsePrivateDirs(raw, '/h');
      expect(dirs, raw).toEqual([{ dir: '/srv/a' }]);
      expect(warnings.length, raw).toBeGreaterThan(0);
    }
  });

  it('entrada sem pasta avisa', () => {
    const { dirs, warnings } = parsePrivateDirs('=ana', '/h');
    expect(dirs).toEqual([]);
    expect(warnings).toHaveLength(1);
  });
});

function agent(id: string, account: string, roomId: string) {
  return { id, account, roomId, kind: 'main', name: id, sessionId: id, status: 'working', recent: [], tasks: [], stats: {} } as unknown as OfficeSnapshot['agents'][number];
}

function room(id: string, slot: number, extra: object = {}) {
  return { id, name: id.split('/').pop(), path: id, slot, seed: 1, createdAt: 1, ...extra } as OfficeSnapshot['rooms'][number];
}

function snapshot(rev: number, over: Partial<OfficeSnapshot> = {}): OfficeSnapshot {
  return {
    rev,
    serverTime: 1000 + rev,
    rooms: [room('/p/secreta', 0), room('/p/comum', 1)],
    agents: [agent('priv:1', 'priv', '/p/secreta'), agent('pub:1', 'pub', '/p/comum')],
    accounts: [
      { id: 'priv', email: 'x', configDir: '/d/priv' },
      { id: 'pub', configDir: '/d/pub' },
    ] as unknown as OfficeSnapshot['accounts'],
    meta: {
      demo: false,
      startedAt: 1,
      version: 'v',
      sources: [
        { label: 'priv', path: '/d/priv', sessions: 1, ok: true },
        { label: 'pub', path: '/d/pub', sessions: 1, ok: true },
      ],
    },
    ...over,
  };
}

const ENTRIES = [
  { id: 'priv', dir: '/d/priv', detected: { configDir: '/host/priv' } },
  { id: 'pub', dir: '/d/pub', detected: { configDir: '/host/pub' } },
];

function hiding(...dirs: string[]): PrivacyView {
  return new PrivacyView({ hidden: dirs.map((dir) => ({ dir })), entries: () => ENTRIES });
}

describe('PrivacyView', () => {
  it('tira agentes, salas, contas e fontes da conta escondida e renumera os slots', () => {
    const s = hiding('/d/priv').snapshot(snapshot(1));
    expect(s.agents.map((a) => a.id)).toEqual(['pub:1']);
    expect(s.rooms.map((r) => [r.id, r.slot])).toEqual([['/p/comum', 0]]);
    expect(s.accounts.map((a) => a.id)).toEqual(['pub']);
    expect(s.meta.sources.map((x) => x.label)).toEqual(['pub']);
  });

  it('reconhece a conta também pelo caminho do host (Docker)', () => {
    expect(hiding('/host/priv').snapshot(snapshot(1)).agents.map((a) => a.id)).toEqual(['pub:1']);
  });

  it('conta desconhecida não aparece; a do demo aparece, mas não uma pasta real chamada "demo:"', () => {
    const view = new PrivacyView({ hidden: [{ dir: '/d/demo' }], entries: () => [...ENTRIES, { id: 'demo:real', dir: '/d/demo', detected: { configDir: '/d/demo' } }] });
    const visible = view.accountFilter();
    expect(visible('nunca-vista')).toBe(false);
    expect(visible('demo:contaA')).toBe(true);
    expect(visible('demo:real')).toBe(false);
    expect(visible('pub')).toBe(true);
  });

  it('arquivo dentro da pasta escondida não abre, nem por um caminho com ".." ou pelo caminho do host', () => {
    const view = hiding('/d/priv');
    expect(view.hidesPath('/d/priv/projects/a.html')).toBe(true);
    expect(view.hidesPath('/d/pub/../priv/a.html')).toBe(true);
    expect(view.hidesPath('/host/priv/a.html')).toBe(true);
    expect(view.hidesPath('/d/privada/a.html')).toBe(false);
    expect(view.hidesPath('/d/pub/a.html')).toBe(false);
  });

  it('nome da sala não denuncia outra com o mesmo final de caminho, e o apelido continua valendo', () => {
    const base = snapshot(1, {
      rooms: [room('/a/app', 0, { name: 'a/app' }), room('/b/app', 1, { name: 'b/app' }), room('/c/log', 2, { name: 'apelido' })],
      agents: [agent('priv:1', 'priv', '/a/app'), agent('pub:1', 'pub', '/b/app'), agent('pub:2', 'pub', '/c/log')],
    });
    const view = new PrivacyView({ hidden: [{ dir: '/d/priv' }], entries: () => ENTRIES, roomAlias: (p) => (p === '/c/log' ? 'apelido' : undefined) });
    expect(view.snapshot(base).rooms.map((r) => r.name)).toEqual(['app', 'apelido']);
  });

  it('festa ou alarme de agente escondido não sai, mesmo numa sala visível', () => {
    const effect = { kind: 'alarm', text: 'CI', at: 1, until: 2 } as const;
    const base = snapshot(1, {
      rooms: [room('/p/comum', 0, { effect: { ...effect, agentId: 'priv:9' } }), room('/p/outra', 1, { effect: { ...effect, agentId: 'pub:2' } }), room('/p/sem', 2, { effect })],
      agents: [agent('priv:9', 'priv', '/p/comum'), agent('pub:1', 'pub', '/p/comum'), agent('pub:2', 'pub', '/p/outra'), agent('pub:3', 'pub', '/p/sem')],
    });
    expect(hiding('/d/priv').snapshot(base).rooms.map((r) => r.effect?.agentId)).toEqual([undefined, 'pub:2', undefined]);
  });

  it('o resumo do prédio no Habblaud World não vai para quem não vê tudo, e os terminais da conta somem', () => {
    const base = snapshot(1, {
      ptys: [{ id: 'x', account: 'priv', cwd: '/p/secreta' }, { id: 'y', account: 'pub', cwd: '/p/comum' }] as OfficeSnapshot['ptys'],
    });
    base.meta.world = { enabled: true, configured: true, state: 'off', building: { agents: 2 } } as unknown as OfficeSnapshot['meta']['world'];
    const s = hiding('/d/priv').snapshot(base);
    expect(s.meta.world).toEqual({ enabled: true, configured: true, state: 'off' });
    expect(s.ptys?.map((p) => p.id)).toEqual(['y']);
  });

  it('`rev` e o frame só andam quando algo visível muda', () => {
    const view = hiding('/d/priv');
    const first = view.attachFrame(snapshot(1));
    expect(JSON.parse(first.split('data: ')[1]).rev).toBe(1);
    // Só a sessão escondida mudou.
    const quiet = snapshot(2, { agents: [agent('priv:1', 'priv', '/p/secreta'), agent('priv:2', 'priv', '/p/secreta'), agent('pub:1', 'pub', '/p/comum')] });
    expect(view.snapshotFrame(quiet)).toBeNull();
    expect(view.snapshot(quiet).rev).toBe(1);
    // Mudou o que ela vê.
    const moved = snapshot(3, { agents: [agent('pub:1', 'pub', '/p/comum'), agent('pub:2', 'pub', '/p/comum')] });
    const next = view.snapshotFrame(moved);
    const data = JSON.parse(next!.split('data: ')[1]) as OfficeSnapshot;
    expect(data.rev).toBe(2);
    expect(data.serverTime).toBe(moved.serverTime);
    expect(data.agents.map((a) => a.id)).toEqual(['pub:1', 'pub:2']);
  });

  it('feed: sem conta conhecida e permitida, não sai', () => {
    const view = hiding('/d/priv');
    view.snapshot(snapshot(1));
    const item = (id: string, account?: string) => ({ id, account, agentId: id, roomId: '/p/comum', roomName: 'comum' }) as FeedItem;
    expect(view.feed([item('a', 'priv'), item('b', 'pub'), item('c'), item('d', 'sumiu')]).map((i) => i.id)).toEqual(['b']);
  });

  it('aviso: pelo agente, ou pela sala quando é de sala; sem nenhum dos dois não sai', () => {
    const view = hiding('/d/priv');
    const s = snapshot(1);
    const n = (o: Partial<Notice>) => ({ id: 'n', level: 'info', text: 't', at: 1, ...o }) as Notice;
    expect(view.notice(n({ agentId: 'priv:1', roomId: '/p/comum' }), s)).toBe(false);
    expect(view.notice(n({ agentId: 'pub:1' }), s)).toBe(true);
    expect(view.notice(n({ agentId: 'nunca-visto' }), s)).toBe(false);
    expect(view.notice(n({ roomId: '/p/secreta' }), s)).toBe(false);
    expect(view.notice(n({ roomId: '/p/comum' }), s)).toBe(true);
    expect(view.notice(n({}), s)).toBe(false);
  });
});

describe('Hub com visões', () => {
  /** Um escritório de mentira: cada commit devolve o que o teste pôs na fila. */
  function fakeOffice() {
    let next = { snapshot: snapshot(1), changed: true, feed: [] as FeedItem[], notices: [] as Notice[] };
    let listener = () => {};
    const office = {
      onChange: (cb: () => void) => ((listener = cb), () => {}),
      recentFeed: () => [] as FeedItem[],
      commit: () => {
        const r = next;
        next = { ...next, changed: false, feed: [], notices: [] };
        return r;
      },
    };
    return { office: office as unknown as Office, push: (o: Partial<typeof next>) => ((next = { ...next, ...o }), listener()) };
  }
  function client() {
    const chunks: string[] = [];
    const res = { writeHead() {}, write: (c: string) => chunks.push(c), on() {}, destroyed: false, writableEnded: false, writableLength: 0, end() {} };
    const req = { socket: { setTimeout() {}, setNoDelay() {} }, on() {}, headers: { host: 'x' } };
    return { req: req as never, res: res as unknown as ServerResponse, text: () => chunks.join('') };
  }

  it('cada um recebe o seu, e a visão monta o frame uma vez só com dois clientes', () => {
    const { office, push } = fakeOffice();
    const hub = new Hub(office, { throttleMs: 100_000, canAnswer: () => false });
    const view = hiding('/d/priv');
    const a = client();
    const b = client();
    const dono = client();
    hub.attach(a.req, a.res, view);
    hub.attach(b.req, b.res, view);
    hub.attach(dono.req, dono.res);

    let frames = 0;
    const original = view.snapshotFrame.bind(view);
    view.snapshotFrame = (s) => (frames++, original(s));
    push({
      snapshot: snapshot(2, { agents: [agent('priv:1', 'priv', '/p/secreta'), agent('pub:1', 'pub', '/p/comum'), agent('pub:2', 'pub', '/p/comum')] }),
      changed: true,
      feed: [{ id: 'f1', account: 'priv', agentId: 'priv:1', roomId: '/p/secreta', roomName: PRIV } as FeedItem],
      notices: [{ id: 'n1', level: 'info', text: PRIV, agentId: 'priv:1', at: 1 }],
    });
    hub.flush();
    expect(frames).toBe(1);
    for (const c of [a, b]) {
      expect(c.text()).toContain('pub:2');
      expect(c.text()).not.toContain('priv:1');
      expect(c.text()).not.toContain(PRIV);
    }
    expect(dono.text()).toContain(PRIV);
    expect(dono.text()).toContain('priv:1');
  });

  it('atividade só da conta escondida não manda nem um frame para quem não a vê', () => {
    const { office, push } = fakeOffice();
    const hub = new Hub(office, { throttleMs: 100_000, canAnswer: () => false });
    const view = hiding('/d/priv');
    const a = client();
    hub.attach(a.req, a.res, view);
    const before = a.text();
    push({ snapshot: snapshot(2, { agents: [agent('priv:1', 'priv', '/p/secreta'), agent('priv:2', 'priv', '/p/secreta'), agent('pub:1', 'pub', '/p/comum')] }), changed: true });
    hub.flush();
    expect(a.text()).toBe(before);
  });
});

describe('createPrivacy', () => {
  const opts = (raw: string | undefined): PrivacyOptions =>
    ({
      raw,
      home: '/h',
      dataDir: '/nao/usado',
      timeline: false,
      base: { office: {}, version: 'v', inDocker: false, sources: () => [] },
      api: () => true,
      office: {},
      hub: {},
      accounts: { allEntries: () => [], entriesOf: () => [] },
      deliveriesOf: () => ({}),
      spawnFoldersOf: () => async () => [],
    }) as unknown as PrivacyOptions;

  it('sem a variável não existe', () => {
    expect(createPrivacy(opts(undefined))).toBeUndefined();
    expect(createPrivacy(opts(''))).toBeUndefined();
  });

  it('usuário não identificado e usuário qualquer caem na visão que esconde; só quem é dono de tudo usa a API sem filtro', () => {
    const o = opts('/a=dono');
    const p = createPrivacy(o)!;
    expect(p.apiFor('dono')).toBe(o.api);
    expect(p.apiFor(undefined)).not.toBe(o.api);
    expect(p.apiFor('qualquer')).toBe(p.apiFor(undefined));
  });

  it('com dois donos, cada um tem a sua visão e nenhum usa a API sem filtro', () => {
    const o = opts('/a=ana,/b=bia');
    const p = createPrivacy(o)!;
    const seen = new Set([p.apiFor('ana'), p.apiFor('bia'), p.apiFor('outro')]);
    expect(seen.size).toBe(3);
    expect(seen.has(o.api)).toBe(false);
  });
});

// ------------------------------------------------------------------ de ponta a ponta

const UUIDS = {
  pub: '10000000-0000-4000-8000-000000000001',
  pubShared: '10000000-0000-4000-8000-000000000002',
  priv: '20000000-0000-4000-8000-000000000001',
  privShared: '20000000-0000-4000-8000-000000000002',
  privNew: '20000000-0000-4000-8000-000000000003',
};

/** Linha de transcript com o cwd da sessão (os construtores usam um fixo). */
function withCwd(line: string, cwd: string): string {
  return JSON.stringify({ ...(JSON.parse(line) as object), cwd });
}

function freePort(): Promise<number> {
  return new Promise((ok, fail) => {
    const s = net.createServer();
    s.on('error', fail);
    s.listen(0, '127.0.0.1', () => {
      const { port } = s.address() as AddressInfo;
      s.close(() => ok(port));
    });
  });
}

function encodeCwd(cwd: string): string {
  return cwd.replace(/[^a-zA-Z0-9]/g, '-');
}

function transcriptFile(dir: string, cwd: string, sessionId: string): string {
  return join(dir, 'projects', encodeCwd(cwd), `${sessionId}.jsonl`);
}

/** Abre uma sessão "espelhada": o arquivo marca dispensa o PID vivo, como em scripts/pc-receive.mjs. */
function openSession(dir: string, pid: number, sessionId: string, cwd: string, mark: string): void {
  mkdirSync(join(dir, 'sessions'), { recursive: true });
  const file = transcriptFile(dir, cwd, sessionId);
  mkdirSync(join(file, '..'), { recursive: true });
  const at = Date.now() - 60_000;
  writeFileSync(
    file,
    `${[
      withCwd(L.prompt(`pedido ${mark}`, { sessionId, at }), cwd),
      withCwd(L.assistant([L.tool(`tool-${pid}`, 'Bash', { command: `echo ${mark}` })], { sessionId, at: at + 1000 }), cwd),
      withCwd(L.result(`tool-${pid}`, `saida ${mark}`, { sessionId, at: at + 2000 }), cwd),
      withCwd(L.assistant([L.text(`Pronto: resposta ${mark} em ${dir}/relatorio-${mark}.html`)], { sessionId, at: at + 3000, stop: 'end_turn' }), cwd),
      withCwd(L.prompt(`segundo pedido ${mark}`, { sessionId, at: at + 4000 }), cwd),
    ].join('\n')}\n`,
  );
  writeFileSync(join(dir, 'sessions', `${pid}.json`), JSON.stringify({ pid, sessionId, cwd, startedAt: at, kind: 'interactive', status: 'busy', updatedAt: Date.now() }));
}

interface Reply {
  status: number;
  body: string;
  headers: http.IncomingHttpHeaders;
}

function call(port: number, path: string, o: { method?: string; cookie?: string; body?: unknown } = {}): Promise<Reply> {
  return new Promise((ok, fail) => {
    const payload = o.body === undefined ? undefined : JSON.stringify(o.body);
    const req = http.request(
      {
        host: '127.0.0.1',
        port,
        path,
        method: o.method ?? 'GET',
        headers: { ...(o.cookie ? { Cookie: o.cookie } : {}), ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } : {}) },
      },
      (res) => {
        const chunks: Buffer[] = [];
        // Fluxos (SSE) ficam abertos: guarda o que chegar por um instante e fecha.
        const sse = /event-stream/.test(String(res.headers['content-type']));
        const finish = () => ok({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8'), headers: res.headers });
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', finish);
        res.on('close', finish);
        if (sse) setTimeout(() => req.destroy(), 700);
      },
    );
    req.on('error', fail);
    req.end(payload);
  });
}

/** Como o EventSource: guarda tudo o que chega e reconecta quando a conexão cai (mudar uma conta corta as conexões dela). */
class Stream {
  data = '';
  private req?: http.ClientRequest;
  private closed = false;
  constructor(
    private readonly port: number,
    private readonly cookie?: string,
  ) {
    this.connect();
  }
  private connect(): void {
    if (this.closed) return;
    const again = () => {
      if (!this.closed) setTimeout(() => this.connect(), 200);
    };
    const req = http.get({ host: '127.0.0.1', port: this.port, path: '/api/stream', headers: this.cookie ? { Cookie: this.cookie } : {} }, (res) => {
      res.on('data', (c: Buffer) => (this.data += c.toString('utf8')));
      res.on('close', again);
    });
    req.on('error', again);
    this.req = req;
  }
  close(): void {
    this.closed = true;
    this.req?.destroy();
  }
  /** O último snapshot recebido. */
  snapshot(): OfficeSnapshot {
    const frames = this.data.split('\n\n').filter((f) => f.startsWith('event: snapshot\n'));
    return JSON.parse(frames[frames.length - 1].split('data: ')[1]) as OfficeSnapshot;
  }
}

async function until(what: string, cond: () => boolean | Promise<boolean>, ms = 20_000): Promise<void> {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await cond()) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`não aconteceu a tempo: ${what}`);
}

interface Instance {
  local: number;
  remote: number;
  data: string;
  child: ChildProcess;
  log: () => string;
  stop: () => Promise<void>;
}

const SEED = await hashPassword(ADMIN_PASS, 10);

async function boot(base: string, dirs: string[], privateDirs: string | undefined, name: string): Promise<Instance> {
  const [local, remote] = [await freePort(), await freePort()];
  const data = join(base, `dados-${name}`);
  const env: NodeJS.ProcessEnv = {
    PATH: process.env.PATH,
    NO_COLOR: '1',
    HOME: base,
    HABBLAUD_IN_DOCKER: '0',
    HABBLAUD_HOST: '127.0.0.1',
    HABBLAUD_PORT: String(local),
    HABBLAUD_DATA_DIR: data,
    HABBLAUD_CLAUDE_DIRS: dirs.join(','),
    HABBLAUD_CODEX: '0',
    HABBLAUD_WORLD: '0',
    HABBLAUD_UPDATE_CHECK: '0',
    HABBLAUD_PTY: '1',
    HABBLAUD_CLAUDE_BIN: 'nao-existe-claude',
    HABBLAUD_LANG: 'pt-BR',
    HABBLAUD_REMOTE_USER: 'chefe',
    HABBLAUD_REMOTE_PASSWORD_HASH: SEED,
    HABBLAUD_REMOTE_ALLOW: 'permissions,messages,terminal,spawn',
    HABBLAUD_REMOTE_INSECURE_HTTP: '1',
    HABBLAUD_REMOTE_HOST: '127.0.0.1',
    HABBLAUD_REMOTE_PORT: String(remote),
  };
  if (privateDirs !== undefined) env.HABBLAUD_PRIVATE_DIRS = privateDirs;
  const child = spawn(process.execPath, ['--import', 'tsx', 'server/index.ts'], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  let log = '';
  child.stdout?.on('data', (c: Buffer) => (log += c.toString('utf8')));
  child.stderr?.on('data', (c: Buffer) => (log += c.toString('utf8')));
  try {
    await until(
      'o servidor subir',
      async () => {
        const r = await call(local, '/api/health').catch(() => undefined);
        const s = await call(remote, '/api/remote/me').catch(() => undefined);
        return r?.status === 200 && s?.status === 401;
      },
      40_000,
    );
  } catch (err) {
    child.kill('SIGKILL');
    throw new Error(`${(err as Error).message}\n${log}`);
  }
  return {
    local,
    remote,
    data,
    child,
    log: () => log,
    stop: () =>
      new Promise((ok) => {
        child.once('exit', () => ok());
        child.kill('SIGTERM');
      }),
  };
}

async function login(port: number, user: string, password: string): Promise<string> {
  const r = await call(port, '/api/remote/login', { method: 'POST', body: { user, password } });
  expect(r.status, `login de ${user}: ${r.body}`).toBe(200);
  return String(r.headers['set-cookie']?.[0]).split(';')[0];
}

async function addUser(port: number, admin: string, name: string, role: string): Promise<string> {
  const r = await call(port, '/api/remote/users', { method: 'POST', cookie: admin, body: { name, role, password: USER_PASS } });
  expect(r.status, `criar ${name}: ${r.body}`).toBe(201);
  return login(port, name, USER_PASS);
}

function filesUnder(dir: string): string[] {
  const out: string[] = [];
  const walk = (d: string) => {
    for (const name of readdirSync(d)) {
      const p = join(d, name);
      if (statSync(p).isDirectory()) walk(p);
      else out.push(p);
    }
  };
  walk(dir);
  return out;
}

const SHARED = '/projetos/compartilhada';
const PRIV_ROOM = `/projetos/${PRIV}-sala`;
const PUB_ROOM = `/projetos/${PUB}-sala`;

describe('de ponta a ponta: dois usuários reais na mesma instância', () => {
  let tmp: ReturnType<typeof tempDir>;
  let pubDir: string;
  let privDir: string;

  beforeAll(() => {
    tmp = tempDir();
    pubDir = join(tmp.dir, '.claude-publica');
    privDir = join(tmp.dir, `.claude-${PRIV}`);
    for (const dir of [pubDir, privDir]) {
      mkdirSync(dir, { recursive: true });
      writeFileSync(join(dir, '.habblaud-remote'), '');
    }
    writeFileSync(join(privDir, '.claude.json'), JSON.stringify({ oauthAccount: { emailAddress: `${PRIV}@example.org`, organizationName: `${PRIV} Org` } }));
    writeFileSync(join(pubDir, '.claude.json'), JSON.stringify({ oauthAccount: { emailAddress: `${PUB}@example.org` } }));
    writeFileSync(join(privDir, `relatorio-${PRIV}.html`), `conteudo ${PRIV}`);
    writeFileSync(join(pubDir, `relatorio-${PUB}.html`), `conteudo ${PUB}`);
    // A sala privada entra primeiro: pegaria o slot 0 do prédio.
    openSession(privDir, 2001, UUIDS.priv, PRIV_ROOM, PRIV);
    openSession(privDir, 2002, UUIDS.privShared, SHARED, PRIV);
    openSession(pubDir, 1001, UUIDS.pub, PUB_ROOM, PUB);
    openSession(pubDir, 1002, UUIDS.pubShared, SHARED, PUB);
  });

  afterAll(() => tmp.cleanup());

  it('nenhuma rota entrega um byte da sessão privada a quem não é o dono', { timeout: 120_000 }, async () => {
    const srv = await boot(tmp.dir, [pubDir, privDir], `${privDir}=dono`, 'privado');
    const streams: Stream[] = [];
    const seen: Record<string, string> = { chefe: '', outro: '', oper: '', dono: '' };
    const table: string[] = [];
    try {
      const chefe = await login(srv.remote, 'chefe', ADMIN_PASS);
      const cookies: Record<string, string> = {
        chefe,
        outro: await addUser(srv.remote, chefe, 'outro', 'viewer'),
        oper: await addUser(srv.remote, chefe, 'oper', 'operator'),
        dono: await addUser(srv.remote, chefe, 'dono', 'viewer'),
      };
      // Quem não é dono, do papel mais baixo ao mais alto (o dono entra só como Ver: ser dono não depende do papel).
      const others = ['chefe', 'outro', 'oper'];

      const live: Record<string, Stream> = {};
      for (const u of Object.keys(cookies)) streams.push((live[u] = new Stream(srv.remote, cookies[u])));
      const localStream = new Stream(srv.local);
      streams.push(localStream);

      await until('o dono ver as sessões', () => live.dono.data.includes(UUIDS.priv) && live.dono.data.includes(UUIDS.pub));
      await until('os outros verem as públicas', () => others.every((u) => live[u].data.includes(UUIDS.pub)));

      // Atividade ao vivo: sessão nova, prompt novo e pedido de permissão só na conta privada; prompt novo na pública.
      openSession(privDir, 2003, UUIDS.privNew, `/projetos/${PRIV}-nova`, PRIV);
      appendFileSync(transcriptFile(privDir, PRIV_ROOM, UUIDS.priv), `${withCwd(L.prompt(`ao vivo ${PRIV}-VIVO`, { sessionId: UUIDS.priv }), PRIV_ROOM)}\n`);
      appendFileSync(transcriptFile(pubDir, PUB_ROOM, UUIDS.pub), `${withCwd(L.prompt(`ao vivo ${PUB}-VIVO`, { sessionId: UUIDS.pub }), PUB_ROOM)}\n`);
      await until('o dono receber a atividade privada', () => live.dono.data.includes(`${PRIV}-VIVO`) && live.dono.data.includes(`${PRIV}-nova`));
      await until('os outros receberem a atividade pública', () => others.every((u) => live[u].data.includes(`${PUB}-VIVO`)));

      const perm = await call(srv.local, '/api/permissions', {
        method: 'POST',
        body: { session_id: UUIDS.priv, tool_name: 'Bash', tool_input: { command: `rm ${PRIV}-comando`, description: `apaga ${PRIV}` } },
      });
      expect(perm.status, perm.body).toBe(201);
      const permId = (JSON.parse(perm.body) as { id: string }).id;
      await until('o dono ver o pedido de permissão', () => live.dono.data.includes(permId));

      const donoSnap = live.dono.snapshot();
      const privAgent = donoSnap.agents.find((a) => a.sessionId === UUIDS.priv)!;
      const privAccount = privAgent.account;
      expect(privAgent.permission?.id).toBe(permId);

      // Deixa os gravadores de cada visão trabalharem.
      await new Promise((r) => setTimeout(r, 2500));

      // Só quem tem `terminal` abre entregas e histórico: para servir de controle ali, o dono precisa do papel.
      expect((await call(srv.remote, '/api/remote/users/dono', { method: 'PATCH', cookie: chefe, body: { role: 'operator' } })).status).toBe(200);
      // Mudar o papel corta as conexões da conta logo depois de responder.
      await new Promise((r) => setTimeout(r, 400));
      const ownerList = JSON.parse((await call(srv.remote, '/api/deliveries', { cookie: cookies.dono })).body) as { deliveries: Array<{ text: string; attachments: Array<{ id: string; name: string }> }> };
      const ownerFile = ownerList.deliveries.flatMap((d) => d.attachments).find((a) => a.name.includes(PRIV));
      expect(ownerFile, JSON.stringify(ownerList).slice(0, 2000)).toBeDefined();
      const fileId = encodeURIComponent(ownerFile!.id);
      const day = (u: string) => call(srv.remote, '/api/timeline/days', { cookie: cookies[u] }).then((r) => (JSON.parse(r.body) as { days: Array<{ day: string }> }).days[0]?.day ?? '2026-01-01');

      const privId = encodeURIComponent(privAgent.id);
      const acc = encodeURIComponent(privAccount);
      const routes = async (u: string): Promise<Array<[string, string?, unknown?]>> => [
        ['/api/snapshot'],
        ['/api/health'],
        ['/api/access'],
        ['/api/mod/summary'],
        ['/api/updates'],
        ['/api/remote/me'],
        ['/api/sessions/recent'],
        [`/api/sessions/${acc}/${UUIDS.priv}/terminal`],
        [`/api/agents/${privId}`],
        [`/api/agents/${privId}/terminal`],
        [`/api/permissions/${permId}`],
        ['/api/deliveries'],
        [`/api/deliveries/file/${fileId}`],
        ['/api/stats'],
        ['/api/stats/days'],
        ['/api/timeline/days'],
        [`/api/timeline/${await day(u)}`],
        ['/api/spawn'],
        ['/api/spawn/folders'],
        ['/api/pty'],
      ];

      for (const u of others) {
        for (const [path] of await routes(u)) {
          const r = await call(srv.remote, path, { cookie: cookies[u] });
          seen[u] += r.body + JSON.stringify(r.headers);
          table.push(`${u.padEnd(5)} ${r.status} ${String(r.body.length).padStart(7)} ${path.replace(PRIV, '<conta>').replace(privAccount, '<conta>')}`);
        }
        // Ações sobre a sessão privada: recusadas como se ela não existisse, ou sem nem chegar a ela.
        for (const [path, method, body] of [
          [`/api/permissions/${permId}/decision`, 'POST', { behavior: 'deny' }],
          ['/api/messages', 'POST', { agentId: privAgent.id, text: 'oi' }],
          [`/api/agents/${privId}/stop`, 'POST', {}],
          [`/api/agents/${privId}/takeover`, 'POST', {}],
          [`/api/agents/${privId}/character`, 'DELETE', {}],
          ['/api/rooms/rename', 'POST', { id: PRIV_ROOM, name: 'x' }],
          ['/api/demo', 'POST', { enabled: true }],
        ] as Array<[string, string, unknown]>) {
          const r = await call(srv.remote, path, { method, cookie: cookies[u], body });
          seen[u] += r.body;
          table.push(`${u.padEnd(5)} ${r.status} ${String(r.body.length).padStart(7)} ${method} ${path.replace(privId, '<agente>')}`);
          expect(r.status, `${u} ${method} ${path}: ${r.body}`).toBeGreaterThanOrEqual(400);
        }
        // O pedido continua aberto: ninguém o respondeu por engano.
        expect((await call(srv.local, `/api/permissions/${permId}`)).status).toBe(200);
      }

      // Depois de todas as rotas, o que os fluxos já mandaram.
      await new Promise((r) => setTimeout(r, 600));
      for (const u of others) {
        seen[u] += live[u].data;
        for (const marker of [PRIV, privAccount, UUIDS.priv, UUIDS.privShared, UUIDS.privNew, privDir, privAgent.id, permId]) {
          expect(seen[u].includes(marker), `${u} recebeu ${marker}`).toBe(false);
        }
        // Contadores: só as duas sessões públicas, nas duas salas com gente visível, sem buraco no prédio.
        const s = JSON.parse((await call(srv.remote, '/api/snapshot', { cookie: cookies[u] })).body) as OfficeSnapshot;
        expect(s.agents.map((a) => a.sessionId).sort()).toEqual([UUIDS.pub, UUIDS.pubShared].sort());
        expect(s.accounts.map((a) => a.id)).toEqual(['.claude-publica']);
        expect(s.accounts[0].sessions).toBe(2);
        expect(s.meta.sources.map((x) => x.label)).toEqual(['.claude-publica']);
        expect(s.rooms.map((r) => r.slot)).toEqual([0, 1]);
        const summary = JSON.parse((await call(srv.remote, '/api/mod/summary', { cookie: cookies[u] })).body) as { agents: number };
        expect(summary.agents).toBe(2);
        const health = JSON.parse((await call(srv.remote, '/api/health', { cookie: cookies[u] })).body) as { accounts: unknown[]; sources: unknown[] };
        expect(health.accounts).toHaveLength(1);
        expect(health.sources).toHaveLength(1);
        // E o que é público continua chegando: filtrar não virou esconder tudo.
        expect(live[u].data).toContain(`${PUB}-VIVO`);
      }
      // "Meu dia" só conta o que a visão vê, inclusive na sala que as duas contas dividem.
      const counted = (JSON.parse((await call(srv.remote, '/api/stats', { cookie: cookies.oper })).body) as { stats: { totals: { sessions: number }; rooms: unknown[]; accounts: unknown[] } }).stats;
      expect(counted.totals.sessions).toBe(2);
      expect(counted.rooms).toHaveLength(2);
      expect(counted.accounts).toHaveLength(1);

      // Público para quem tem o papel: nada do que é dele ficou preso no filtro.
      const pubAgent = (JSON.parse((await call(srv.remote, '/api/snapshot', { cookie: cookies.oper })).body) as OfficeSnapshot).agents.find((a) => a.sessionId === UUIDS.pub)!;
      const pubId = encodeURIComponent(pubAgent.id);
      expect((await call(srv.remote, `/api/agents/${pubId}`, { cookie: cookies.oper })).body).toContain(PUB);
      expect((await call(srv.remote, `/api/agents/${pubId}/terminal`, { cookie: cookies.oper })).body).toContain(PUB);
      expect((await call(srv.remote, `/api/sessions/${encodeURIComponent(pubAgent.account)}/${UUIDS.pub}/terminal`, { cookie: cookies.oper })).body).toContain(PUB);
      // Sem o plugin ligado a sessão não recebe mensagem: 409, e não o 404 de quem não existe.
      expect((await call(srv.remote, '/api/messages', { method: 'POST', cookie: cookies.oper, body: { agentId: pubAgent.id, text: 'oi' } })).status).toBe(409);
      const pubPerm = await call(srv.local, '/api/permissions', { method: 'POST', body: { session_id: UUIDS.pub, tool_name: 'Bash', tool_input: { command: 'ls' } } });
      const pubPermId = (JSON.parse(pubPerm.body) as { id: string }).id;
      expect((await call(srv.remote, `/api/permissions/${pubPermId}`, { cookie: cookies.oper })).status).toBe(200);
      expect((await call(srv.remote, `/api/permissions/${pubPermId}/decision`, { method: 'POST', cookie: cookies.oper, body: { behavior: 'deny' } })).status).toBe(200);
      const operSessions = await call(srv.remote, '/api/sessions/recent', { cookie: cookies.oper });
      expect(operSessions.body).toContain(UUIDS.pub);
      expect((await call(srv.remote, '/api/deliveries', { cookie: cookies.oper })).body).toContain(PUB);
      expect((await call(srv.remote, '/api/stats', { cookie: cookies.oper })).body).toContain(PUB);
      expect((await call(srv.remote, `/api/timeline/${await day('oper')}`, { cookie: cookies.oper })).body).toContain(PUB);
      expect((await call(srv.remote, '/api/spawn/folders', { cookie: cookies.oper })).body).toContain(PUB);

      // O dono vê tudo.
      for (const [path, marker] of [
        ['/api/snapshot', PRIV],
        ['/api/sessions/recent', UUIDS.priv],
        [`/api/agents/${privId}`, PRIV],
        [`/api/agents/${privId}/terminal`, PRIV],
        [`/api/sessions/${acc}/${UUIDS.priv}/terminal`, PRIV],
        [`/api/permissions/${permId}`, PRIV],
        ['/api/deliveries', PRIV],
        [`/api/deliveries/file/${fileId}`, PRIV],
        ['/api/stats', PRIV],
        [`/api/timeline/${await day('dono')}`, PRIV],
        ['/api/spawn/folders', PRIV],
      ] as Array<[string, string]>) {
        const r = await call(srv.remote, path, { cookie: cookies.dono });
        table.push(`dono  ${r.status} ${String(r.body.length).padStart(7)} ${path.replace(privId, '<agente>').replace(acc, '<conta>')}`);
        expect(r.body.includes(marker), `dono em ${path} (${r.status})`).toBe(true);
      }

      // A porta local não mudou.
      expect((await call(srv.local, '/api/snapshot')).body).toContain(PRIV);
      expect(localStream.data).toContain(`${PRIV}-VIVO`);

      // eslint-disable-next-line no-console
      console.log(`rotas percorridas (usuário, status, bytes, rota):\n${table.join('\n')}\nbytes dos fluxos SSE: ${others.map((u) => `${u}=${live[u].data.length}`).join(' ')} dono=${live.dono.data.length}`);
    } finally {
      for (const s of streams) s.close();
      await srv.stop();
    }

    // No disco: o que cada visão gravou nunca recebeu o marcador; o geral recebeu (controle).
    const views = [...filesUnder(join(srv.data, 'stats-views')), ...filesUnder(join(srv.data, 'timeline-views'))];
    expect(views.length).toBeGreaterThanOrEqual(2);
    for (const f of views) expect(readFileSync(f, 'utf8').includes(PRIV), f).toBe(false);
    expect(views.some((f) => readFileSync(f, 'utf8').includes(PUB))).toBe(true);
    const general = [...filesUnder(join(srv.data, 'stats')), ...filesUnder(join(srv.data, 'timeline'))];
    expect(general.some((f) => readFileSync(f, 'utf8').includes(PRIV))).toBe(true);
  });

  it('desligado por padrão: sem a variável, tudo continua como antes (e a prova acima distingue os dois casos)', { timeout: 60_000 }, async () => {
    const srv = await boot(tmp.dir, [pubDir, privDir], undefined, 'desligado');
    try {
      const chefe = await login(srv.remote, 'chefe', ADMIN_PASS);
      const outro = await addUser(srv.remote, chefe, 'outro', 'viewer');
      await until('a sessão privada aparecer', async () => (await call(srv.remote, '/api/snapshot', { cookie: outro })).body.includes(PRIV));
      expect(existsDir(join(srv.data, 'stats-views'))).toBe(false);
    } finally {
      await srv.stop();
    }
  });

  it('pasta sem usuário válido: ninguém vê pela porta remota, nem o administrador', { timeout: 60_000 }, async () => {
    const srv = await boot(tmp.dir, [pubDir, privDir], privDir, 'semdono');
    try {
      const chefe = await login(srv.remote, 'chefe', ADMIN_PASS);
      await until('a sessão pública aparecer', async () => (await call(srv.remote, '/api/snapshot', { cookie: chefe })).body.includes(PUB));
      expect((await call(srv.remote, '/api/snapshot', { cookie: chefe })).body).not.toContain(PRIV);
      expect((await call(srv.local, '/api/snapshot')).body).toContain(PRIV);
      expect(srv.log()).toContain('HABBLAUD_PRIVATE_DIRS');
    } finally {
      await srv.stop();
    }
  });

  it('cada dono vê só a sua pasta, mesmo com duas pastas privadas', { timeout: 60_000 }, async () => {
    const srv = await boot(tmp.dir, [pubDir, privDir], `${privDir}=ana,${pubDir}=bia`, 'doisdonos');
    try {
      const chefe = await login(srv.remote, 'chefe', ADMIN_PASS);
      const ana = await addUser(srv.remote, chefe, 'ana', 'operator');
      const bia = await addUser(srv.remote, chefe, 'bia', 'operator');
      await until('ana ver a dela', async () => (await call(srv.remote, '/api/snapshot', { cookie: ana })).body.includes(PRIV));
      await until('bia ver a dela', async () => (await call(srv.remote, '/api/snapshot', { cookie: bia })).body.includes(PUB));
      for (const path of ['/api/snapshot', '/api/sessions/recent', '/api/deliveries', '/api/health']) {
        expect((await call(srv.remote, path, { cookie: ana })).body, path).not.toContain(PUB);
        expect((await call(srv.remote, path, { cookie: bia })).body, path).not.toContain(PRIV);
      }
      const nobody = (await call(srv.remote, '/api/snapshot', { cookie: chefe })).body;
      expect(nobody).not.toContain(PRIV);
      expect(nobody).not.toContain(PUB);
    } finally {
      await srv.stop();
    }
  });
});

function existsDir(path: string): boolean {
  try {
    return statSync(path).isDirectory();
  } catch {
    return false;
  }
}
