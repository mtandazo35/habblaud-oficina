import { existsSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { setQuiet } from '../log';
import { hashPassword, parsePasswordHash } from '../remote/password';
import { ConnectionTracker, UserStore } from '../remote/users';
import { tempDir } from '../test/fixtures';
import { createRequestGuard } from './guard';
import { COOKIE, createRemoteGate, isRemoteRequest, LoginThrottles, RemoteSessions, remoteRequestUser, type RemoteFeature } from './remote';
import { createUserRoutes, usersPage } from './remote-users';

setQuiet(true);

const SECRET = Buffer.alloc(32, 9);
const ADMIN_PASS = 'senha do admin 123';
const SEED_HASH = await hashPassword(ADMIN_PASS, 10);
const CFG = { user: 'chefe', passwordHash: parsePasswordHash(SEED_HASH)!, passwordHashText: SEED_HASH };
const quickHash = (p: string) => hashPassword(p, 10);
const ALL: RemoteFeature[] = ['permissions', 'messages', 'terminal', 'spawn'];
const closers: Array<() => Promise<void> | void> = [];

afterEach(async () => {
  for (const c of closers.splice(0)) await c();
});

async function setup(allow: RemoteFeature[] = ALL) {
  const tmp = tempDir();
  const file = join(tmp.dir, 'remote-users.json');
  const users = new UserStore(file, { user: CFG.user, hashText: SEED_HASH });
  const connections = new ConnectionTracker();
  users.onChange((name) => connections.kick(name));
  const throttles = new LoginThrottles();
  const allowSet = new Set(allow);
  const gate = createRemoteGate({
    config: CFG,
    sessions: new RemoteSessions(SECRET, CFG),
    secure: false,
    users,
    throttles,
    connections,
    routes: createUserRoutes({ users, throttles, allow: allowSet, hash: quickHash }),
  });
  const guard = createRequestGuard();
  const server = http.createServer((req, res) => {
    if (guard(req, res)) return;
    const url = new URL(req.url ?? '/', 'http://x');
    if (gate(req, res, url)) return;
    req.resume();
    if (url.pathname === '/api/stream') {
      res.writeHead(200, { 'Content-Type': 'text/event-stream' });
      res.write(':ok\n\n');
      return;
    }
    const can = (f: RemoteFeature) => isRemoteRequest(req) && allowSet.has(f) && users.can(remoteRequestUser(req), f);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ user: remoteRequestUser(req), features: ALL.filter(can) }));
  });
  await new Promise<void>((ok) => server.listen(0, '127.0.0.1', ok));
  closers.push(async () => {
    server.closeAllConnections();
    await new Promise<void>((ok) => server.close(() => ok()));
    tmp.cleanup();
  });
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return { base, users, file, throttles };
}

async function call(base: string, method: string, path: string, opts: { cookie?: string; body?: unknown } = {}) {
  const res = await fetch(new URL(path, base), {
    method,
    redirect: 'manual',
    headers: {
      ...(method !== 'GET' ? { 'Content-Type': 'application/json' } : {}),
      ...(opts.cookie ? { Cookie: opts.cookie } : {}),
    },
    body: method === 'GET' ? undefined : JSON.stringify(opts.body ?? {}),
  });
  const text = await res.text();
  let json: Record<string, unknown> = {};
  try {
    json = JSON.parse(text) as Record<string, unknown>;
  } catch {
    // página HTML
  }
  return { status: res.status, json, text, setCookie: res.headers.get('set-cookie') ?? '' };
}

async function login(base: string, user: string, password: string): Promise<string> {
  const r = await call(base, 'POST', '/api/remote/login', { body: { user, password } });
  expect(r.status, `login de ${user}`).toBe(200);
  expect(r.setCookie).toMatch(/HttpOnly/);
  return r.setCookie.split(';')[0];
}

const addUser = (base: string, cookie: string, name: string, role: string, password = `senha de ${name} 99`) =>
  call(base, 'POST', '/api/remote/users', { cookie, body: { name, role, password } });

describe('contas: entrada', () => {
  it('a conta do .env vira administradora com a mesma senha, e o arquivo guarda só o hash, com permissão 600', async () => {
    const { base, file } = await setup();
    const cookie = await login(base, 'chefe', ADMIN_PASS);
    const me = await call(base, 'GET', '/api/remote/me', { cookie });
    expect(me.json).toMatchObject({ user: 'chefe', role: 'admin', admin: true, features: ALL });
    const raw = readFileSync(file, 'utf8');
    expect(raw).not.toContain(ADMIN_PASS);
    if (process.platform !== 'win32') expect(statSync(file).mode & 0o777).toBe(0o600);
  });

  it('usuário sem conta, conta desativada e senha errada recebem a mesma resposta', async () => {
    const { base } = await setup();
    const cookie = await login(base, 'chefe', ADMIN_PASS);
    await addUser(base, cookie, 'ana', 'viewer', 'senha da ana 123');
    await call(base, 'PATCH', '/api/remote/users/ana', { cookie, body: { disabled: true } });
    const attempts = [
      { user: 'ninguem', password: ADMIN_PASS },
      { user: 'ana', password: 'senha da ana 123' },
      { user: 'chefe', password: 'errada errada' },
    ];
    const answers = [];
    for (const body of attempts) answers.push(await call(base, 'POST', '/api/remote/login', { body }));
    expect(answers.map((a) => a.status)).toEqual([401, 401, 401]);
    expect(new Set(answers.map((a) => a.text)).size).toBe(1);
  });

  it('o token de uma conta não vale adulterado para outra conta', async () => {
    const { base } = await setup();
    const admin = await login(base, 'chefe', ADMIN_PASS);
    await addUser(base, admin, 'ana', 'viewer', 'senha da ana 123');
    const ana = await login(base, 'ana', 'senha da ana 123');
    const forged = ana.replace('.ana.', '.chefe.');
    expect(forged).not.toBe(ana);
    expect((await call(base, 'GET', '/api/remote/me', { cookie: forged })).status).toBe(401);
  });
});

describe('contas: papéis', () => {
  it('cada papel libera só o que deve, e HABBLAUD_REMOTE_ALLOW é o teto', async () => {
    const { base } = await setup(['permissions', 'messages', 'spawn']);
    const admin = await login(base, 'chefe', ADMIN_PASS);
    const expected: Record<string, RemoteFeature[]> = {
      viewer: [],
      approver: ['permissions', 'messages'],
      operator: ['permissions', 'messages', 'spawn'],
    };
    for (const [role, features] of Object.entries(expected)) {
      const name = `u-${role}`;
      expect((await addUser(base, admin, name, role, `senha de ${name} 1`)).status).toBe(201);
      const cookie = await login(base, name, `senha de ${name} 1`);
      expect((await call(base, 'GET', '/api/qualquer', { cookie })).json.features).toEqual(features);
    }
  });

  it('só administrador gerencia; os outros não listam, não criam e não mudam o próprio papel', async () => {
    const { base } = await setup();
    const admin = await login(base, 'chefe', ADMIN_PASS);
    await addUser(base, admin, 'ana', 'operator', 'senha da ana 123');
    const ana = await login(base, 'ana', 'senha da ana 123');
    expect((await call(base, 'GET', '/api/remote/users', { cookie: ana })).status).toBe(403);
    expect((await addUser(base, ana, 'nova', 'admin')).status).toBe(403);
    expect((await call(base, 'PATCH', '/api/remote/users/ana', { cookie: ana, body: { role: 'admin' } })).status).toBe(403);
    expect((await call(base, 'DELETE', '/api/remote/users/chefe', { cookie: ana })).status).toBe(403);
    expect((await call(base, 'GET', '/api/remote/me', { cookie: ana })).json.admin).toBe(false);
  });

  it('sem login, as rotas de contas e a página não respondem', async () => {
    const { base } = await setup();
    expect((await call(base, 'GET', '/api/remote/users')).status).toBe(401);
    expect((await call(base, 'GET', '/api/remote/me')).status).toBe(401);
    expect((await call(base, 'POST', '/api/remote/password', { body: {} })).status).toBe(401);
    expect((await call(base, 'GET', '/usuarios')).status).toBe(302);
  });

  it('a lista nunca devolve o hash', async () => {
    const { base } = await setup();
    const cookie = await login(base, 'chefe', ADMIN_PASS);
    const r = await call(base, 'GET', '/api/remote/users', { cookie });
    expect(r.status).toBe(200);
    expect(r.text).not.toContain('scrypt');
    expect((r.json.users as Array<{ name: string }>).map((u) => u.name)).toEqual(['chefe']);
  });

  it('sempre fica um administrador ativo, e ninguém desativa ou remove a si mesmo', async () => {
    const { base } = await setup();
    const cookie = await login(base, 'chefe', ADMIN_PASS);
    expect((await call(base, 'PATCH', '/api/remote/users/chefe', { cookie, body: { role: 'viewer' } })).status).toBe(409);
    expect((await call(base, 'PATCH', '/api/remote/users/chefe', { cookie, body: { disabled: true } })).status).toBe(409);
    expect((await call(base, 'DELETE', '/api/remote/users/chefe', { cookie })).status).toBe(409);
    await addUser(base, cookie, 'ana', 'admin', 'senha da ana 123');
    expect((await call(base, 'PATCH', '/api/remote/users/chefe', { cookie, body: { role: 'viewer' } })).status).toBe(200);
  });

  it('recusa senha curta, igual ao nome, nome inválido, papel inválido e usuário repetido', async () => {
    const { base } = await setup();
    const cookie = await login(base, 'chefe', ADMIN_PASS);
    expect((await addUser(base, cookie, 'ana', 'viewer', 'curta')).status).toBe(400);
    expect((await addUser(base, cookie, 'anaanaanaana', 'viewer', 'anaanaanaana')).status).toBe(400);
    expect((await addUser(base, cookie, '../admin', 'viewer')).status).toBe(400);
    expect((await addUser(base, cookie, 'ana', 'dono')).status).toBe(400);
    expect((await addUser(base, cookie, 'chefe', 'viewer')).status).toBe(409);
    expect((await addUser(base, cookie, '__proto__', 'viewer')).status).toBe(400);
  });
});

describe('contas: tirar o acesso', () => {
  it('desativar derruba a sessão guardada e a conexão aberta, e reativar não ressuscita o token antigo', async () => {
    const { base } = await setup();
    const admin = await login(base, 'chefe', ADMIN_PASS);
    await addUser(base, admin, 'ana', 'approver', 'senha da ana 123');
    const ana = await login(base, 'ana', 'senha da ana 123');
    const url = new URL('/api/stream', base);
    const closed = new Promise<void>((ok, fail) => {
      const req = http.get(url, { headers: { Cookie: ana } }, (res) => {
        expect(res.statusCode).toBe(200);
        res.on('close', () => ok());
        res.on('error', () => ok());
        res.resume();
        res.once('data', () => void call(base, 'PATCH', '/api/remote/users/ana', { cookie: admin, body: { disabled: true } }).catch(fail));
      });
      req.on('error', () => ok());
    });
    await closed;
    expect((await call(base, 'GET', '/api/remote/me', { cookie: ana })).status).toBe(401);
    await call(base, 'PATCH', '/api/remote/users/ana', { cookie: admin, body: { disabled: false } });
    expect((await call(base, 'GET', '/api/remote/me', { cookie: ana })).status).toBe(401);
    expect(await login(base, 'ana', 'senha da ana 123')).toContain(COOKIE);
  });

  it('remover e encerrar sessões derrubam o token; recriar com o mesmo nome não aceita o token antigo', async () => {
    const { base } = await setup();
    const admin = await login(base, 'chefe', ADMIN_PASS);
    await addUser(base, admin, 'ana', 'approver', 'senha da ana 123');
    const first = await login(base, 'ana', 'senha da ana 123');
    await call(base, 'PATCH', '/api/remote/users/ana', { cookie: admin, body: { revoke: true } });
    expect((await call(base, 'GET', '/api/remote/me', { cookie: first })).status).toBe(401);
    const second = await login(base, 'ana', 'senha da ana 123');
    await call(base, 'DELETE', '/api/remote/users/ana', { cookie: admin });
    expect((await call(base, 'GET', '/api/remote/me', { cookie: second })).status).toBe(401);
    expect((await call(base, 'PATCH', '/api/remote/users/ana', { cookie: admin, body: { revoke: true } })).status).toBe(404);
    await addUser(base, admin, 'ana', 'approver', 'senha da ana 123');
    expect((await call(base, 'GET', '/api/remote/me', { cookie: first })).status).toBe(401);
    expect((await call(base, 'GET', '/api/remote/me', { cookie: second })).status).toBe(401);
    const third = await login(base, 'ana', 'senha da ana 123');
    expect((await call(base, 'GET', '/api/remote/me', { cookie: third })).status).toBe(200);
  });

  it('mudar o papel vale na hora, sem novo login', async () => {
    const { base } = await setup();
    const admin = await login(base, 'chefe', ADMIN_PASS);
    await addUser(base, admin, 'ana', 'operator', 'senha da ana 123');
    const ana = await login(base, 'ana', 'senha da ana 123');
    expect((await call(base, 'GET', '/api/x', { cookie: ana })).json.features).toEqual(ALL);
    await call(base, 'PATCH', '/api/remote/users/ana', { cookie: admin, body: { role: 'viewer' } });
    await new Promise((ok) => setTimeout(ok, 200));
    expect((await call(base, 'GET', '/api/x', { cookie: ana })).json.features).toEqual([]);
  });

  it('trocar a própria senha exige a atual e derruba as sessões', async () => {
    const { base } = await setup();
    const admin = await login(base, 'chefe', ADMIN_PASS);
    await addUser(base, admin, 'ana', 'viewer', 'senha da ana 123');
    const ana = await login(base, 'ana', 'senha da ana 123');
    expect((await call(base, 'POST', '/api/remote/password', { cookie: ana, body: { current: 'errada errada', next: 'senha nova 12345' } })).status).toBe(403);
    expect((await call(base, 'POST', '/api/remote/password', { cookie: ana, body: { current: 'senha da ana 123', next: 'curta' } })).status).toBe(400);
    const r = await call(base, 'POST', '/api/remote/password', { cookie: ana, body: { current: 'senha da ana 123', next: 'senha nova 12345' } });
    expect(r.status).toBe(200);
    expect((await call(base, 'GET', '/api/remote/me', { cookie: ana })).status).toBe(401);
    expect((await call(base, 'POST', '/api/remote/login', { body: { user: 'ana', password: 'senha da ana 123' } })).status).toBe(401);
    await login(base, 'ana', 'senha nova 12345');
  });
});

describe('contas: arquivo e recuperação', () => {
  it('trocar o hash no .env recoloca a conta como administradora ativa (saída de quem perdeu o acesso)', async () => {
    const tmp = tempDir();
    closers.push(() => tmp.cleanup());
    const file = join(tmp.dir, 'u.json');
    const store = new UserStore(file, { user: 'chefe', hashText: SEED_HASH });
    store.add('ana', 'admin', await quickHash('senha da ana 123'));
    store.update('chefe', { role: 'viewer', disabled: true });
    const novo = await quickHash('recuperada 12345');
    const again = new UserStore(file, { user: 'chefe', hashText: novo });
    expect(again.get('chefe')).toMatchObject({ role: 'admin', disabled: false, hash: novo });
    expect(again.get('ana')?.role).toBe('admin');
  });

  it('reiniciar com o mesmo .env não desfaz nada', async () => {
    const tmp = tempDir();
    closers.push(() => tmp.cleanup());
    const file = join(tmp.dir, 'u.json');
    const store = new UserStore(file, { user: 'chefe', hashText: SEED_HASH });
    store.add('ana', 'admin', await quickHash('senha da ana 123'));
    store.update('chefe', { role: 'viewer' });
    expect(new UserStore(file, { user: 'chefe', hashText: SEED_HASH }).get('chefe')?.role).toBe('viewer');
  });

  it('arquivo corrompido: ninguém entra, nada é sobrescrito e a conta do .env não volta sozinha', async () => {
    const tmp = tempDir();
    closers.push(() => tmp.cleanup());
    const file = join(tmp.dir, 'u.json');
    writeFileSync(file, '{ quebrado');
    const store = new UserStore(file, { user: 'chefe', hashText: SEED_HASH });
    expect(store.problem).toBeTruthy();
    expect(store.get('chefe')).toBeUndefined();
    expect(() => store.add('ana', 'viewer', SEED_HASH)).toThrow();
    expect(readFileSync(file, 'utf8')).toBe('{ quebrado');
  });

  it('mudança feita por fora (npm run remote:users) vale na hora e avisa quem estiver conectado', async () => {
    const tmp = tempDir();
    closers.push(() => tmp.cleanup());
    const file = join(tmp.dir, 'u.json');
    const server = new UserStore(file, { user: 'chefe', hashText: SEED_HASH });
    server.add('ana', 'approver', await quickHash('senha da ana 123'));
    const changed: string[] = [];
    server.onChange((n) => changed.push(n));
    await new Promise((ok) => setTimeout(ok, 20));
    new UserStore(file, { user: 'chefe', hashText: SEED_HASH }).update('ana', { disabled: true });
    expect(server.get('ana')?.disabled).toBe(true);
    await new Promise((ok) => setTimeout(ok, 200));
    expect(changed).toContain('ana');
    expect(existsSync(`${file}.tmp`)).toBe(false);
  });
});

describe('freio por endereço', () => {
  it('quem erra de um endereço não trava o login de outro', () => {
    let now = 1_000_000;
    const t = new LoginThrottles(() => now);
    for (let i = 0; i < 5; i++) {
      const a = t.scoped('192.0.2.1');
      expect(a.begin()).toBe(true);
      a.end(false);
    }
    expect(t.scoped('192.0.2.1').retryAfter()).toBeGreaterThan(0);
    expect(t.scoped('192.0.2.2').retryAfter()).toBe(0);
    now += 400_000;
    expect(t.scoped('192.0.2.1').retryAfter()).toBe(0);
  });

  it('limita as conferências de senha ao mesmo tempo, e o limite volta depois', () => {
    const t = new LoginThrottles(Date.now, 1000, 2);
    const a = t.scoped('192.0.2.1');
    const b = t.scoped('192.0.2.2');
    expect(a.begin()).toBe(true);
    expect(b.begin()).toBe(true);
    const c = t.scoped('192.0.2.3');
    expect(c.begin()).toBe(false);
    a.end(true);
    expect(c.begin()).toBe(true);
    b.end(true);
    c.end(true);
  });

  it('a lista de endereços não cresce sem limite', () => {
    const t = new LoginThrottles(Date.now, 10);
    for (let i = 0; i < 100; i++) t.scoped(`192.0.2.${i}`);
    expect((t as unknown as { byIp: Map<string, unknown> }).byIp.size).toBeLessThanOrEqual(10);
  });
});

describe('página de usuários', () => {
  it('não leva dados de contas no HTML: tudo entra como texto pela API', () => {
    const html = usersPage();
    expect(html).not.toContain('innerHTML');
    expect(html).toContain('/api/remote/users');
    expect(html).toContain('<dialog');
  });

  it('o script da página compila', () => {
    const script = /<script>([\s\S]*)<\/script>/.exec(usersPage())?.[1] ?? '';
    expect(script.length).toBeGreaterThan(1000);
    expect(() => new Function(script)).not.toThrow();
  });
});
