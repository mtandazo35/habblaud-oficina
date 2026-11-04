import { readFileSync, statSync } from 'node:fs';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { setQuiet } from '../log';
import { AuditLog } from '../remote/audit';
import { hashPassword, parsePasswordHash } from '../remote/password';
import { totpAt, TOTP_PERIOD_S } from '../remote/totp';
import { ConnectionTracker, UserStore } from '../remote/users';
import { tempDir } from '../test/fixtures';
import { createRequestGuard } from './guard';
import { createRemoteGate, loginPage, LoginThrottles, RemoteSessions, type RemoteFeature } from './remote';
import { createUserRoutes, usersPage } from './remote-users';

setQuiet(true);

const SECRET = Buffer.alloc(32, 7);
const ADMIN_PASS = 'senha do admin 123';
const SEED_HASH = await hashPassword(ADMIN_PASS, 10);
const CFG = { user: 'chefe', passwordHash: parsePasswordHash(SEED_HASH)!, passwordHashText: SEED_HASH };
const quickHash = (p: string) => hashPassword(p, 10);
const ALL: RemoteFeature[] = ['permissions', 'messages', 'terminal', 'spawn'];
const STEP_MS = TOTP_PERIOD_S * 1000;
const closers: Array<() => Promise<void> | void> = [];

afterEach(async () => {
  for (const c of closers.splice(0)) await c();
});

async function setup(opts: { requireTotp?: boolean } = {}) {
  const tmp = tempDir();
  const file = join(tmp.dir, 'remote-users.json');
  const clock = { now: 1_800_000_000_000 };
  const now = () => clock.now;
  const users = new UserStore(file, { user: CFG.user, hashText: SEED_HASH }, now);
  const connections = new ConnectionTracker();
  users.onChange((name) => connections.kick(name));
  const throttles = new LoginThrottles(now);
  const audit = new AuditLog(join(tmp.dir, 'remote-audit.log'), { now });
  const gate = createRemoteGate({
    config: CFG,
    sessions: new RemoteSessions(SECRET, CFG, now),
    secure: false,
    users,
    throttles,
    connections,
    audit,
    routes: createUserRoutes({ users, throttles, allow: new Set(ALL), hash: quickHash, audit, requireTotp: opts.requireTotp }),
  });
  const guard = createRequestGuard();
  const server = http.createServer((req, res) => {
    if (guard(req, res)) return;
    const url = new URL(req.url ?? '/', 'http://x');
    if (gate(req, res, url)) return;
    // No lugar da API: lê o corpo no mesmo ciclo, como as rotas de permissões e mensagens.
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ reached: url.pathname, body: Buffer.concat(chunks).toString('utf8') }));
    });
  });
  await new Promise<void>((ok) => server.listen(0, '127.0.0.1', ok));
  closers.push(async () => {
    server.closeAllConnections();
    await new Promise<void>((ok) => server.close(() => ok()));
    tmp.cleanup();
  });
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return { base, users, file, clock, audit, logFile: audit.file };
}

async function call(base: string, method: string, path: string, opts: { cookie?: string; body?: unknown } = {}) {
  const res = await fetch(new URL(path, base), {
    method,
    redirect: 'manual',
    headers: { ...(method !== 'GET' ? { 'Content-Type': 'application/json' } : {}), ...(opts.cookie ? { Cookie: opts.cookie } : {}) },
    body: method === 'GET' ? undefined : JSON.stringify(opts.body ?? {}),
  });
  const text = await res.text();
  let json: Record<string, unknown> = {};
  try {
    json = JSON.parse(text) as Record<string, unknown>;
  } catch {
    // página HTML
  }
  return { status: res.status, json, text, setCookie: res.headers.get('set-cookie') ?? '', location: res.headers.get('location') ?? '' };
}

const post = (base: string, path: string, cookie: string | undefined, body: unknown) => call(base, 'POST', path, { cookie, body });
const tryLogin = (base: string, user: string, password: string, code?: string) => post(base, '/api/remote/login', undefined, { user, password, code });

async function login(base: string, user: string, password: string, code?: string): Promise<string> {
  const r = await tryLogin(base, user, password, code);
  expect(r.status, `login de ${user}`).toBe(200);
  return r.setCookie.split(';')[0];
}

/** Ativa o 2FA da conta do .env e devolve o segredo, os códigos de recuperação e a sessão antiga. */
async function enable(ctx: Awaited<ReturnType<typeof setup>>, user = 'chefe', password = ADMIN_PASS) {
  const cookie = await login(ctx.base, user, password);
  const started = await post(ctx.base, '/api/remote/2fa/setup', cookie, { password });
  expect(started.status).toBe(200);
  const secret = started.json.secret as string;
  const done = await post(ctx.base, '/api/remote/2fa/confirm', cookie, { code: totpAt(secret, ctx.clock.now) });
  expect(done.status).toBe(200);
  return { secret, recovery: done.json.recovery as string[], oldCookie: cookie, uri: started.json.uri as string };
}

describe('2FA: ativar', () => {
  it('pede a senha, mostra o segredo uma vez e só ativa com um código certo', async () => {
    const ctx = await setup();
    const cookie = await login(ctx.base, 'chefe', ADMIN_PASS);
    expect((await post(ctx.base, '/api/remote/2fa/setup', cookie, { password: 'errada errada' })).status).toBe(403);
    const started = await post(ctx.base, '/api/remote/2fa/setup', cookie, { password: ADMIN_PASS });
    const secret = started.json.secret as string;
    expect(secret).toMatch(/^[A-Z2-7]{32}$/);
    expect(started.json.uri).toContain(`otpauth://totp/Habblaud:chefe?secret=${secret}`);
    // Ainda pendente: o login não muda, e o código errado não ativa.
    await login(ctx.base, 'chefe', ADMIN_PASS);
    expect((await post(ctx.base, '/api/remote/2fa/confirm', cookie, { code: '000000' })).status).toBe(403);
    expect(ctx.users.get('chefe')?.totp).toBeUndefined();
    const done = await post(ctx.base, '/api/remote/2fa/confirm', cookie, { code: totpAt(secret, ctx.clock.now) });
    expect(done.status).toBe(200);
    expect(done.json.recovery).toHaveLength(10);
    expect(ctx.users.get('chefe')?.totp).toBeTruthy();
    expect(ctx.users.get('chefe')?.totpPending).toBeUndefined();
  });

  it('ativar derruba as sessões abertas da conta', async () => {
    const ctx = await setup();
    const { oldCookie } = await enable(ctx);
    expect((await call(ctx.base, 'GET', '/api/remote/me', { cookie: oldCookie })).status).toBe(401);
  });

  it('com 2FA ativo, não dá para pedir o segredo de novo, e nenhuma resposta o devolve', async () => {
    const ctx = await setup();
    const { secret } = await enable(ctx);
    ctx.clock.now += STEP_MS;
    const cookie = await login(ctx.base, 'chefe', ADMIN_PASS, totpAt(secret, ctx.clock.now));
    expect((await post(ctx.base, '/api/remote/2fa/setup', cookie, { password: ADMIN_PASS })).status).toBe(409);
    const me = await call(ctx.base, 'GET', '/api/remote/me', { cookie });
    const list = await call(ctx.base, 'GET', '/api/remote/users', { cookie });
    expect(me.json.totp).toBe(true);
    expect(me.json.recoveryLeft).toBe(10);
    expect(me.text).not.toContain(secret);
    expect(list.text).not.toContain(secret);
    expect((list.json.users as Array<{ totp: boolean }>)[0].totp).toBe(true);
    expect(usersPage()).not.toContain(secret);
  });

  it('o segredo e os códigos só existem no arquivo de contas (600); os códigos de recuperação, só em hash', async () => {
    const ctx = await setup();
    const { secret, recovery } = await enable(ctx);
    const raw = readFileSync(ctx.file, 'utf8');
    expect(raw).toContain(secret);
    for (const code of recovery) {
      expect(raw).not.toContain(code);
      expect(raw).not.toContain(code.replace(/-/g, ''));
    }
    if (process.platform !== 'win32') expect(statSync(ctx.file).mode & 0o777).toBe(0o600);
    const log = readFileSync(ctx.logFile, 'utf8');
    expect(log).not.toContain(secret);
    for (const code of recovery) expect(log).not.toContain(code);
  });

  it('a ativação começada expira', async () => {
    const ctx = await setup();
    const cookie = await login(ctx.base, 'chefe', ADMIN_PASS);
    const started = await post(ctx.base, '/api/remote/2fa/setup', cookie, { password: ADMIN_PASS });
    ctx.clock.now += 16 * 60 * 1000;
    const late = await post(ctx.base, '/api/remote/2fa/confirm', cookie, { code: totpAt(started.json.secret as string, ctx.clock.now) });
    expect(late.status).toBe(409);
  });
});

describe('2FA: login', () => {
  it('senha errada e código errado recebem exatamente a mesma resposta', async () => {
    const ctx = await setup();
    const { secret } = await enable(ctx);
    ctx.clock.now += STEP_MS;
    const answers = [
      await tryLogin(ctx.base, 'chefe', 'errada errada', totpAt(secret, ctx.clock.now)),
      await tryLogin(ctx.base, 'chefe', ADMIN_PASS, '000000'),
      await tryLogin(ctx.base, 'chefe', ADMIN_PASS),
      await tryLogin(ctx.base, 'ninguem', ADMIN_PASS, '000000'),
    ];
    expect(answers.map((a) => a.status)).toEqual([401, 401, 401, 401]);
    expect(new Set(answers.map((a) => a.text)).size).toBe(1);
  });

  it('senha errada não gasta o código', async () => {
    const ctx = await setup();
    const { secret } = await enable(ctx);
    ctx.clock.now += STEP_MS;
    const code = totpAt(secret, ctx.clock.now);
    expect((await tryLogin(ctx.base, 'chefe', 'errada errada', code)).status).toBe(401);
    await login(ctx.base, 'chefe', ADMIN_PASS, code);
  });

  it('o mesmo código não vale duas vezes, nem o da ativação, nem depois de reiniciar', async () => {
    const ctx = await setup();
    const { secret } = await enable(ctx);
    expect((await tryLogin(ctx.base, 'chefe', ADMIN_PASS, totpAt(secret, ctx.clock.now))).status).toBe(401);
    ctx.clock.now += STEP_MS;
    const code = totpAt(secret, ctx.clock.now);
    await login(ctx.base, 'chefe', ADMIN_PASS, code);
    expect((await tryLogin(ctx.base, 'chefe', ADMIN_PASS, code)).status).toBe(401);
    const restarted = new UserStore(ctx.file, { user: CFG.user, hashText: SEED_HASH }, () => ctx.clock.now);
    expect(restarted.checkSecondFactor('chefe', code)).toBeUndefined();
    ctx.clock.now += STEP_MS;
    await login(ctx.base, 'chefe', ADMIN_PASS, totpAt(secret, ctx.clock.now));
  });

  it('duas requisições ao mesmo tempo com o mesmo código: só uma entra', async () => {
    const ctx = await setup();
    const { secret } = await enable(ctx);
    ctx.clock.now += STEP_MS;
    const code = totpAt(secret, ctx.clock.now);
    const [a, b] = await Promise.all([tryLogin(ctx.base, 'chefe', ADMIN_PASS, code), tryLogin(ctx.base, 'chefe', ADMIN_PASS, code)]);
    // A segunda pode cair no freio (uma conferência por endereço de cada vez) ou na repetição: nunca em 200.
    expect([a.status, b.status].filter((s) => s === 200)).toHaveLength(1);
  });

  it('código de recuperação entra uma única vez, com qualquer formatação', async () => {
    const ctx = await setup();
    const { recovery } = await enable(ctx);
    const cookie = await login(ctx.base, 'chefe', ADMIN_PASS, ` ${recovery[0].replace(/-/g, ' ').toLowerCase()} `);
    expect((await call(ctx.base, 'GET', '/api/remote/me', { cookie })).json.recoveryLeft).toBe(9);
    expect((await tryLogin(ctx.base, 'chefe', ADMIN_PASS, recovery[0])).status).toBe(401);
    await login(ctx.base, 'chefe', ADMIN_PASS, recovery[1]);
  });

  it('o código passa pelo freio por endereço, mesmo com a senha certa', async () => {
    const ctx = await setup();
    await enable(ctx);
    for (let i = 0; i < 5; i++) expect((await tryLogin(ctx.base, 'chefe', ADMIN_PASS, '000000')).status).toBe(401);
    expect((await tryLogin(ctx.base, 'chefe', ADMIN_PASS, '000000')).status).toBe(429);
  });

  it('conta sem 2FA continua entrando só com a senha, e o código digitado é ignorado', async () => {
    const ctx = await setup();
    await login(ctx.base, 'chefe', ADMIN_PASS);
    await login(ctx.base, 'chefe', ADMIN_PASS, '123456');
  });

  it('a página de login só pede o código com contas, e o campo aceita letras', () => {
    expect(loginPage({ caDownload: false })).not.toContain('one-time-code');
    const html = loginPage({ caDownload: false, code: true });
    expect(html).toContain('one-time-code');
    expect(html).not.toContain('inputmode="numeric"');
  });
});

describe('2FA: desativar', () => {
  it('a própria conta precisa de senha e código, e isso derruba as sessões', async () => {
    const ctx = await setup();
    const { secret } = await enable(ctx);
    ctx.clock.now += STEP_MS;
    const cookie = await login(ctx.base, 'chefe', ADMIN_PASS, totpAt(secret, ctx.clock.now));
    ctx.clock.now += STEP_MS;
    const code = totpAt(secret, ctx.clock.now);
    expect((await post(ctx.base, '/api/remote/2fa/disable', cookie, { password: ADMIN_PASS, code: '000000' })).status).toBe(403);
    expect((await post(ctx.base, '/api/remote/2fa/disable', cookie, { password: 'errada errada', code })).status).toBe(403);
    expect((await post(ctx.base, '/api/remote/2fa/disable', cookie, { password: ADMIN_PASS, code })).status).toBe(200);
    expect((await call(ctx.base, 'GET', '/api/remote/me', { cookie })).status).toBe(401);
    expect(ctx.users.get('chefe')?.totp).toBeUndefined();
    await login(ctx.base, 'chefe', ADMIN_PASS);
  });

  it('um administrador desativa o 2FA de outra conta, derrubando as sessões dela; a dele mesmo, não por aí', async () => {
    const ctx = await setup();
    const admin = await login(ctx.base, 'chefe', ADMIN_PASS);
    await post(ctx.base, '/api/remote/users', admin, { name: 'ana', role: 'operator', password: 'senha da ana 123' });
    const { secret } = await enable(ctx, 'ana', 'senha da ana 123');
    ctx.clock.now += STEP_MS;
    const ana = await login(ctx.base, 'ana', 'senha da ana 123', totpAt(secret, ctx.clock.now));
    expect((await call(ctx.base, 'PATCH', '/api/remote/users/chefe', { cookie: admin, body: { totp: false } })).status).toBe(409);
    // Quem não é administrador não mexe no 2FA dos outros.
    expect((await call(ctx.base, 'PATCH', '/api/remote/users/chefe', { cookie: ana, body: { totp: false } })).status).toBe(403);
    const r = await call(ctx.base, 'PATCH', '/api/remote/users/ana', { cookie: admin, body: { totp: false } });
    expect(r.status).toBe(200);
    expect((r.json.user as { totp: boolean }).totp).toBe(false);
    expect((await call(ctx.base, 'GET', '/api/remote/me', { cookie: ana })).status).toBe(401);
    await login(ctx.base, 'ana', 'senha da ana 123');
    expect((await call(ctx.base, 'PATCH', '/api/remote/users/ana', { cookie: admin, body: { totp: false } })).status).toBe(409);
  });

  it('a loja faz o que o npm run remote:users usa, percebido pelo servidor em execução', async () => {
    const ctx = await setup();
    const { secret } = await enable(ctx);
    ctx.clock.now += STEP_MS;
    const cookie = await login(ctx.base, 'chefe', ADMIN_PASS, totpAt(secret, ctx.clock.now));
    await new Promise((ok) => setTimeout(ok, 20));
    new UserStore(ctx.file, { user: CFG.user, hashText: SEED_HASH }, () => ctx.clock.now).update('chefe', { totpOff: true });
    expect((await call(ctx.base, 'GET', '/api/remote/me', { cookie })).status).toBe(401);
    await login(ctx.base, 'chefe', ADMIN_PASS);
  });

  it('trocar o hash no .env tira o 2FA da conta: é a última saída', async () => {
    const ctx = await setup();
    await enable(ctx);
    const novo = await quickHash('recuperada 12345');
    const again = new UserStore(ctx.file, { user: 'chefe', hashText: novo }, () => ctx.clock.now);
    expect(again.seedApplied).toBe('chefe');
    expect(again.get('chefe')?.totp).toBeUndefined();
    expect(new UserStore(ctx.file, { user: 'chefe', hashText: novo }, () => ctx.clock.now).seedApplied).toBeUndefined();
  });

  it('arquivo de contas antigo, sem nada de 2FA, continua valendo; 2FA estragado não vira conta sem 2FA', async () => {
    const ctx = await setup();
    const data = JSON.parse(readFileSync(ctx.file, 'utf8')) as { users: Array<Record<string, unknown>> };
    expect(data.users[0].totp).toBeUndefined();
    await enable(ctx);
    const { writeFileSync } = await import('node:fs');
    const withTotp = JSON.parse(readFileSync(ctx.file, 'utf8')) as { users: Array<{ totp: { secret: string } }> };
    withTotp.users[0].totp.secret = 'minusculo';
    writeFileSync(ctx.file, JSON.stringify(withTotp));
    const store = new UserStore(ctx.file, undefined, () => ctx.clock.now);
    expect(store.problem).toBeTruthy();
    expect(store.get('chefe')).toBeUndefined();
  });
});

describe('2FA: insistir e exigir', () => {
  it('desligado (padrão): Operar sem 2FA usa tudo; o escritório leva para /usuarios só de vez em quando', async () => {
    const ctx = await setup();
    const cookie = await login(ctx.base, 'chefe', ADMIN_PASS);
    const me = await call(ctx.base, 'GET', '/api/remote/me', { cookie });
    expect(me.json).toMatchObject({ totp: false, totpNeeded: true, restricted: false, features: ALL });
    const first = await call(ctx.base, 'GET', '/', { cookie });
    expect(first.status).toBe(302);
    expect(first.location).toBe('/usuarios');
    expect(first.setCookie).toMatch(/habblaud_2fa_aviso=1;.*HttpOnly.*SameSite=Strict/);
    const nudged = `${cookie}; ${first.setCookie.split(';')[0]}`;
    expect((await call(ctx.base, 'GET', '/', { cookie: nudged })).status).toBe(200);
    expect((await call(ctx.base, 'GET', '/api/qualquer', { cookie })).json.reached).toBe('/api/qualquer');
  });

  it('Ver e Aprobar não são levados nem restringidos, nem com o obrigatório ligado', async () => {
    const ctx = await setup({ requireTotp: true });
    const created = new UserStore(ctx.file, { user: CFG.user, hashText: SEED_HASH }, () => ctx.clock.now);
    created.add('ana', 'approver', await quickHash('senha da ana 123'));
    const ana = await login(ctx.base, 'ana', 'senha da ana 123');
    expect((await call(ctx.base, 'GET', '/api/remote/me', { cookie: ana })).json).toMatchObject({ totpNeeded: false, restricted: false });
    expect((await call(ctx.base, 'GET', '/', { cookie: ana })).status).toBe(200);
    expect((await post(ctx.base, '/api/messages', ana, { agentId: 'a1', text: 'oi' })).status).toBe(200);
  });

  it('ligado: a conta entra, mas só alcança /usuarios até ativar; depois de ativar, volta tudo', async () => {
    const ctx = await setup({ requireTotp: true });
    const cookie = await login(ctx.base, 'chefe', ADMIN_PASS);
    expect((await call(ctx.base, 'GET', '/api/remote/me', { cookie })).json).toMatchObject({ restricted: true, features: [] });
    expect((await call(ctx.base, 'GET', '/usuarios', { cookie })).status).toBe(200);
    const home = await call(ctx.base, 'GET', '/', { cookie });
    expect([home.status, home.location]).toEqual([302, '/usuarios']);
    // Mesmo já tendo visto o aviso de hoje, não há como passar.
    const nudged = `${cookie}; habblaud_2fa_aviso=1`;
    expect((await call(ctx.base, 'GET', '/', { cookie: nudged })).status).toBe(302);
    expect((await call(ctx.base, 'GET', '/api/snapshot', { cookie })).status).toBe(403);
    expect((await post(ctx.base, '/api/messages', cookie, { agentId: 'a1', text: 'x' })).status).toBe(403);
    expect((await post(ctx.base, '/api/permissions/p1/decision', cookie, { behavior: 'allow' })).status).toBe(403);
    expect((await call(ctx.base, 'GET', '/api/remote/users', { cookie })).status).toBe(403);
    expect((await call(ctx.base, 'GET', '/api/remote/audit', { cookie })).status).toBe(403);
    const started = await post(ctx.base, '/api/remote/2fa/setup', cookie, { password: ADMIN_PASS });
    expect(started.status).toBe(200);
    const secret = started.json.secret as string;
    expect((await post(ctx.base, '/api/remote/2fa/confirm', cookie, { code: totpAt(secret, ctx.clock.now) })).status).toBe(200);
    ctx.clock.now += STEP_MS;
    const fresh = await login(ctx.base, 'chefe', ADMIN_PASS, totpAt(secret, ctx.clock.now));
    expect((await call(ctx.base, 'GET', '/api/remote/me', { cookie: fresh })).json).toMatchObject({ restricted: false, features: ALL });
    expect((await call(ctx.base, 'GET', '/', { cookie: fresh })).status).toBe(200);
  });

  it('ligado: um administrador pode desativar o 2FA de quem perdeu o celular, e a pessoa volta a entrar', async () => {
    const ctx = await setup({ requireTotp: true });
    const { secret } = await enable(ctx);
    ctx.clock.now += STEP_MS;
    const admin = await login(ctx.base, 'chefe', ADMIN_PASS, totpAt(secret, ctx.clock.now));
    await post(ctx.base, '/api/remote/users', admin, { name: 'ana', role: 'admin', password: 'senha da ana 123' });
    const ana = await enable(ctx, 'ana', 'senha da ana 123');
    expect((await call(ctx.base, 'PATCH', '/api/remote/users/ana', { cookie: admin, body: { totp: false } })).status).toBe(200);
    const back = await login(ctx.base, 'ana', 'senha da ana 123');
    expect((await call(ctx.base, 'GET', '/api/remote/me', { cookie: back })).json).toMatchObject({ restricted: true });
    expect(ana.secret).not.toBe(secret);
  });
});

describe('registro de acessos pela porta remota', () => {
  const log = (file: string) => readFileSync(file, 'utf8').trim().split('\n').map((l) => JSON.parse(l) as Record<string, unknown>);

  it('registra login certo e errado com endereço, e saída; nunca senha nem código', async () => {
    const ctx = await setup();
    const { secret, recovery } = await enable(ctx);
    ctx.clock.now += STEP_MS;
    const code = totpAt(secret, ctx.clock.now);
    await tryLogin(ctx.base, 'chefe', ADMIN_PASS, '000111');
    await tryLogin(ctx.base, 'chefe', 'senha-errada-unica', code);
    const cookie = await login(ctx.base, 'chefe', ADMIN_PASS, code);
    await post(ctx.base, '/api/remote/logout', cookie, {});
    const entries = log(ctx.logFile);
    expect(entries.filter((e) => e.ev === 'login.fail').map((e) => e.reason)).toEqual(['code', 'credentials']);
    const okEntry = entries.filter((e) => e.ev === 'login.ok').at(-1)!;
    expect(okEntry).toMatchObject({ user: 'chefe', via: 'totp' });
    expect(String(okEntry.ip)).toContain('127.0.0.1');
    expect(entries.at(-1)).toMatchObject({ ev: 'logout', user: 'chefe' });
    const raw = readFileSync(ctx.logFile, 'utf8');
    for (const secretText of [ADMIN_PASS, 'senha-errada-unica', '000111', code, secret, recovery[0]]) expect(raw).not.toContain(secretText);
  });

  it('usuário digitado com quebra de linha não forja uma entrada', async () => {
    const ctx = await setup();
    await tryLogin(ctx.base, 'ana\n{"t":"x","ev":"login.ok","user":"chefe"}', 'errada errada');
    const lines = readFileSync(ctx.logFile, 'utf8').trim().split('\n');
    expect(lines.filter((l) => l.includes('login.fail'))).toHaveLength(1);
    expect(log(ctx.logFile).some((e) => e.ev === 'login.ok')).toBe(false);
  });

  it('registra mudanças de contas: quem, em quem e o quê, sem a senha', async () => {
    const ctx = await setup();
    const cookie = await login(ctx.base, 'chefe', ADMIN_PASS);
    await post(ctx.base, '/api/remote/users', cookie, { name: 'ana', role: 'viewer', password: 'senha da ana 123' });
    await call(ctx.base, 'PATCH', '/api/remote/users/ana', { cookie, body: { role: 'approver', password: 'senha nova da ana 1' } });
    await call(ctx.base, 'PATCH', '/api/remote/users/ana', { cookie, body: { revoke: true } });
    await call(ctx.base, 'DELETE', '/api/remote/users/ana', { cookie });
    const entries = log(ctx.logFile).filter((e) => String(e.ev).startsWith('user.'));
    expect(entries.map((e) => [e.ev, e.by, e.target, e.what])).toEqual([
      ['user.add', 'chefe', 'ana', 'role=viewer'],
      ['user.change', 'chefe', 'ana', 'role=approver password'],
      ['user.change', 'chefe', 'ana', 'sessions'],
      ['user.remove', 'chefe', 'ana', undefined],
    ]);
    const raw = readFileSync(ctx.logFile, 'utf8');
    expect(raw).not.toContain('senha da ana');
    expect(raw).not.toContain('senha nova');
  });

  it('registra 2FA: ativar, falhar e desativar por administrador', async () => {
    const ctx = await setup();
    const admin = await login(ctx.base, 'chefe', ADMIN_PASS);
    await post(ctx.base, '/api/remote/users', admin, { name: 'ana', role: 'viewer', password: 'senha da ana 123' });
    const ana = await login(ctx.base, 'ana', 'senha da ana 123');
    await post(ctx.base, '/api/remote/2fa/setup', ana, { password: 'errada errada' });
    const started = await post(ctx.base, '/api/remote/2fa/setup', ana, { password: 'senha da ana 123' });
    await post(ctx.base, '/api/remote/2fa/confirm', ana, { code: totpAt(started.json.secret as string, ctx.clock.now) });
    await call(ctx.base, 'PATCH', '/api/remote/users/ana', { cookie: admin, body: { totp: false } });
    const entries = log(ctx.logFile).filter((e) => String(e.ev).startsWith('2fa.'));
    expect(entries.map((e) => [e.ev, e.by ?? e.user, e.target])).toEqual([
      ['2fa.fail', 'ana', undefined],
      ['2fa.setup', 'ana', undefined],
      ['2fa.on', 'ana', 'ana'],
      ['2fa.off', 'chefe', 'ana'],
    ]);
  });

  it('registra permissões e mensagens da porta remota sem o conteúdo, e a API recebe o corpo inteiro', async () => {
    const ctx = await setup();
    const cookie = await login(ctx.base, 'chefe', ADMIN_PASS);
    const text = 'texto-secreto-da-mensagem';
    const sent = await post(ctx.base, '/api/messages', cookie, { agentId: 'agente-1', text });
    expect(JSON.parse(sent.json.body as string).text).toBe(text);
    const denied = await post(ctx.base, '/api/permissions/p-1/decision', cookie, { behavior: 'deny', message: 'motivo-secreto' });
    expect(JSON.parse(denied.json.body as string).message).toBe('motivo-secreto');
    await post(ctx.base, '/api/permissions/p-2/decision', cookie, { behavior: 'inventado\ncom quebra' });
    await new Promise((ok) => setTimeout(ok, 20));
    const entries = log(ctx.logFile);
    expect(entries.find((e) => e.ev === 'message.send')).toMatchObject({ user: 'chefe', agent: 'agente-1', status: 200 });
    expect(entries.find((e) => e.id === 'p-1')).toMatchObject({ ev: 'permission.decision', user: 'chefe', behavior: 'deny', status: 200 });
    expect(entries.find((e) => e.id === 'p-2')?.behavior).toBeUndefined();
    const raw = readFileSync(ctx.logFile, 'utf8');
    expect(raw).not.toContain(text);
    expect(raw).not.toContain('motivo-secreto');
  });

  it('corpo fora do JSON na decisão não atrapalha nem aparece', async () => {
    const ctx = await setup();
    const cookie = await login(ctx.base, 'chefe', ADMIN_PASS);
    const res = await fetch(new URL('/api/permissions/p-3/decision', ctx.base), { method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: cookie }, body: 'nao-e-json-secreto' });
    expect(res.status).toBe(200);
    await res.text();
    await new Promise((ok) => setTimeout(ok, 20));
    expect(log(ctx.logFile).find((e) => e.id === 'p-3')).toMatchObject({ ev: 'permission.decision' });
    expect(readFileSync(ctx.logFile, 'utf8')).not.toContain('nao-e-json-secreto');
  });

  it('só administrador lê o registro, e a resposta vem do mais novo para o mais antigo', async () => {
    const ctx = await setup();
    const admin = await login(ctx.base, 'chefe', ADMIN_PASS);
    await post(ctx.base, '/api/remote/users', admin, { name: 'ana', role: 'approver', password: 'senha da ana 123' });
    const ana = await login(ctx.base, 'ana', 'senha da ana 123');
    expect((await call(ctx.base, 'GET', '/api/remote/audit', { cookie: ana })).status).toBe(403);
    expect((await call(ctx.base, 'GET', '/api/remote/audit')).status).toBe(401);
    expect((await post(ctx.base, '/api/remote/audit', admin, {})).status).toBe(405);
    const r = await call(ctx.base, 'GET', '/api/remote/audit', { cookie: admin });
    const entries = r.json.entries as Array<{ ev: string; user?: string }>;
    expect(entries[0]).toMatchObject({ ev: 'login.ok', user: 'ana' });
    expect(entries.at(-1)).toMatchObject({ ev: 'login.ok', user: 'chefe' });
  });
});

describe('página de usuários com 2FA', () => {
  it('o script da página continua compilando e toda escrita manda JSON', () => {
    const script = /<script>([\s\S]*)<\/script>/.exec(usersPage())?.[1] ?? '';
    expect(() => new Function(script)).not.toThrow();
    expect(script).toContain("'Content-Type': 'application/json'");
    expect(script).not.toContain('innerHTML');
    expect(script).toContain('/api/remote/2fa/setup');
    expect(script).toContain('/api/remote/audit');
    expect(script).toContain('toLocaleString');
  });
});
