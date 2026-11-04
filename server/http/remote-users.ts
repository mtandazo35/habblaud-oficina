// Rotas e página da gestão de contas (porta remota). Só chegam aqui requisições já autenticadas pelo filtro de
// http/remote.ts; quem não é administrador só pode trocar a própria senha.
import type { IncomingMessage, ServerResponse } from 'node:http';
import { getLocale, tr } from '../../shared/i18n';
import { hashPassword, parsePasswordHash, verifyPassword } from '../remote/password';
import { isRole, normalizeName, passwordProblem, ROLES, UserError, type RemoteRole, type RemoteUser, type UserPatch, type UserStore } from '../remote/users';
import { readBody, sendHtml, sendJson, type LoginThrottles, type RemoteFeature } from './remote';

export const USERS_PAGE = '/usuarios';

export interface UserRoutesDeps {
  users: UserStore;
  throttles: LoginThrottles;
  /** HABBLAUD_REMOTE_ALLOW: o teto do que qualquer papel consegue pela porta remota. */
  allow: ReadonlySet<RemoteFeature>;
  /** Conferência e hash da senha (injetáveis nos testes). */
  hash?: (password: string) => Promise<string>;
  verify?: typeof verifyPassword;
}

function publicUser(u: RemoteUser): { name: string; role: RemoteRole; disabled: boolean; createdAt: number } {
  return { name: u.name, role: u.role, disabled: u.disabled, createdAt: u.createdAt };
}

async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  const data: unknown = JSON.parse(await readBody(req));
  if (!data || typeof data !== 'object' || Array.isArray(data)) throw new UserError(tr('requisição inválida'));
  return data as Record<string, unknown>;
}

export function createUserRoutes(deps: UserRoutesDeps): (req: IncomingMessage, res: ServerResponse, url: URL, who: RemoteUser) => boolean {
  const { users } = deps;
  const hash = deps.hash ?? hashPassword;
  const verify = deps.verify ?? verifyPassword;

  const fail = (res: ServerResponse, err: unknown): void => {
    if (res.headersSent) return;
    if (err instanceof UserError) sendJson(res, err.status, { error: err.message });
    else sendJson(res, 400, { error: tr('requisição inválida') });
  };
  const newHash = async (password: unknown, name: string): Promise<string> => {
    if (typeof password !== 'string') throw new UserError(tr('senha inválida'));
    const problem = passwordProblem(password, name);
    if (problem) throw new UserError(tr('senha recusada: {0}', [problem]));
    return hash(password);
  };

  const changeOwnPassword = async (req: IncomingMessage, res: ServerResponse, who: RemoteUser): Promise<void> => {
    const body = await readJson(req);
    const limit = deps.throttles.scoped(req.socket.remoteAddress ?? '');
    if (!limit.begin()) {
      sendJson(res, 429, { error: tr('Muitas tentativas. Tente de novo em {0} s.', [Math.max(1, limit.retryAfter())]) });
      return;
    }
    let ok = false;
    try {
      const stored = parsePasswordHash(users.get(who.name)?.hash);
      if (!stored || typeof body.current !== 'string' || !(await verify(body.current, stored))) {
        sendJson(res, 403, { error: tr('A senha atual não confere.') });
        return;
      }
      ok = true;
    } finally {
      limit.end(ok);
    }
    users.update(who.name, { hash: await newHash(body.next, who.name) });
    sendJson(res, 200, { ok: true });
  };

  const patchUser = async (req: IncomingMessage, res: ServerResponse, name: string, who: RemoteUser): Promise<void> => {
    const body = await readJson(req);
    const patch: UserPatch = {};
    if (body.role !== undefined) {
      if (!isRole(body.role)) throw new UserError(tr('papel inválido'));
      patch.role = body.role;
    }
    if (body.disabled !== undefined) {
      if (typeof body.disabled !== 'boolean') throw new UserError(tr('requisição inválida'));
      if (body.disabled && name === who.name) throw new UserError(tr('você não pode desativar a sua própria conta'), 409);
      patch.disabled = body.disabled;
    }
    if (body.revoke === true) patch.revoke = true;
    if (body.password !== undefined) patch.hash = await newHash(body.password, name);
    sendJson(res, 200, { user: publicUser(users.update(name, patch)) });
  };

  const addUser = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const body = await readJson(req);
    const name = typeof body.name === 'string' ? normalizeName(body.name) : '';
    if (!isRole(body.role)) throw new UserError(tr('papel inválido'));
    if (users.get(name)) throw new UserError(tr('esse usuário já existe'), 409);
    sendJson(res, 201, { user: publicUser(users.add(name, body.role, await newHash(body.password, name))) });
  };

  return (req, res, url, who) => {
    const path = url.pathname;
    const method = req.method ?? 'GET';
    if (path === USERS_PAGE) {
      req.resume();
      if (method !== 'GET' && method !== 'HEAD') sendJson(res, 405, { error: tr('método não permitido') }, { Allow: 'GET' });
      else sendHtml(res, usersPage());
      return true;
    }
    if (path === '/api/remote/me') {
      req.resume();
      if (method !== 'GET') sendJson(res, 405, { error: tr('método não permitido') }, { Allow: 'GET' });
      else {
        sendJson(res, 200, {
          user: who.name,
          role: who.role,
          admin: who.role === 'admin',
          features: users.featuresOf(who.role).filter((f) => deps.allow.has(f)),
        });
      }
      return true;
    }
    if (path === '/api/remote/password') {
      if (method !== 'POST') {
        req.resume();
        sendJson(res, 405, { error: tr('método não permitido') }, { Allow: 'POST' });
      } else changeOwnPassword(req, res, who).catch((err) => fail(res, err));
      return true;
    }
    if (path !== '/api/remote/users' && !path.startsWith('/api/remote/users/')) return false;
    if (who.role !== 'admin') {
      req.resume();
      sendJson(res, 403, { error: tr('só um administrador pode gerenciar usuários') });
      return true;
    }
    if (path === '/api/remote/users') {
      if (method === 'GET') {
        req.resume();
        sendJson(res, 200, { users: users.list().map(publicUser), allow: [...deps.allow], roles: ROLES });
      } else if (method === 'POST') addUser(req, res).catch((err) => fail(res, err));
      else {
        req.resume();
        sendJson(res, 405, { error: tr('método não permitido') }, { Allow: 'GET, POST' });
      }
      return true;
    }
    let name: string;
    try {
      name = normalizeName(decodeURIComponent(path.slice('/api/remote/users/'.length)));
    } catch {
      req.resume();
      sendJson(res, 400, { error: tr('requisição inválida') });
      return true;
    }
    if (method === 'PATCH') patchUser(req, res, name, who).catch((err) => fail(res, err));
    else if (method === 'DELETE') {
      req.resume();
      try {
        if (name === who.name) throw new UserError(tr('você não pode remover a sua própria conta'), 409);
        users.remove(name);
        sendJson(res, 200, { ok: true });
      } catch (err) {
        fail(res, err);
      }
    } else {
      req.resume();
      sendJson(res, 405, { error: tr('método não permitido') }, { Allow: 'PATCH, DELETE' });
    }
    return true;
  };
}

/** Página simples, servida pelo próprio servidor: nada de dados dentro do HTML, tudo vem da API e entra como texto. */
export function usersPage(): string {
  // Dentro do <script>: JSON com "<" escapado, para nenhum texto fechar a tag.
  const texts = JSON.stringify({
    title: tr('Usuários'),
    you: tr('você'),
    active: tr('Ativo'),
    disabled: tr('Desativado'),
    roles: {
      viewer: tr('Ver: só olha o escritório'),
      approver: tr('Aprovar: responde permissões e manda mensagens'),
      operator: tr('Operar: também usa a terminal e abre agentes'),
      admin: tr('Administrar: também gerencia usuários'),
    },
    capped: tr('O limite HABBLAUD_REMOTE_ALLOW deste servidor não libera: {0}. Nenhum papel consegue usar isso.'),
    changePassword: tr('Trocar senha'),
    closeSessions: tr('Encerrar sessões'),
    deactivate: tr('Desativar'),
    activate: tr('Ativar'),
    remove: tr('Remover'),
    confirm: tr('Confirmar'),
    cancel: tr('Cancelar'),
    close: tr('Fechar'),
    confirmDeactivate: tr('Desativar {0}? As conexões abertas caem na hora.'),
    confirmRemove: tr('Remover {0}? Isso não pode ser desfeito.'),
    confirmClose: tr('Encerrar todas as sessões de {0}?'),
    newPasswordFor: tr('Nova senha de {0}'),
    created: tr('Usuário {0} criado. Passe a senha por um canal seguro: ela não aparece de novo.'),
    done: tr('Pronto.'),
    passwordChanged: tr('Senha trocada. Entre de novo com a senha nova.'),
    noConnection: tr('Sem conexão com o Habblaud.'),
    failed: tr('Não deu certo.'),
  }).replace(/</g, '\\u003c');
  const option = (role: RemoteRole, label: string) => `<option value="${role}">${label}</option>`;
  return `<!doctype html>
<html lang="${getLocale()}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Habblaud · ${tr('Usuários')}</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin: 0; background: #0e1116; color: #e6e9ee; font: 14px/1.45 system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif; padding: 16px; }
  main { max-width: 860px; margin: 0 auto; }
  h1 { margin: 0; font-size: 20px; color: #e6e9ee; }
  h2 { margin: 0 0 12px; font-size: 15px; color: #e6e9ee; }
  header { display: flex; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 16px; }
  a { color: #7fb8e0; }
  section { background: #151a21; border: 1px solid #2f3945; border-radius: 6px; padding: 16px; margin-bottom: 16px; }
  label { display: block; font-size: 13px; color: #a8b1bd; margin: 10px 0 4px; }
  input, select { width: 100%; padding: 10px; font: inherit; color: inherit; background: #0e1116; border: 1px solid #66717f; border-radius: 4px; }
  input:focus, select:focus { outline: 2px solid #7fb8e0; border-color: #7fb8e0; }
  button { padding: 9px 12px; font: inherit; color: #e6e9ee; background: #1c232c; border: 1px solid #66717f; border-radius: 4px; cursor: pointer; }
  button:disabled { opacity: .5; cursor: not-allowed; }
  button.main { color: #fff; font-weight: 600; background: #2f76b0; border-color: #4b90c8; }
  button.danger { color: #f27a76; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 0 12px; }
  .row { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 12px; }
  .user { border-top: 1px solid #2f3945; padding: 12px 0; }
  .user:first-child { border-top: 0; padding-top: 0; }
  .name { font-weight: 600; overflow-wrap: anywhere; }
  .muted { color: #a8b1bd; font-size: 13px; }
  .off { color: #f27a76; }
  dialog { width: min(92vw, 440px); color: inherit; background: #151a21; border: 1px solid #66717f; border-radius: 6px; padding: 18px; overflow-wrap: anywhere; }
  dialog::backdrop { background: rgba(0, 0, 0, .65); }
</style>
</head>
<body>
<main>
  <header><h1>${tr('Usuários')}</h1><a href="/">${tr('Voltar ao escritório')}</a></header>
  <section>
    <h2 id="me"></h2>
    <form id="own">
      <div class="grid">
        <div><label for="oc">${tr('Senha atual')}</label><input id="oc" type="password" autocomplete="current-password" required></div>
        <div><label for="on">${tr('Senha nova')}</label><input id="on" type="password" autocomplete="new-password" minlength="10" required></div>
      </div>
      <div class="row"><button class="main" type="submit">${tr('Trocar a minha senha')}</button></div>
    </form>
  </section>
  <section id="admin" hidden>
    <h2>${tr('Contas')}</h2>
    <p id="cap" class="muted" hidden></p>
    <div id="list"></div>
  </section>
  <section id="create" hidden>
    <h2>${tr('Novo usuário')}</h2>
    <form id="add">
      <div class="grid">
        <div><label for="an">${tr('Usuário')}</label><input id="an" autocomplete="off" autocapitalize="none" spellcheck="false" maxlength="32" required></div>
        <div><label for="ar">${tr('Papel')}</label><select id="ar">
          ${option('viewer', tr('Ver: só olha o escritório'))}
          ${option('approver', tr('Aprovar: responde permissões e manda mensagens'))}
          ${option('operator', tr('Operar: também usa a terminal e abre agentes'))}
          ${option('admin', tr('Administrar: também gerencia usuários'))}
        </select></div>
        <div><label for="ap">${tr('Senha')}</label><input id="ap" autocomplete="new-password" minlength="10" spellcheck="false" required></div>
      </div>
      <div class="row"><button type="button" id="gen">${tr('Gerar senha')}</button><button class="main" type="submit">${tr('Criar usuário')}</button></div>
    </form>
  </section>
</main>
<dialog id="dlg"><form method="dialog"><p id="dlgText"></p><input id="dlgInput" type="text" autocomplete="new-password" spellcheck="false" hidden><div class="row"><button class="main" id="dlgOk" value="ok"></button><button id="dlgNo" value="no"></button></div></form></dialog>
<script>
  const T = ${texts};
  const $ = (id) => document.getElementById(id);
  const fill = (text, values) => text.replace(/\\{(\\d+)\\}/g, (_, i) => values[Number(i)]);
  const dlg = $('dlg');
  function modal(text, opts) {
    const o = opts || {};
    $('dlgText').textContent = text;
    $('dlgInput').hidden = !o.input;
    $('dlgInput').value = '';
    $('dlgOk').textContent = o.ok || T.close;
    $('dlgNo').textContent = T.cancel;
    $('dlgNo').hidden = !o.ask;
    return new Promise((resolve) => {
      dlg.addEventListener('close', () => resolve(dlg.returnValue === 'ok' ? (o.input ? $('dlgInput').value : true) : false), { once: true });
      dlg.returnValue = 'no';
      dlg.showModal();
    });
  }
  async function api(method, path, body) {
    let r;
    try {
      r = await fetch(path, { method, credentials: 'same-origin', cache: 'no-store',
        headers: method === 'GET' ? {} : { 'Content-Type': 'application/json' }, body: method === 'GET' ? undefined : JSON.stringify(body || {}) });
    } catch { throw new Error(T.noConnection); }
    if (r.status === 401) { location.assign('/login'); throw new Error(T.failed); }
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(data.error || T.failed);
    return data;
  }
  const attempt = async (fn) => { try { await fn(); } catch (e) { await modal(e.message); } };
  const randomPassword = () => {
    const chars = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    const limit = 256 - (256 % chars.length);
    let out = '';
    while (out.length < 20) {
      for (const b of crypto.getRandomValues(new Uint8Array(32))) if (b < limit && out.length < 20) out += chars[b % chars.length];
    }
    return out;
  };
  let me;
  function button(text, onClick, cls) {
    const b = document.createElement('button');
    b.type = 'button';
    b.textContent = text;
    if (cls) b.className = cls;
    b.addEventListener('click', () => attempt(onClick));
    return b;
  }
  function renderUser(u) {
    const self = u.name === me.user;
    const box = document.createElement('div');
    box.className = 'user';
    const name = document.createElement('div');
    name.className = 'name';
    name.textContent = u.name + (self ? ' (' + T.you + ')' : '');
    const state = document.createElement('div');
    state.className = u.disabled ? 'off' : 'muted';
    state.textContent = u.disabled ? T.disabled : T.active;
    const select = document.createElement('select');
    select.setAttribute('aria-label', u.name);
    for (const role of Object.keys(T.roles)) {
      const o = document.createElement('option');
      o.value = role;
      o.textContent = T.roles[role];
      o.selected = role === u.role;
      select.append(o);
    }
    select.addEventListener('change', () => attempt(async () => {
      try { await api('PATCH', '/api/remote/users/' + encodeURIComponent(u.name), { role: select.value }); }
      catch (e) { select.value = u.role; throw e; }
      await load();
    }));
    const row = document.createElement('div');
    row.className = 'row';
    const path = '/api/remote/users/' + encodeURIComponent(u.name);
    if (!self) {
      row.append(button(T.changePassword, async () => {
        const password = await modal(fill(T.newPasswordFor, [u.name]), { ask: true, input: true, ok: T.confirm });
        if (!password) return;
        await api('PATCH', path, { password });
        await modal(T.done);
      }));
      row.append(button(T.closeSessions, async () => {
        if (!await modal(fill(T.confirmClose, [u.name]), { ask: true, ok: T.confirm })) return;
        await api('PATCH', path, { revoke: true });
        await modal(T.done);
      }));
      row.append(u.disabled
        ? button(T.activate, async () => { await api('PATCH', path, { disabled: false }); await load(); })
        : button(T.deactivate, async () => {
            if (!await modal(fill(T.confirmDeactivate, [u.name]), { ask: true, ok: T.deactivate })) return;
            await api('PATCH', path, { disabled: true });
            await load();
          }, 'danger'));
      row.append(button(T.remove, async () => {
        if (!await modal(fill(T.confirmRemove, [u.name]), { ask: true, ok: T.remove })) return;
        await api('DELETE', path);
        await load();
      }, 'danger'));
    }
    box.append(name, state, select, row);
    return box;
  }
  async function load() {
    me = await api('GET', '/api/remote/me');
    $('me').textContent = me.user + ' · ' + T.roles[me.role];
    if (!me.admin) return;
    const data = await api('GET', '/api/remote/users');
    $('admin').hidden = false;
    $('create').hidden = false;
    $('list').replaceChildren(...data.users.map(renderUser));
    const missing = ['permissions', 'messages', 'terminal', 'spawn'].filter((f) => !data.allow.includes(f));
    $('cap').hidden = !missing.length;
    $('cap').textContent = fill(T.capped, [missing.join(', ')]);
  }
  $('gen').addEventListener('click', () => { $('ap').value = randomPassword(); });
  $('add').addEventListener('submit', (e) => {
    e.preventDefault();
    attempt(async () => {
      const name = $('an').value.trim();
      await api('POST', '/api/remote/users', { name, role: $('ar').value, password: $('ap').value });
      e.target.reset();
      await load();
      await modal(fill(T.created, [name.toLowerCase()]));
    });
  });
  $('own').addEventListener('submit', (e) => {
    e.preventDefault();
    attempt(async () => {
      await api('POST', '/api/remote/password', { current: $('oc').value, next: $('on').value });
      await modal(T.passwordChanged);
      location.assign('/login');
    });
  });
  attempt(load);
</script>
</body>
</html>
`;
}
