// Rotas e página da gestão de contas (porta remota). Só chegam aqui requisições já autenticadas pelo filtro de
// http/remote.ts; quem não é administrador só pode trocar a própria senha e cuidar do próprio 2FA.
//
// 2FA obrigatório sem risco de deixar alguém de fora: conta de Operar ou Administrar sem 2FA NUNCA é barrada no login.
//   - Por padrão, ela usa tudo normalmente e a página insiste: o escritório leva para /usuarios de tempos em tempos.
//   - Com HABBLAUD_REMOTE_TOTP_REQUIRED=1, ela continua entrando, mas só alcança /usuarios até ativar (sessão restrita).
// Saídas para quem perdeu o celular: outro administrador, `npm run remote:users -- 2fa-off <nome>` e, como última, trocar
// o hash da conta do .env (npm run remote:setup), que a recoloca como administradora sem 2FA.
import type { IncomingMessage, ServerResponse } from 'node:http';
import { getLocale, tr } from '../../shared/i18n';
import type { AuditLog } from '../remote/audit';
import { hashPassword, parsePasswordHash, verifyPassword } from '../remote/password';
import { isRole, normalizeName, passwordProblem, roleNeedsTotp, ROLES, UserError, type RemoteRole, type RemoteUser, type UserPatch, type UserStore } from '../remote/users';
import { createTwoFactorRoutes, readJsonBody as readJson, replyError as fail, TOTP_API } from './remote-2fa';
import { observeRemoteAction } from './remote-audit';
import { readCookie, sendHtml, sendJson, type LoginThrottles, type RemoteFeature } from './remote';

export const USERS_PAGE = '/usuarios';
const AUDIT_API = '/api/remote/audit';
/** Marca de que a página já insistiu há pouco: sem ela, o escritório leva para /usuarios. */
const NUDGE_COOKIE = 'habblaud_2fa_aviso';
const NUDGE_S = 4 * 60 * 60;

export interface UserRoutesDeps {
  users: UserStore;
  throttles: LoginThrottles;
  /** HABBLAUD_REMOTE_ALLOW: o teto do que qualquer papel consegue pela porta remota. */
  allow: ReadonlySet<RemoteFeature>;
  /** Conferência e hash da senha (injetáveis nos testes). */
  hash?: (password: string) => Promise<string>;
  verify?: typeof verifyPassword;
  /** Registro de acessos (remote/audit.ts). */
  audit?: AuditLog;
  /** HABBLAUD_REMOTE_TOTP_REQUIRED. */
  requireTotp?: boolean;
}

function publicUser(u: RemoteUser): { name: string; role: RemoteRole; disabled: boolean; createdAt: number; totp: boolean } {
  return { name: u.name, role: u.role, disabled: u.disabled, createdAt: u.createdAt, totp: !!u.totp };
}

export function createUserRoutes(deps: UserRoutesDeps): (req: IncomingMessage, res: ServerResponse, url: URL, who: RemoteUser) => boolean {
  const { users, audit } = deps;
  const hash = deps.hash ?? hashPassword;
  const verify = deps.verify ?? verifyPassword;
  const twoFactor = createTwoFactorRoutes({ users, throttles: deps.throttles, audit, verify });
  const ipOf = (req: IncomingMessage) => req.socket.remoteAddress ?? '';

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
    audit?.write('password.self', { by: who.name, target: who.name, ip: ipOf(req) });
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
    if (body.totp === false) {
      // A própria conta desliga pelo caminho que pede senha e código: uma sessão roubada não tira o 2FA do dono.
      if (name === who.name) throw new UserError(tr('para desativar o seu próprio 2FA, confirme com a senha e o código'), 409);
      patch.totpOff = true;
    }
    if (body.password !== undefined) patch.hash = await newHash(body.password, name);
    const updated = users.update(name, patch);
    const what = [
      patch.role && `role=${patch.role}`,
      patch.disabled !== undefined && `disabled=${patch.disabled}`,
      patch.hash && 'password',
      patch.revoke && 'sessions',
    ].filter(Boolean);
    if (what.length) audit?.write('user.change', { by: who.name, target: name, ip: ipOf(req), what: what.join(' ') });
    if (patch.totpOff) audit?.write('2fa.off', { by: who.name, target: name, ip: ipOf(req) });
    sendJson(res, 200, { user: publicUser(updated) });
  };

  const addUser = async (req: IncomingMessage, res: ServerResponse, who: RemoteUser): Promise<void> => {
    const body = await readJson(req);
    const name = typeof body.name === 'string' ? normalizeName(body.name) : '';
    if (!isRole(body.role)) throw new UserError(tr('papel inválido'));
    if (users.get(name)) throw new UserError(tr('esse usuário já existe'), 409);
    const created = users.add(name, body.role, await newHash(body.password, name));
    audit?.write('user.add', { by: who.name, target: created.name, ip: ipOf(req), what: `role=${created.role}` });
    sendJson(res, 201, { user: publicUser(created) });
  };

  return (req, res, url, who) => {
    const path = url.pathname;
    const method = req.method ?? 'GET';
    const missingTotp = roleNeedsTotp(who.role) && !who.totp;
    const restricted = !!deps.requireTotp && missingTotp;
    if (restricted && path !== USERS_PAGE && path !== '/api/remote/me' && path !== '/api/remote/password' && !path.startsWith(TOTP_API)) {
      req.resume();
      if (path.startsWith('/api/')) sendJson(res, 403, { error: tr('ative o 2FA em /usuarios para continuar') });
      else {
        res.writeHead(302, { Location: USERS_PAGE, 'Cache-Control': 'no-store' });
        res.end();
      }
      return true;
    }
    if (missingTotp && method === 'GET' && path === '/' && !readCookie(req.headers.cookie, NUDGE_COOKIE)) {
      req.resume();
      res.writeHead(302, {
        Location: USERS_PAGE,
        'Cache-Control': 'no-store',
        'Set-Cookie': `${NUDGE_COOKIE}=1; Path=/; HttpOnly; SameSite=Strict; Max-Age=${NUDGE_S}`,
      });
      res.end();
      return true;
    }
    if (twoFactor(req, res, path, who)) return true;
    if (path === AUDIT_API) {
      req.resume();
      if (who.role !== 'admin') sendJson(res, 403, { error: tr('só um administrador pode gerenciar usuários') });
      else if (method !== 'GET') sendJson(res, 405, { error: tr('método não permitido') }, { Allow: 'GET' });
      else sendJson(res, 200, { entries: audit?.read(200) ?? [] });
      return true;
    }
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
          features: restricted ? [] : users.featuresOf(who.role).filter((f) => deps.allow.has(f)),
          totp: !!who.totp,
          totpNeeded: missingTotp,
          restricted,
          recoveryLeft: who.totp?.recovery.length ?? 0,
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
    if (path !== '/api/remote/users' && !path.startsWith('/api/remote/users/')) {
      observeRemoteAction(req, res, path, who.name, audit);
      return false;
    }
    if (who.role !== 'admin') {
      req.resume();
      sendJson(res, 403, { error: tr('só um administrador pode gerenciar usuários') });
      return true;
    }
    if (path === '/api/remote/users') {
      if (method === 'GET') {
        req.resume();
        sendJson(res, 200, { users: users.list().map(publicUser), allow: [...deps.allow], roles: ROLES });
      } else if (method === 'POST') addUser(req, res, who).catch((err) => fail(res, err));
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
        audit?.write('user.remove', { by: who.name, target: name, ip: ipOf(req) });
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
    totpOn: tr('2FA ativo'),
    totpMissing: tr('sem 2FA'),
    totpOnLeft: tr('Ativo. Restam {0} códigos de recuperação. Para gerar outros, desative e ative de novo.'),
    totpOffRisk: tr('Desativado. A sua conta pode executar comandos no servidor: só a senha protege esse acesso.'),
    totpOffPlain: tr('Desativado. Opcional no seu papel, mas protege a conta se a senha vazar.'),
    nag: tr('A sua conta pode executar comandos no servidor e está sem verificação em duas etapas (2FA). Ative agora: leva um minuto.'),
    nagRequired: tr('Este servidor exige 2FA para o seu papel. Até ativar, você só consegue usar esta página.'),
    activateNow: tr('Ativar agora'),
    later: tr('Depois'),
    recovery: tr('2FA ativo. Guarde estes códigos de recuperação: cada um vale uma vez e eles não aparecem de novo.\n\n{0}\n\nAgora entre de novo. Espere o aplicativo mostrar um código NOVO: o que você acabou de usar não vale outra vez.'),
    totpOffDone: tr('2FA desativado. Entre de novo.'),
    totpOffUser: tr('Desativar 2FA'),
    confirmTotpOff: tr('Desativar o 2FA de {0}? As sessões da conta caem na hora.'),
    auditEmpty: tr('Nada registrado ainda.'),
    behaviors: { allow: tr('permitiu'), deny: tr('recusou'), terminal: tr('deixou para o terminal'), answer: tr('respondeu') },
    vias: { password: tr('só senha'), totp: tr('com código'), recovery: tr('com código de recuperação') },
    reasons: { credentials: tr('usuário ou senha'), code: tr('senha certa, código errado') },
    leftCodes: tr('restam {0} códigos'),
    events: {
      'login.ok': tr('Entrou'),
      'login.fail': tr('Falha ao entrar'),
      logout: tr('Saiu'),
      'account.seed': tr('Conta do .env recolocada como administradora'),
      'user.add': tr('Conta criada'),
      'user.change': tr('Conta alterada'),
      'user.remove': tr('Conta removida'),
      'password.self': tr('Trocou a própria senha'),
      '2fa.setup': tr('Começou a ativar o 2FA'),
      '2fa.on': tr('2FA ativado'),
      '2fa.off': tr('2FA desativado'),
      '2fa.fail': tr('Falha ao mexer no 2FA'),
      'permission.decision': tr('Respondeu permissão'),
      'message.send': tr('Mandou mensagem'),
    },
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
  body { margin: 0; background: #14161f; color: #e8e6df; font: 15px/1.45 ui-monospace, SFMono-Regular, Menlo, monospace; padding: 16px; }
  main { max-width: 860px; margin: 0 auto; }
  h1 { margin: 0; font-size: 22px; color: #f4c95d; }
  h2 { margin: 0 0 12px; font-size: 16px; color: #f4c95d; }
  header { display: flex; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 16px; }
  a { color: #f4c95d; }
  section { background: #1e2130; border: 2px solid #3a3f58; border-radius: 10px; padding: 16px; margin-bottom: 16px; }
  label { display: block; font-size: 13px; color: #9aa0b8; margin: 10px 0 4px; }
  input, select { width: 100%; padding: 10px; font: inherit; color: inherit; background: #14161f; border: 2px solid #3a3f58; border-radius: 6px; }
  input:focus, select:focus { outline: none; border-color: #f4c95d; }
  button { padding: 9px 12px; font: inherit; color: #e8e6df; background: #2b2f44; border: 2px solid #3a3f58; border-radius: 6px; cursor: pointer; }
  button:disabled { opacity: .5; cursor: not-allowed; }
  button.main { color: #14161f; font-weight: 700; background: #f4c95d; border-color: #f4c95d; }
  button.danger { color: #ff8a80; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 0 12px; }
  .row { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 12px; }
  .user { border-top: 1px solid #3a3f58; padding: 12px 0; }
  .user:first-child { border-top: 0; padding-top: 0; }
  .name { font-weight: 700; overflow-wrap: anywhere; }
  .muted { color: #9aa0b8; font-size: 13px; }
  .off { color: #ff8a80; }
  #tfaSecret { display: block; padding: 10px; background: #14161f; border: 2px solid #3a3f58; border-radius: 6px; letter-spacing: 1px; overflow-wrap: anywhere; }
  #tfaUri { overflow-wrap: anywhere; font-size: 13px; }
  .log { border-top: 1px solid #3a3f58; padding: 8px 0; overflow-wrap: anywhere; }
  .log:first-child { border-top: 0; }
  #dlgText { white-space: pre-line; }
  dialog { width: min(92vw, 440px); color: inherit; background: #1e2130; border: 2px solid #f4c95d; border-radius: 10px; padding: 18px; overflow-wrap: anywhere; }
  dialog::backdrop { background: rgba(0, 0, 0, .65); }
</style>
</head>
<body>
<main>
  <header><h1>${tr('Usuários')}</h1><a id="back" href="/">${tr('Voltar ao escritório')}</a></header>
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
  <section id="tfa">
    <h2>${tr('Verificação em duas etapas (2FA)')}</h2>
    <p id="tfaState" class="muted"></p>
    <form id="tfaStart" hidden>
      <label for="tfaPass">${tr('Senha atual')}</label><input id="tfaPass" type="password" autocomplete="current-password" required>
      <div class="row"><button class="main" type="submit">${tr('Ativar 2FA')}</button></div>
    </form>
    <form id="tfaConfirm" hidden>
      <p class="muted">${tr('No Google Authenticator ou parecido, adicione uma conta com esta chave (ou toque no endereço, se estiver no celular) e digite o código que aparecer.')}</p>
      <label>${tr('Chave')}</label><code id="tfaSecret"></code>
      <label>${tr('Endereço para o aplicativo')}</label><a id="tfaUri"></a>
      <label for="tfaCode">${tr('Código de 6 dígitos')}</label><input id="tfaCode" inputmode="numeric" autocomplete="one-time-code" maxlength="6" required>
      <div class="row"><button class="main" type="submit">${tr('Confirmar e ativar')}</button></div>
    </form>
    <form id="tfaOff" hidden>
      <div class="grid">
        <div><label for="tfaOffPass">${tr('Senha atual')}</label><input id="tfaOffPass" type="password" autocomplete="current-password" required></div>
        <div><label for="tfaOffCode">${tr('Código 2FA ou de recuperação')}</label><input id="tfaOffCode" autocomplete="one-time-code" spellcheck="false" maxlength="32" required></div>
      </div>
      <div class="row"><button class="danger" type="submit">${tr('Desativar o meu 2FA')}</button></div>
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
  <section id="auditBox" hidden>
    <h2>${tr('Registro de acessos')}</h2>
    <div id="auditList"></div>
    <div class="row"><button type="button" id="auditReload">${tr('Atualizar')}</button></div>
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
    $('dlgNo').textContent = o.no || T.cancel;
    $('dlgNo').hidden = !o.ask;
    // Texto que só aparece uma vez: o Esc não fecha sem querer.
    const hold = (e) => e.preventDefault();
    if (o.hold) dlg.addEventListener('cancel', hold);
    return new Promise((resolve) => {
      dlg.addEventListener('close', () => {
        dlg.removeEventListener('cancel', hold);
        resolve(dlg.returnValue === 'ok' ? (o.input ? $('dlgInput').value : true) : false);
      }, { once: true });
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
    state.textContent = (u.disabled ? T.disabled : T.active) + ' · ' + (u.totp ? T.totpOn : T.totpMissing);
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
      if (u.totp) row.append(button(T.totpOffUser, async () => {
        if (!await modal(fill(T.confirmTotpOff, [u.name]), { ask: true, ok: T.totpOffUser })) return;
        await api('PATCH', path, { totp: false });
        await load();
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
    renderTotp();
    if (!me.admin || me.restricted) return;
    const data = await api('GET', '/api/remote/users');
    $('admin').hidden = false;
    $('create').hidden = false;
    $('list').replaceChildren(...data.users.map(renderUser));
    const missing = ['permissions', 'messages', 'terminal', 'spawn'].filter((f) => !data.allow.includes(f));
    $('cap').hidden = !missing.length;
    $('cap').textContent = fill(T.capped, [missing.join(', ')]);
    await loadAudit();
  }
  function renderTotp() {
    $('back').hidden = me.restricted;
    $('tfaState').textContent = me.totp ? fill(T.totpOnLeft, [me.recoveryLeft]) : me.totpNeeded ? T.totpOffRisk : T.totpOffPlain;
    $('tfaState').className = !me.totp && me.totpNeeded ? 'off' : 'muted';
    $('tfaOff').hidden = !me.totp;
    // Ativação em andamento: recarregar a lista não pode esconder a chave que a pessoa está digitando.
    if (me.totp || $('tfaConfirm').hidden) $('tfaStart').hidden = me.totp;
  }
  function auditLine(e) {
    const box = document.createElement('div');
    box.className = 'log';
    const when = document.createElement('div');
    when.className = 'muted';
    const date = new Date(e.t);
    when.textContent = (isNaN(date.getTime()) ? e.t : date.toLocaleString()) + (e.ip ? ' · ' + e.ip : '');
    const text = document.createElement('div');
    const parts = [T.events[e.ev] || e.ev];
    const who = e.by || e.user;
    if (who) parts.push(who);
    if (e.target && e.target !== who) parts.push('→ ' + e.target);
    if (e.via) parts.push(T.vias[e.via] || e.via);
    if (e.reason) parts.push(T.reasons[e.reason] || e.reason);
    if (e.behavior) parts.push(T.behaviors[e.behavior] || e.behavior);
    if (e.what) parts.push(e.what);
    if (e.id) parts.push(e.id);
    if (e.agent) parts.push(e.agent);
    if (e.left !== undefined) parts.push(fill(T.leftCodes, [e.left]));
    if (e.status !== undefined && e.status >= 300) parts.push('HTTP ' + e.status);
    text.textContent = parts.join(' · ');
    box.append(text, when);
    return box;
  }
  async function loadAudit() {
    const data = await api('GET', '/api/remote/audit');
    $('auditBox').hidden = false;
    if (data.entries.length) $('auditList').replaceChildren(...data.entries.map(auditLine));
    else $('auditList').textContent = T.auditEmpty;
  }
  async function insist() {
    if (me.totp || !me.totpNeeded) return;
    const go = await modal(me.restricted ? T.nagRequired : T.nag, { ask: !me.restricted, ok: T.activateNow, no: T.later });
    if (go) $('tfaPass').focus();
  }
  $('tfaStart').addEventListener('submit', (e) => {
    e.preventDefault();
    attempt(async () => {
      const r = await api('POST', '/api/remote/2fa/setup', { password: $('tfaPass').value });
      $('tfaPass').value = '';
      $('tfaSecret').textContent = r.secret.match(/.{1,4}/g).join(' ');
      $('tfaUri').href = r.uri;
      $('tfaUri').textContent = r.uri;
      $('tfaStart').hidden = true;
      $('tfaConfirm').hidden = false;
      $('tfaCode').focus();
    });
  });
  $('tfaConfirm').addEventListener('submit', (e) => {
    e.preventDefault();
    attempt(async () => {
      const r = await api('POST', '/api/remote/2fa/confirm', { code: $('tfaCode').value });
      $('tfaCode').value = '';
      await modal(fill(T.recovery, [r.recovery.join('\\n')]), { hold: true });
      location.assign('/login');
    });
  });
  $('tfaOff').addEventListener('submit', (e) => {
    e.preventDefault();
    attempt(async () => {
      await api('POST', '/api/remote/2fa/disable', { password: $('tfaOffPass').value, code: $('tfaOffCode').value });
      await modal(T.totpOffDone);
      location.assign('/login');
    });
  });
  $('auditReload').addEventListener('click', () => attempt(loadAudit));
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
  attempt(async () => { await load(); await insist(); });
</script>
</body>
</html>
`;
}
