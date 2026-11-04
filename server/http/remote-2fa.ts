// Rotas do 2FA de cada pessoa (porta remota, já autenticada). Ativar exige a senha, porque um cookie roubado não pode
// servir para prender o dono fora da própria conta; desativar exige senha e código. Toda conferência passa pelo mesmo
// freio por endereço do login. O segredo só sai na resposta de /setup, antes de ativar; depois disso, nunca mais.
import type { IncomingMessage, ServerResponse } from 'node:http';
import { tr } from '../../shared/i18n';
import type { AuditLog } from '../remote/audit';
import { parsePasswordHash, verifyPassword } from '../remote/password';
import { UserError, type RemoteUser, type UserStore } from '../remote/users';
import { readBody, sendJson, type LoginThrottles } from './remote';

export const TOTP_API = '/api/remote/2fa/';

export async function readJsonBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  const data: unknown = JSON.parse(await readBody(req));
  if (!data || typeof data !== 'object' || Array.isArray(data)) throw new UserError(tr('requisição inválida'));
  return data as Record<string, unknown>;
}

export function replyError(res: ServerResponse, err: unknown): void {
  if (res.headersSent) return;
  if (err instanceof UserError) sendJson(res, err.status, { error: err.message });
  else sendJson(res, 400, { error: tr('requisição inválida') });
}

export interface TwoFactorDeps {
  users: UserStore;
  throttles: LoginThrottles;
  audit?: AuditLog;
  verify?: typeof verifyPassword;
}

export function createTwoFactorRoutes(deps: TwoFactorDeps): (req: IncomingMessage, res: ServerResponse, path: string, who: RemoteUser) => boolean {
  const { users, throttles, audit } = deps;
  const verify = deps.verify ?? verifyPassword;
  const ipOf = (req: IncomingMessage) => req.socket.remoteAddress ?? '';

  /** `attempt` responde e diz se acertou; errar conta no freio do endereço. */
  const limited = async (req: IncomingMessage, res: ServerResponse, attempt: () => Promise<boolean> | boolean): Promise<void> => {
    const limit = throttles.scoped(ipOf(req));
    if (!limit.begin()) {
      sendJson(res, 429, { error: tr('Muitas tentativas. Tente de novo em {0} s.', [Math.max(1, limit.retryAfter())]) });
      return;
    }
    let ok = false;
    try {
      ok = await attempt();
    } finally {
      limit.end(ok);
    }
  };
  const passwordOk = async (who: RemoteUser, password: unknown): Promise<boolean> => {
    const stored = parsePasswordHash(users.get(who.name)?.hash);
    return !!stored && typeof password === 'string' && (await verify(password, stored));
  };
  const refused = (req: IncomingMessage, who: RemoteUser, what: string) => audit?.write('2fa.fail', { user: who.name, ip: ipOf(req), what });

  const setup = async (req: IncomingMessage, res: ServerResponse, who: RemoteUser): Promise<void> => {
    const body = await readJsonBody(req);
    await limited(req, res, async () => {
      if (!(await passwordOk(who, body.password))) {
        refused(req, who, 'setup');
        sendJson(res, 403, { error: tr('A senha atual não confere.') });
        return false;
      }
      const started = users.startTotp(who.name);
      audit?.write('2fa.setup', { user: who.name, ip: ipOf(req) });
      sendJson(res, 200, started);
      return true;
    });
  };

  const confirm = async (req: IncomingMessage, res: ServerResponse, who: RemoteUser): Promise<void> => {
    const body = await readJsonBody(req);
    await limited(req, res, () => {
      let recovery: string[];
      try {
        recovery = users.confirmTotp(who.name, typeof body.code === 'string' ? body.code : '');
      } catch (err) {
        refused(req, who, 'confirm');
        throw err;
      }
      audit?.write('2fa.on', { by: who.name, target: who.name, ip: ipOf(req) });
      sendJson(res, 200, { recovery });
      return true;
    });
  };

  const disable = async (req: IncomingMessage, res: ServerResponse, who: RemoteUser): Promise<void> => {
    const body = await readJsonBody(req);
    await limited(req, res, async () => {
      // A senha vem primeiro: uma senha errada não gasta o código.
      const good = (await passwordOk(who, body.password)) && !!users.checkSecondFactor(who.name, typeof body.code === 'string' ? body.code : '');
      if (!good) {
        refused(req, who, 'disable');
        sendJson(res, 403, { error: tr('Senha ou código incorretos.') });
        return false;
      }
      users.update(who.name, { totpOff: true });
      audit?.write('2fa.off', { by: who.name, target: who.name, ip: ipOf(req) });
      sendJson(res, 200, { ok: true });
      return true;
    });
  };

  const routes = new Map<string, (req: IncomingMessage, res: ServerResponse, who: RemoteUser) => Promise<void>>([
    [`${TOTP_API}setup`, setup],
    [`${TOTP_API}confirm`, confirm],
    [`${TOTP_API}disable`, disable],
  ]);

  return (req, res, path, who) => {
    if (!path.startsWith(TOTP_API)) return false;
    const route = routes.get(path);
    if (!route) {
      req.resume();
      sendJson(res, 404, { error: tr('rota desconhecida') });
    } else if (req.method !== 'POST') {
      req.resume();
      sendJson(res, 405, { error: tr('método não permitido') }, { Allow: 'POST' });
    } else route(req, res, who).catch((err) => replyError(res, err));
    return true;
  };
}
