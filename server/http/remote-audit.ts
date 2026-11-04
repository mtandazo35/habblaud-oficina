// O que passa pela porta remota e entra no registro de acessos sem mexer nas rotas de permissões e mensagens: observa a
// requisição ao lado de quem a atende e registra quando a resposta sai.
//
// Do corpo só sai o que é dado de controle: a decisão (uma de BEHAVIORS) e o agente. O texto da mensagem, o motivo da
// recusa e as respostas às perguntas nunca são copiados para o registro.
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { AuditLog } from '../remote/audit';

const DECISION = /^\/api\/permissions\/([^/]+)\/decision$/;
const BEHAVIORS = new Set(['allow', 'deny', 'terminal', 'answer']);
/** O mesmo limite de corpo da API (http/app.ts). */
const MAX_PEEK = 256 * 1024;

function controlFields(chunks: Buffer[]): Record<string, unknown> {
  try {
    const data: unknown = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    return data && typeof data === 'object' ? (data as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

/**
 * Chamado de forma síncrona antes de a requisição seguir para a API: quem atende lê o corpo no mesmo ciclo, e os dois
 * ouvintes de 'data' recebem os mesmos pedaços.
 */
export function observeRemoteAction(req: IncomingMessage, res: ServerResponse, path: string, user: string, audit: AuditLog | undefined): void {
  if (!audit || (req.method ?? 'GET') !== 'POST') return;
  const decision = DECISION.exec(path);
  if (!decision && path !== '/api/messages') return;
  const chunks: Buffer[] = [];
  let size = 0;
  req.on('data', (c: Buffer) => {
    size += c.length;
    if (size <= MAX_PEEK) chunks.push(c);
  });
  res.once('finish', () => {
    const body = size <= MAX_PEEK ? controlFields(chunks) : {};
    const ip = req.socket.remoteAddress ?? '';
    if (decision) {
      const behavior = typeof body.behavior === 'string' && BEHAVIORS.has(body.behavior) ? body.behavior : undefined;
      audit.write('permission.decision', { user, ip, id: decision[1], behavior, status: res.statusCode });
    } else {
      audit.write('message.send', { user, ip, agent: typeof body.agentId === 'string' ? body.agentId : undefined, status: res.statusCode });
    }
  });
}
