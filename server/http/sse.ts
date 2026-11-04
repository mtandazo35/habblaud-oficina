// Transmissão em tempo real (Server-Sent Events) em GET /api/stream.
// Eventos nomeados: snapshot | feed | notice (o `data` é o JSON do protocolo em shared/types.ts).
// Snapshots saem com throttle (~200 ms); feed e avisos vão em lote logo depois do snapshot.
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { FeedItem, Notice, OfficeSnapshot } from '../../shared/types';
import type { Office } from '../model/office';
import { isLoopbackHost } from './guard';

/** Cliente lento demais (buffer acumulado acima disto) é desconectado; o EventSource reconecta. */
const MAX_BUFFERED = 8 * 1024 * 1024;

/**
 * O que um cliente pode ver, quando não pode ver tudo (sessões privadas, http/privacy.ts). Quem conecta sem visão recebe
 * o frame de sempre; cada visão serializa uma vez por rodada, não importa quantos clientes tenha.
 */
export interface HubView {
  /** Frame do snapshot para quem acabou de conectar. */
  attachFrame(snap: OfficeSnapshot): string;
  /** Frame para quem já está conectado; null = nada mudou do ponto de vista desta visão. */
  snapshotFrame(snap: OfficeSnapshot): string | null;
  feed(items: readonly FeedItem[]): FeedItem[];
  notice(notice: Notice, snap: OfficeSnapshot): boolean;
}

export class Hub {
  private clients = new Set<ServerResponse>();
  private views = new WeakMap<ServerResponse, HubView>();
  /** Clientes que abriram a página por um Host local (os únicos que podem responder pedidos de permissão). */
  private local = new WeakSet<ServerResponse>();
  private timer: ReturnType<typeof setTimeout> | null = null;
  private pinger: ReturnType<typeof setInterval> | null = null;
  private lastFlush = 0;
  private unsubscribe: (() => void) | null = null;
  private snapshotCbs = new Set<(snap: OfficeSnapshot) => void>();
  private readonly throttleMs: number;
  private readonly pingMs: number;
  /** Quem pode responder pelo escritório; padrão: Host local. A porta remota (http/remote.ts) troca a regra. */
  private readonly canAnswer: (req: IncomingMessage) => boolean;

  constructor(
    private readonly office: Office,
    opts: { throttleMs?: number; pingMs?: number; canAnswer?: (req: IncomingMessage) => boolean } = {},
  ) {
    this.throttleMs = opts.throttleMs ?? 200;
    this.pingMs = opts.pingMs ?? 15_000;
    this.canAnswer = opts.canAnswer ?? ((req) => isLoopbackHost(req.headers.host));
  }

  start(): void {
    this.unsubscribe = this.office.onChange(() => this.schedule());
    this.pinger = setInterval(() => this.writeEach(() => ': ping\n\n'), this.pingMs);
    this.pinger.unref?.();
  }

  stop(): void {
    this.unsubscribe?.();
    this.unsubscribe = null;
    if (this.timer) clearTimeout(this.timer);
    if (this.pinger) clearInterval(this.pinger);
    this.timer = null;
    this.pinger = null;
    for (const c of this.clients) c.end();
    this.clients.clear();
  }

  get size(): number {
    return this.clients.size;
  }

  /** Avisado a cada snapshot novo transmitido (ex.: o gravador da linha do tempo). */
  onSnapshot(cb: (snap: OfficeSnapshot) => void): () => void {
    this.snapshotCbs.add(cb);
    return () => void this.snapshotCbs.delete(cb);
  }

  /** Páginas conectadas por um Host local (localhost/127.x): quem pode responder pelo escritório. */
  get localSize(): number {
    let n = 0;
    for (const c of this.clients) if (this.local.has(c) && !c.destroyed && !c.writableEnded) n++;
    return n;
  }

  /** Conecta um cliente: snapshot completo + últimos 50 itens do feed, depois o fluxo ao vivo. */
  attach(req: IncomingMessage, res: ServerResponse, view?: HubView): void {
    req.socket.setTimeout(0);
    req.socket.setNoDelay(true);
    res.writeHead(200, {
      'Content-Type': 'text/event-stream; charset=utf-8',
      'Cache-Control': 'no-cache, no-transform',
      Connection: 'keep-alive',
      'X-Accel-Buffering': 'no',
    });
    const snapshot = this.current();
    res.write('retry: 2000\n\n');
    res.write(view ? view.attachFrame(snapshot) : frame('snapshot', snapshot));
    // Com visão, os 50 mais recentes DELA (os 50 de todos poderiam ser só de sessões que ela não vê).
    res.write(frame('feed', view ? view.feed(this.office.recentFeed(Infinity)).slice(-50) : this.office.recentFeed(50)));
    this.clients.add(res);
    if (view) this.views.set(res, view);
    if (this.canAnswer(req)) this.local.add(res);
    const drop = () => this.clients.delete(res);
    req.on('close', drop);
    res.on('close', drop);
    res.on('error', drop);
  }

  /** Fecha a revisão agora e transmite o que houver. Devolve o snapshot atual. */
  flush(): OfficeSnapshot {
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    this.lastFlush = Date.now();
    const r = this.office.commit();
    if (r.changed) {
      this.writeEach((view) => (view ? view.snapshotFrame(r.snapshot) : frame('snapshot', r.snapshot)));
      for (const cb of this.snapshotCbs) {
        try {
          cb(r.snapshot);
        } catch {
          // quem escuta não atrapalha a transmissão
        }
      }
    }
    if (r.feed.length) {
      this.writeEach((view) => {
        const items = view ? view.feed(r.feed) : r.feed;
        return items.length ? frame('feed', items) : null;
      });
    }
    for (const n of r.notices) this.writeEach((view) => (!view || view.notice(n, r.snapshot) ? frame('notice', n) : null));
    return r.snapshot;
  }

  /** Snapshot atual (depois de transmitir o que estiver pendente), com `serverTime` de agora. */
  current(): OfficeSnapshot {
    return { ...this.flush(), serverTime: Date.now() };
  }

  private schedule(): void {
    if (this.timer) return;
    const wait = Math.max(0, this.lastFlush + this.throttleMs - Date.now());
    this.timer = setTimeout(() => {
      this.timer = null;
      this.flush();
    }, wait);
    this.timer.unref?.();
  }

  /** Manda a cada cliente o que `chunkOf` montar para a visão dele (uma vez por visão; null = nada para ela). */
  private writeEach(chunkOf: (view: HubView | undefined) => string | null): void {
    const chunks = new Map<HubView | undefined, string | null>();
    for (const c of this.clients) {
      if (c.destroyed || c.writableEnded) {
        this.clients.delete(c);
        continue;
      }
      if (c.writableLength > MAX_BUFFERED) {
        this.clients.delete(c);
        c.destroy();
        continue;
      }
      const view = this.views.get(c);
      let chunk = chunks.get(view);
      if (chunk === undefined) {
        chunk = chunkOf(view);
        chunks.set(view, chunk);
      }
      if (chunk !== null) c.write(chunk);
    }
  }
}

export function frame(event: string, data: unknown): string {
  return `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
}
