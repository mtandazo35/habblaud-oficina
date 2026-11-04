// Sessões privadas: uma conta de agentes que só um usuário de login vê pela porta remota.
//
//   HABBLAUD_PRIVATE_DIRS=<pasta>=<usuário>[,<pasta>=<usuário>...]
//
// Desligado por padrão, e a porta local nunca passa por aqui. Cada usuário remoto cai numa VISÃO, que é o conjunto das
// pastas privadas que ele não pode ver. Quem vê tudo (dono de todas as pastas) usa a API de sempre.
//
// Como nada fica sem filtrar:
// - A API da visão é createApiHandler com dependências montadas uma a uma (scopedDeps), sem copiar `base`: uma rota nova
//   que dependa de algo não listado ali nasce desligada na porta remota, em vez de nascer vazando.
// - Só passa o que é sabidamente permitido: conta desconhecida não aparece, e pedido sem dono (usuário não identificado)
//   usa a visão que esconde todas as pastas privadas. Entrada sem usuário válido em HABBLAUD_PRIVATE_DIRS esconde a pasta
//   de todo mundo na porta remota.
// - "Meu dia" e timelapse têm gravador próprio por visão (<dataDir>/stats-views e timeline-views): um arquivo da visão
//   nunca recebeu o que ela esconde, e os números das salas saem certos mesmo com sessões privadas na mesma sala (os
//   arquivos gerais somam tudo por sala, sem separar por conta).
// - Salas e slots são remontados para a visão, e `rev` só anda quando algo visível muda: sem buraco no prédio, nome
//   desambiguado por causa de uma sala escondida nem frame que denuncie atividade alheia.
//
// Custo: uma visão a mais por dono distinto. A projeção é calculada uma vez por revisão do escritório e serializada uma
// vez por visão, não por cliente; com a variável ausente, nada disso existe.
import { createHash } from 'node:crypto';
import { realpathSync } from 'node:fs';
import { join, resolve } from 'node:path';
import type { FeedItem, Notice, OfficeSnapshot, RoomInfo } from '../../shared/types';
import { isDemoId } from '../../shared/timeline';
import { tr } from '../../shared/i18n';
import { expandHome } from '../accounts/detect';
import type { AccountEntry, AccountsService } from '../accounts/service';
import { DayStatsService } from '../history/daystats';
import { TimelineRecorder } from '../history/timeline';
import { log } from '../log';
import { createMessageRoutes } from '../messages/http';
import { parseSend, type MessageRegistry } from '../messages/registry';
import { SLOT_COOLDOWN_MS, type Office } from '../model/office';
import { roomDisplayNames, SlotAllocator } from '../model/rooms';
import { createPermissionRoutes } from '../permissions/http';
import type { PermissionRegistry } from '../permissions/registry';
import { normalizeName } from '../remote/users';
import type { SessionLookup } from '../sources/source';
import { createApiHandler, HttpError, sendJson, type ApiDeps } from './app';
import type { Hub, HubView } from './sse';
import { createTimelineHandler } from './timeline';

export interface PrivateDir {
  /** Caminho absoluto da pasta da conta. */
  dir: string;
  /** Usuário de login dono; ausente = ninguém a vê pela porta remota. */
  owner?: string;
}

/** Mesma regra de nome de remote/users.ts. */
const OWNER_RE = /^[a-z0-9][a-z0-9._-]{0,31}$/;
/** Mensagens lembradas por visão (o registro as esquece em minutos). */
const MAX_SENT = 1_000;

/** Lê HABBLAUD_PRIVATE_DIRS. Na dúvida, esconde: pasta sem usuário válido ou com dois donos fica sem dono. */
export function parsePrivateDirs(raw: string | undefined, home: string): { dirs: PrivateDir[]; warnings: string[] } {
  const byDir = new Map<string, PrivateDir>();
  const warnings: string[] = [];
  for (const item of (raw ?? '').split(',').map((s) => s.trim()).filter(Boolean)) {
    const eq = item.lastIndexOf('=');
    const path = eq < 0 ? item : item.slice(0, eq).trim();
    const name = eq < 0 ? '' : normalizeName(item.slice(eq + 1));
    if (!path) {
      warnings.push(tr('HABBLAUD_PRIVATE_DIRS: entrada sem pasta ignorada: "{0}".', [item]));
      continue;
    }
    const dir = expandHome(path, home);
    const valid = OWNER_RE.test(name);
    if (!valid) warnings.push(tr('HABBLAUD_PRIVATE_DIRS: "{0}" não tem um usuário válido (use <pasta>=<usuário>): ninguém vê essa pasta pela porta remota.', [item]));
    const seen = byDir.get(dir);
    if (seen && seen.owner !== (valid ? name : undefined)) {
      warnings.push(tr('HABBLAUD_PRIVATE_DIRS: a pasta {0} aparece com dois donos: ninguém a vê pela porta remota.', [dir]));
      delete seen.owner;
    } else if (!seen) {
      byDir.set(dir, valid ? { dir, owner: name } : { dir });
    }
  }
  return { dirs: [...byDir.values()], warnings };
}

/** Caminho real (a pasta da conta pode ser um link); fora do disco deste processo (host no Docker), o próprio caminho. */
function canonical(path: string): string {
  try {
    return realpathSync(path);
  } catch {
    return resolve(path);
  }
}

type EntryRef = Pick<AccountEntry, 'id' | 'dir'> & { detected: Pick<AccountEntry['detected'], 'configDir'> };

/** A pasta privada é a desta conta? (no Docker a conta tem dois caminhos: o montado e o do host) */
function sameAccount(entry: EntryRef, dir: PrivateDir): boolean {
  const target = canonical(dir.dir);
  return canonical(entry.dir) === target || canonical(entry.detected.configDir) === target;
}

interface Projection {
  /** Revisão do escritório de onde veio. */
  source: number;
  /** JSON de tudo menos `rev` e `serverTime`: é ele que diz se algo visível mudou. */
  body: string;
  value: Omit<OfficeSnapshot, 'rev' | 'serverTime'>;
  agents: ReadonlySet<string>;
  rooms: ReadonlyMap<string, string>;
}

/** O que os usuários que escondem o mesmo conjunto de pastas enxergam. */
export class PrivacyView implements HubView {
  private readonly slots = new SlotAllocator(SLOT_COOLDOWN_MS);
  private projection?: Projection;
  private visibility?: { signature: string; known: ReadonlyMap<string, boolean> };
  private rev = 0;
  private sentRev = -1;

  constructor(
    private readonly opts: {
      hidden: readonly PrivateDir[];
      entries: () => readonly EntryRef[];
      roomAlias?: (path: string) => string | undefined;
    },
  ) {}

  /**
   * Filtro de contas: só passa conta conhecida e não escondida, ou do demo (que não é sessão de ninguém). Calculado uma
   * vez por lista de contas (a do Codex chega depois do boot), porque roda a cada feed e aviso e olha o disco.
   */
  accountFilter(): (account: string) => boolean {
    const entries = this.opts.entries();
    const signature = entries.map((e) => `${e.id}\0${e.dir}\0${e.detected.configDir}`).join('\n');
    if (this.visibility?.signature !== signature) {
      const known = new Map<string, boolean>();
      for (const e of entries) known.set(e.id, !this.opts.hidden.some((d) => sameAccount(e, d)));
      this.visibility = { signature, known };
    }
    const { known } = this.visibility;
    return (account) => known.get(account) ?? isDemoId(account);
  }

  /** O caminho fica dentro de uma pasta escondida? */
  hidesPath(path: string): boolean {
    const abs = resolve(path);
    const roots = this.opts.hidden.map((d) => d.dir);
    for (const e of this.opts.entries()) if (this.opts.hidden.some((d) => sameAccount(e, d))) roots.push(e.dir, e.detected.configDir);
    return roots.some((root) => {
      const r = resolve(root);
      return abs === r || abs.startsWith(`${r}/`) || canonical(abs) === canonical(r) || canonical(abs).startsWith(`${canonical(r)}/`);
    });
  }

  private project(snap: OfficeSnapshot): Projection {
    if (this.projection?.source === snap.rev) return this.projection;
    const visible = this.accountFilter();
    const agents = snap.agents.filter((a) => visible(a.account));
    const agentIds = new Set(agents.map((a) => a.id));
    const occupied = new Set(agents.map((a) => a.roomId));
    const kept = snap.rooms.filter((r) => occupied.has(r.id) || isDemoId(r.id));
    const names = roomDisplayNames(new Map(kept.map((r) => [r.id, r.path])));
    this.slots.sync(kept.map((r) => r.id), snap.serverTime);
    const rooms = kept
      .map((r): RoomInfo => {
        const { effect, ...rest } = r;
        const room: RoomInfo = { ...rest, name: this.opts.roomAlias?.(r.path) ?? names.get(r.id) ?? r.name, slot: this.slots.slotOf(r.id) ?? 0 };
        // A festa ou o alarme vêm de um agente: só com ele visível (no demo, as salas são todas fictícias).
        if (effect && (isDemoId(r.id) || (effect.agentId && agentIds.has(effect.agentId)))) room.effect = effect;
        return room;
      })
      .sort((a, b) => a.slot - b.slot);
    const { world, ...meta } = snap.meta;
    const value: Projection['value'] = {
      rooms,
      agents,
      accounts: snap.accounts.filter((a) => visible(a.id)),
      ...(snap.ptys ? { ptys: snap.ptys.filter((p) => visible(p.account)) } : {}),
      meta: {
        ...meta,
        sources: meta.sources.filter((s) => visible(s.label)),
      },
    };
    if (world) {
      // `building` conta os agentes do prédio inteiro.
      const { building: _building, ...rest } = world;
      value.meta.world = rest;
    }
    const body = JSON.stringify(value);
    if (body !== this.projection?.body) this.rev++;
    this.projection = { source: snap.rev, body, value, agents: agentIds, rooms: new Map(rooms.map((r) => [r.id, r.name])) };
    return this.projection;
  }

  /** O snapshot desta visão. */
  snapshot(snap: OfficeSnapshot): OfficeSnapshot {
    const p = this.project(snap);
    return { ...p.value, rev: this.rev, serverTime: snap.serverTime };
  }

  attachFrame(snap: OfficeSnapshot): string {
    const p = this.project(snap);
    this.sentRev = this.rev;
    // Reaproveita o JSON da comparação: uma serialização por visão a cada revisão.
    return `event: snapshot\ndata: {"rev":${this.rev},"serverTime":${snap.serverTime},${p.body.slice(1)}\n\n`;
  }

  snapshotFrame(snap: OfficeSnapshot): string | null {
    this.project(snap);
    if (this.rev === this.sentRev) return null;
    return this.attachFrame(snap);
  }

  feed(items: readonly FeedItem[]): FeedItem[] {
    const visible = this.accountFilter();
    const rooms = this.projection?.rooms;
    return items
      .filter((i) => i.account !== undefined && visible(i.account))
      .map((i) => {
        const roomName = rooms?.get(i.roomId);
        return roomName && roomName !== i.roomName ? { ...i, roomName } : i;
      });
  }

  /** Aviso de agente: só com ele visível. De sala: só com a sala visível. Sem nenhum dos dois: não sai. */
  notice(n: Notice, snap: OfficeSnapshot): boolean {
    const p = this.project(snap);
    if (n.agentId) return p.agents.has(n.agentId);
    return !!n.roomId && p.rooms.has(n.roomId);
  }
}

export interface PrivacyOptions {
  raw: string | undefined;
  home: string;
  dataDir: string;
  /** Gravação da linha do tempo ligada. */
  timeline: boolean;
  /** As dependências da API da porta local (tudo que a visão usa de lá é repassado um a um, em scopedDeps). */
  base: ApiDeps;
  /** A API sem filtro: a de quem é dono de todas as pastas privadas. */
  api: ReturnType<typeof createApiHandler>;
  office: Pick<Office, 'detail' | 'has'>;
  hub: Pick<Hub, 'current' | 'attach' | 'onSnapshot'>;
  accounts: Pick<AccountsService, 'allEntries' | 'entriesOf' | 'usageView'>;
  roomAlias?: (path: string) => string | undefined;
  permissions?: Pick<PermissionRegistry, 'agentOf' | 'detail' | 'decide'>;
  messages?: Pick<MessageRegistry, 'send' | 'get'>;
  deliveriesOf: (lookup: SessionLookup) => NonNullable<ApiDeps['deliveries']>;
  spawnFoldersOf: (view: Pick<Hub, 'current'>, lookup: SessionLookup | undefined) => NonNullable<ApiDeps['spawnFolders']>;
}

/** Uma visão com tudo que grava por conta própria. */
interface ViewRuntime {
  key: string;
  view: PrivacyView;
  stats: DayStatsService;
  timeline?: TimelineRecorder;
  timelineDir: string;
  api?: ReturnType<typeof createApiHandler>;
  stopFeed?: () => void;
}

export interface Privacy {
  /** A API que atende este usuário da porta remota; sem usuário identificado, a que esconde todas as pastas. */
  apiFor(user: string | undefined): ReturnType<typeof createApiHandler>;
  start(): void;
  stop(): void;
}

/** undefined = HABBLAUD_PRIVATE_DIRS vazia: nada muda em lugar nenhum. */
export function createPrivacy(opts: PrivacyOptions): Privacy | undefined {
  const { dirs, warnings } = parsePrivateDirs(opts.raw, opts.home);
  if (!dirs.length) {
    for (const w of warnings) log.warn(`   ${w}`);
    return undefined;
  }

  const runtimes = new Map<string, ViewRuntime>();
  const runtimeFor = (hidden: PrivateDir[]): ViewRuntime => {
    // Pelo conjunto escondido: mudar a lista de pastas abre gravações novas, e um arquivo nunca tem o que a visão esconde.
    const key = createHash('sha256').update(hidden.map((d) => d.dir).sort().join('\n')).digest('hex').slice(0, 16);
    let rt = runtimes.get(key);
    if (!rt) {
      const view = new PrivacyView({ hidden, entries: () => opts.accounts.allEntries(), roomAlias: opts.roomAlias });
      const timelineDir = join(opts.dataDir, 'timeline-views', key);
      rt = {
        key,
        view,
        timelineDir,
        stats: new DayStatsService({ dir: join(opts.dataDir, 'stats-views', key), snapshot: () => view.snapshot(opts.hub.current()) }),
        timeline: opts.timeline ? new TimelineRecorder({ dir: timelineDir }) : undefined,
      };
      runtimes.set(key, rt);
    }
    return rt;
  };

  // Todas as visões possíveis existem desde o boot: o histórico delas não depende de alguém ter entrado antes.
  const nobody = runtimeFor(dirs);
  const byOwner = new Map<string, ViewRuntime | null>();
  for (const owner of new Set(dirs.flatMap((d) => (d.owner ? [d.owner] : [])))) {
    const hidden = dirs.filter((d) => d.owner !== owner);
    byOwner.set(owner, hidden.length ? runtimeFor(hidden) : null);
  }

  return {
    apiFor(user) {
      // Só o dono de todas as pastas tem `null` aqui; quem não é dono de nada (ou não foi identificado) esconde todas.
      const found = user === undefined ? undefined : byOwner.get(user);
      if (found === null) return opts.api;
      const rt = found ?? nobody;
      rt.api ??= createApiHandler(scopedDeps(opts, rt));
      return rt.api;
    },
    start() {
      for (const w of warnings) log.warn(`   ${w}`);
      log.info(tr('   Sessões privadas: {0} pasta(s) reservada(s) na porta remota.', [dirs.length]));
      for (const rt of runtimes.values()) {
        rt.stats.load();
        rt.stats.start();
        if (rt.timeline) {
          const recorder = rt.timeline;
          rt.stopFeed = opts.hub.onSnapshot((snap) => recorder.ingest(rt.view.snapshot(snap)));
          recorder.start();
          recorder.ingest(rt.view.snapshot(opts.hub.current()));
        }
      }
      // As contas do Codex chegam depois do boot: um caminho errado seria uma sessão "privada" à vista de todos.
      setTimeout(() => {
        const entries = opts.accounts.allEntries();
        for (const d of dirs) {
          if (!entries.some((e) => sameAccount(e, d))) log.warn(tr('   Sessões privadas: a pasta {0} não é de nenhuma conta: confira o caminho, porque nada está sendo escondido por ela.', [d.dir]));
        }
      }, 5_000).unref?.();
    },
    stop() {
      for (const rt of runtimes.values()) {
        rt.stopFeed?.();
        rt.stats.stop();
        rt.timeline?.stop();
      }
    },
  };
}

/**
 * As dependências da API de uma visão, uma a uma e de propósito sem `...base`: o que não está aqui fica desligado. Ficam
 * de fora `pty`, `world`, `renameRoom` e `codexLive`, que a API já recusa em qualquer requisição remota.
 */
function scopedDeps(opts: PrivacyOptions, rt: ViewRuntime): ApiDeps {
  const { base, office, hub, accounts } = opts;
  const { view } = rt;

  const accountOf = (agentId: string): string | undefined => office.detail(agentId)?.agent.account;
  const agentVisible = (agentId: string): boolean => {
    const account = accountOf(agentId);
    return account !== undefined && view.accountFilter()(account);
  };
  const visibleEntries = (list: readonly AccountEntry[]) => {
    const visible = view.accountFilter();
    return list.filter((e) => visible(e.id));
  };

  const scopedHub: ApiDeps['hub'] = {
    attach: (req, res) => hub.attach(req, res, view),
    current: () => view.snapshot(hub.current()),
  };

  const sessions: SessionLookup | undefined = base.sessions && {
    list: async () => {
      const visible = view.accountFilter();
      return (await base.sessions!.list()).filter((s) => visible(s.account));
    },
    // Conta escondida responde exatamente como uma conta que não existe.
    resolve: (account, sessionId) => base.sessions!.resolve(view.accountFilter()(account) ? account : '\0', sessionId),
  };

  const permissionRegistry = opts.permissions;
  const canAnswer = (id: string): boolean => {
    const agent = permissionRegistry?.agentOf(id);
    // Sem agente real: é do demo ou não existe, e o registro responde cada caso.
    return agent === undefined || agentVisible(agent);
  };

  const sent = new Set<string>();
  const messageRegistry = opts.messages;

  return {
    office: {
      isDemo: () => base.office.isDemo(),
      has: (id) => office.has(id) && agentVisible(id),
      detail: (id) => {
        const detail = office.detail(id);
        return detail && view.accountFilter()(detail.agent.account) ? detail : undefined;
      },
      // A API recusa estes pela porta remota antes de chegar aqui.
      setDemo: () => {},
      resetCharacter: () => 'not-found',
      setCharacter: () => ({ result: 'not-found' }),
    },
    hub: scopedHub,
    accounts: {
      allEntries: () => visibleEntries(accounts.allEntries()),
      entriesOf: (provider) => visibleEntries(accounts.entriesOf(provider)),
      usageView: (id) => accounts.usageView(id),
    },
    sources: () => {
      const visible = view.accountFilter();
      return base.sources().filter((s) => visible(s.label));
    },
    version: base.version,
    inDocker: base.inDocker,
    terminal: base.terminal,
    terminals: base.terminals && {
      attach: (req, res, id) => {
        if (agentVisible(id)) base.terminals!.attach(req, res, id);
        else sendJson(res, 404, { error: tr('agente não encontrado') });
      },
      // Só chega aqui o que `sessions.resolve` acima liberou.
      attachSession: (req, res, streamId, path, createParser) => base.terminals!.attachSession(req, res, streamId, path, createParser),
    },
    sessions,
    timeline: createTimelineHandler({ dir: rt.timelineDir, recording: !!rt.timeline }),
    permissions: permissionRegistry
      ? createPermissionRoutes({
          // As duas primeiras são do hook e a API já as recusa na porta remota.
          register: () => {
            throw new HttpError(403, tr('rota desconhecida'));
          },
          wait: () => undefined,
          detail: (id) => (canAnswer(id) ? permissionRegistry.detail(id) : undefined),
          decide: (id, decision) => (canAnswer(id) ? permissionRegistry.decide(id, decision) : 'not-found'),
        })
      : undefined,
    messages: messageRegistry
      ? createMessageRoutes({
          send: (raw) => {
            const { agentId } = parseSend(raw);
            if (!agentVisible(agentId)) return { error: 'not-found' };
            const r = messageRegistry.send(raw);
            if ('message' in r) {
              if (sent.size >= MAX_SENT) sent.delete(sent.values().next().value!);
              sent.add(r.message.id);
            }
            return r;
          },
          // Só o que foi mandado por esta visão: o agente pode já ter saído quando a página pergunta.
          get: (id) => (sent.has(id) ? messageRegistry.get(id) : undefined),
          inbox: () => [],
          ack: () => {},
          codexPoll: () => [],
          codexAck: () => {},
        })
      : undefined,
    spawn: base.spawn,
    spawnFolders: base.spawnFolders && opts.spawnFoldersOf(scopedHub, sessions),
    attachments: base.attachments,
    dictation: base.dictation,
    // Índice próprio: os anexos dele só vêm das sessões desta visão, então um id de outra visão não abre nada.
    deliveries: base.deliveries && sessions ? opts.deliveriesOf(sessions) : undefined,
    files: base.files && {
      get: async (path) => (view.hidesPath(path) ? { error: tr('arquivo não encontrado'), status: 404 } : base.files!.get(path)),
      pollWait: async () => [],
      ack: () => {},
    },
    stats: rt.stats,
    updates: base.updates,
    remote: base.remote,
  };
}
