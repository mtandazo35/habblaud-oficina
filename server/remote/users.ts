// Contas do acesso remoto: quem entra pela porta com login e o que cada um pode fazer.
//
// Ficam em <dataDir>/remote-users.json (permissão 600), só com o hash scrypt das senhas. O primeiro administrador vem de
// HABBLAUD_REMOTE_USER + HABBLAUD_REMOTE_PASSWORD_HASH. Trocar esse hash no .env (npm run remote:setup) recoloca a conta
// como administradora ativa com a senha nova: é a saída quando ninguém mais consegue entrar.
//
// O arquivo também pode mudar por fora (npm run remote:users): a loja percebe pela data do arquivo. Um arquivo ilegível
// não é sobrescrito: ninguém entra até consertar, porque recomeçar do zero devolveria acesso a quem foi retirado.
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, statSync, unwatchFile, watchFile, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { tr } from '../../shared/i18n';
import type { RemoteFeature } from '../http/remote';
import { parsePasswordHash } from './password';

export const ROLES = ['viewer', 'approver', 'operator', 'admin'] as const;
export type RemoteRole = (typeof ROLES)[number];

const ROLE_FEATURES: Record<RemoteRole, readonly RemoteFeature[]> = {
  viewer: [],
  approver: ['permissions', 'messages'],
  operator: ['permissions', 'messages', 'terminal', 'spawn'],
  admin: ['permissions', 'messages', 'terminal', 'spawn'],
};

export const MIN_PASSWORD = 10;
const NAME_RE = /^[a-z0-9][a-z0-9._-]{0,31}$/;

export interface RemoteUser {
  name: string;
  role: RemoteRole;
  hash: string;
  disabled: boolean;
  /** Geração das sessões: subir este número derruba todas as sessões da conta. */
  gen: number;
  createdAt: number;
}

export interface UserPatch {
  role?: RemoteRole;
  disabled?: boolean;
  hash?: string;
  /** Encerra as sessões abertas sem mudar mais nada. */
  revoke?: boolean;
}

/** Erro que pode ir para quem pediu: a mensagem é nossa e não revela nada interno. */
export class UserError extends Error {
  constructor(
    message: string,
    readonly status = 400,
  ) {
    super(message);
  }
}

export function normalizeName(name: string): string {
  return name.trim().toLowerCase();
}

export function isRole(value: unknown): value is RemoteRole {
  return typeof value === 'string' && (ROLES as readonly string[]).includes(value);
}

/** Por que a senha não serve (undefined = serve). */
export function passwordProblem(password: string, name: string): string | undefined {
  if (password.length < MIN_PASSWORD) return tr('use pelo menos {0} caracteres', [MIN_PASSWORD]);
  if (password.length > 256) return tr('senha longa demais');
  if (password.trim() !== password) return tr('sem espaços no começo ou no fim');
  if (password.toLowerCase() === name.toLowerCase()) return tr('a senha não pode ser o usuário');
  return undefined;
}

function validUser(u: unknown): u is RemoteUser {
  if (!u || typeof u !== 'object') return false;
  const r = u as Partial<RemoteUser>;
  return (
    typeof r.name === 'string' &&
    NAME_RE.test(r.name) &&
    isRole(r.role) &&
    typeof r.hash === 'string' &&
    !!parsePasswordHash(r.hash) &&
    typeof r.disabled === 'boolean' &&
    Number.isSafeInteger(r.gen) &&
    (r.gen as number) >= 0 &&
    typeof r.createdAt === 'number'
  );
}

export class UserStore {
  private users = new Map<string, RemoteUser>();
  private seedHash = '';
  private stamp = '';
  private readonly listeners = new Set<(name: string) => void>();
  /** Preenchido quando o arquivo existe e não dá para ler: ninguém entra e nada é gravado por cima. */
  problem?: string;

  constructor(
    private readonly file: string,
    private readonly seed?: { user: string; hashText: string },
    private readonly now: () => number = Date.now,
  ) {
    this.load();
  }

  /** `listener(nome)` depois de mudar uma conta (também por fora): quem estiver conectado precisa ser reavaliado. */
  onChange(listener: (name: string) => void): void {
    this.listeners.add(listener);
  }

  /** Percebe mudanças feitas por fora mesmo sem nenhuma requisição chegando. */
  watch(intervalMs = 2000): () => void {
    const tick = () => this.refresh();
    watchFile(this.file, { interval: intervalMs, persistent: false }, tick);
    return () => unwatchFile(this.file, tick);
  }

  get(name: string): RemoteUser | undefined {
    this.refresh();
    const user = this.users.get(normalizeName(name));
    return user && { ...user };
  }

  list(): RemoteUser[] {
    this.refresh();
    return [...this.users.values()].map((u) => ({ ...u })).sort((a, b) => a.name.localeCompare(b.name));
  }

  /** O papel desta conta permite `feature`? (HABBLAUD_REMOTE_ALLOW continua sendo o teto, conferido por quem chama.) */
  can(name: string | undefined, feature: RemoteFeature): boolean {
    if (!name) return false;
    const user = this.get(name);
    return !!user && !user.disabled && ROLE_FEATURES[user.role].includes(feature);
  }

  featuresOf(role: RemoteRole): readonly RemoteFeature[] {
    return ROLE_FEATURES[role];
  }

  add(rawName: string, role: RemoteRole, hash: string): RemoteUser {
    this.refresh();
    const name = normalizeName(rawName);
    if (!NAME_RE.test(name)) throw new UserError(tr('nome de usuário inválido: use letras, números, ponto, hífen ou sublinhado'));
    if (!isRole(role)) throw new UserError(tr('papel inválido'));
    if (!parsePasswordHash(hash)) throw new UserError(tr('senha inválida'));
    if (this.users.has(name)) throw new UserError(tr('esse usuário já existe'), 409);
    // A geração começa no relógio: recriar uma conta removida não ressuscita os tokens da antiga.
    const user: RemoteUser = { name, role, hash, disabled: false, gen: this.now(), createdAt: this.now() };
    this.users.set(name, user);
    this.commit(name);
    return { ...user };
  }

  update(rawName: string, patch: UserPatch): RemoteUser {
    this.refresh();
    const name = normalizeName(rawName);
    const current = this.users.get(name);
    if (!current) throw new UserError(tr('usuário não encontrado'), 404);
    if (patch.role !== undefined && !isRole(patch.role)) throw new UserError(tr('papel inválido'));
    if (patch.hash !== undefined && !parsePasswordHash(patch.hash)) throw new UserError(tr('senha inválida'));
    const next: RemoteUser = { ...current };
    if (patch.role !== undefined) next.role = patch.role;
    if (patch.disabled !== undefined) next.disabled = patch.disabled;
    if (patch.hash !== undefined) next.hash = patch.hash;
    if (patch.hash !== undefined || patch.revoke || (patch.disabled && !current.disabled)) next.gen = current.gen + 1;
    const wasAdmin = current.role === 'admin' && !current.disabled;
    const isAdmin = next.role === 'admin' && !next.disabled;
    if (wasAdmin && !isAdmin) this.assertAnotherAdmin(name);
    this.users.set(name, next);
    this.commit(name);
    return { ...next };
  }

  remove(rawName: string): void {
    this.refresh();
    const name = normalizeName(rawName);
    const current = this.users.get(name);
    if (!current) throw new UserError(tr('usuário não encontrado'), 404);
    if (current.role === 'admin' && !current.disabled) this.assertAnotherAdmin(name);
    this.users.delete(name);
    this.commit(name);
  }

  private assertAnotherAdmin(name: string): void {
    for (const u of this.users.values()) if (u.name !== name && u.role === 'admin' && !u.disabled) return;
    throw new UserError(tr('precisa ficar pelo menos um administrador ativo'), 409);
  }

  private commit(name: string): void {
    this.save();
    this.notify([name]);
  }

  private notify(names: string[]): void {
    if (!names.length) return;
    // Depois de um instante: quem pediu a mudança pode estar numa das conexões que vão cair e precisa receber a resposta.
    const timer = setTimeout(() => {
      for (const name of names) for (const listener of this.listeners) listener(name);
    }, 150);
    timer.unref();
  }

  private stampOf(): string {
    try {
      const s = statSync(this.file);
      return `${s.mtimeMs}:${s.size}`;
    } catch {
      return '';
    }
  }

  private refresh(): void {
    const stamp = this.stampOf();
    if (stamp === this.stamp) return;
    const before = this.users;
    this.load();
    const changed: string[] = [];
    for (const [name, old] of before) {
      const now = this.users.get(name);
      if (!now || now.role !== old.role || now.disabled !== old.disabled || now.gen !== old.gen) changed.push(name);
    }
    this.notify(changed);
  }

  private load(): void {
    this.problem = undefined;
    if (!existsSync(this.file)) {
      this.users = new Map();
      this.seedHash = '';
    } else {
      try {
        const data = JSON.parse(readFileSync(this.file, 'utf8')) as { seedHash?: unknown; users?: unknown };
        if (!Array.isArray(data.users) || !data.users.every(validUser)) throw new Error('formato');
        this.users = new Map((data.users as RemoteUser[]).map((u) => [u.name, u]));
        this.seedHash = typeof data.seedHash === 'string' ? data.seedHash : '';
      } catch {
        this.users = new Map();
        this.problem = tr('não deu para ler {0}: ninguém entra pela porta remota até consertar o arquivo', [this.file]);
        this.stamp = this.stampOf();
        return;
      }
    }
    this.stamp = this.stampOf();
    this.applySeed();
  }

  private applySeed(): void {
    if (!this.seed || this.seed.hashText === this.seedHash) return;
    const name = normalizeName(this.seed.user);
    if (!NAME_RE.test(name) || !parsePasswordHash(this.seed.hashText)) return;
    const current = this.users.get(name);
    this.users.set(name, {
      name,
      role: 'admin',
      hash: this.seed.hashText,
      disabled: false,
      gen: current ? current.gen + 1 : this.now(),
      createdAt: current?.createdAt ?? this.now(),
    });
    this.seedHash = this.seed.hashText;
    this.save();
  }

  private save(): void {
    if (this.problem) throw new UserError(this.problem, 500);
    try {
      mkdirSync(dirname(this.file), { recursive: true });
      const tmp = `${this.file}.tmp`;
      writeFileSync(tmp, JSON.stringify({ version: 1, seedHash: this.seedHash, users: [...this.users.values()] }, null, 2), { mode: 0o600 });
      chmodSync(tmp, 0o600);
      renameSync(tmp, this.file);
      this.stamp = this.stampOf();
    } catch {
      throw new UserError(tr('não deu para gravar a lista de usuários'), 500);
    }
  }
}

/** As conexões abertas de cada conta: desativar alguém precisa cortar também o que já estava transmitindo (SSE). */
export class ConnectionTracker {
  private readonly byUser = new Map<string, Set<{ destroy(): unknown; once(event: 'close', fn: () => void): unknown }>>();

  add(name: string, socket: { destroy(): unknown; once(event: 'close', fn: () => void): unknown }): void {
    let sockets = this.byUser.get(name);
    if (!sockets) this.byUser.set(name, (sockets = new Set()));
    if (sockets.has(socket)) return;
    sockets.add(socket);
    socket.once('close', () => {
      const set = this.byUser.get(name);
      set?.delete(socket);
      if (set?.size === 0) this.byUser.delete(name);
    });
  }

  /** Corta tudo da conta; o navegador reconecta e passa pelo login e pelo papel de novo. */
  kick(name: string): void {
    for (const socket of [...(this.byUser.get(name) ?? [])]) socket.destroy();
  }
}
