// Registro de acessos da porta remota: <dataDir>/remote-audit.log (permissão 600), uma linha JSON por evento.
//
// Quem registra só passa os campos de AuditFields, e todo texto é limpo aqui: um usuário digitado com quebra de linha ou
// caracteres de controle não consegue forjar outra linha nem mexer no terminal de quem lê. NUNCA entram senhas, códigos
// ou o conteúdo das mensagens. Falhar ao gravar não trava o login: o aviso vai para o log do servidor.
//
// Rotação simples: ao passar de maxBytes, o arquivo vira .1 (o .1 anterior se perde).
import { appendFileSync, chmodSync, mkdirSync, readFileSync, renameSync, statSync } from 'node:fs';
import { dirname } from 'node:path';

export type AuditEvent =
  | 'login.ok'
  | 'login.fail'
  | 'logout'
  | 'account.seed'
  | 'user.add'
  | 'user.change'
  | 'user.remove'
  | 'password.self'
  | '2fa.setup'
  | '2fa.on'
  | '2fa.off'
  | '2fa.fail'
  | 'permission.decision'
  | 'message.send';

const TEXT_FIELDS = ['user', 'by', 'target', 'ip', 'via', 'reason', 'what', 'id', 'behavior', 'agent'] as const;
type TextField = (typeof TEXT_FIELDS)[number];
const NUMBER_FIELDS = ['status', 'left'] as const;
type NumberField = (typeof NUMBER_FIELDS)[number];

export type AuditFields = Partial<Record<TextField, string>> & Partial<Record<NumberField, number>>;
export interface AuditEntry extends AuditFields {
  /** Data e hora em ISO (UTC); quem mostra converte para a hora local. */
  t: string;
  ev: string;
}

const MAX_FIELD = 64;
const DEFAULT_MAX_BYTES = 5 * 1024 * 1024;

/** Tira o que quebraria a linha ou enganaria o terminal (controle, formatação, separadores) e corta o tamanho. */
export function cleanField(value: string, max = MAX_FIELD): string {
  return value
    .slice(0, max * 4)
    .replace(/[\p{C}\p{Zl}\p{Zp}]/gu, '?')
    .trim()
    .slice(0, max);
}

function cleanFields(raw: Record<string, unknown>): AuditFields {
  const out: AuditFields = {};
  for (const key of TEXT_FIELDS) {
    const v = raw[key];
    if (typeof v === 'string' && v) out[key] = cleanField(v);
  }
  for (const key of NUMBER_FIELDS) {
    const v = raw[key];
    if (typeof v === 'number' && Number.isFinite(v)) out[key] = v;
  }
  return out;
}

export class AuditLog {
  private permsChecked = false;
  private warned = false;

  constructor(
    readonly file: string,
    private readonly opts: { maxBytes?: number; now?: () => number; onError?: (message: string) => void } = {},
  ) {}

  write(ev: AuditEvent, fields: AuditFields = {}): void {
    const now = this.opts.now ?? Date.now;
    const entry: AuditEntry = { t: new Date(now()).toISOString(), ev, ...cleanFields(fields as Record<string, unknown>) };
    try {
      mkdirSync(dirname(this.file), { recursive: true });
      this.rotateIfNeeded();
      appendFileSync(this.file, `${JSON.stringify(entry)}\n`, { mode: 0o600 });
      this.warned = false;
    } catch (err) {
      if (!this.warned) this.opts.onError?.((err as Error).message);
      this.warned = true;
      return;
    }
    this.fixPermissions();
  }

  private rotateIfNeeded(): void {
    let size = 0;
    try {
      size = statSync(this.file).size;
    } catch {
      return; // ainda não existe
    }
    if (size < (this.opts.maxBytes ?? DEFAULT_MAX_BYTES)) return;
    renameSync(this.file, `${this.file}.1`);
    this.permsChecked = false;
  }

  /** O modo em appendFile só vale ao criar: um arquivo que já existia frouxo é corrigido uma vez. */
  private fixPermissions(): void {
    if (this.permsChecked) return;
    this.permsChecked = true;
    try {
      chmodSync(this.file, 0o600);
    } catch {
      // arquivo de outro dono: a linha já foi gravada
    }
  }

  /** Os eventos mais recentes primeiro. O que está no arquivo passa pela mesma limpeza: ele pode ter sido editado. */
  read(limit = 200): AuditEntry[] {
    const max = Math.min(Math.max(1, Math.floor(limit) || 1), 1000);
    const out = this.readFile(this.file, max);
    if (out.length < max) out.push(...this.readFile(`${this.file}.1`, max - out.length));
    return out;
  }

  private readFile(file: string, max: number): AuditEntry[] {
    let lines: string[];
    try {
      lines = readFileSync(file, 'utf8').split('\n');
    } catch {
      return [];
    }
    const out: AuditEntry[] = [];
    for (let i = lines.length - 1; i >= 0 && out.length < max; i--) {
      if (!lines[i]) continue;
      try {
        const raw = JSON.parse(lines[i]) as Record<string, unknown>;
        if (typeof raw.t === 'string' && typeof raw.ev === 'string') out.push({ t: cleanField(raw.t), ev: cleanField(raw.ev), ...cleanFields(raw) });
      } catch {
        // linha cortada ou estranha: fica de fora
      }
    }
    return out;
  }
}
