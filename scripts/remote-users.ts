// npm run remote:users -- <comando>: gerencia as contas do acesso remoto pelo próprio servidor, sem navegador. É também a
// saída para quem perdeu o acesso de administrador ou o celular do 2FA. O servidor em execução percebe a mudança sozinho.
//
// Senha: `add` e `passwd` leem da entrada padrão quando ela vem de um pipe; sem pipe, geram uma e mostram uma vez.
import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AuditLog } from '../server/remote/audit';
import { readEnvValue } from '../server/remote/envfile';
import { hashPassword } from '../server/remote/password';
import { isRole, normalizeName, passwordProblem, UserError, UserStore } from '../server/remote/users';
import { tr } from '../shared/i18n';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const USAGE = tr('Uso: npm run remote:users -- list | add <nome> <papel> | passwd <nome> | role <nome> <papel> | disable <nome> | enable <nome> | revoke <nome> | remove <nome> | 2fa-off <nome> | audit [linhas]');

function open(): { store: UserStore; audit: AuditLog } {
  const envFile = join(ROOT, '.env');
  const env = existsSync(envFile) ? readFileSync(envFile, 'utf8') : '';
  const dataDir = process.env.HABBLAUD_DATA_DIR?.trim() || readEnvValue(env, 'HABBLAUD_DATA_DIR') || join(process.env.HOME || homedir(), '.habblaud');
  const user = readEnvValue(env, 'HABBLAUD_REMOTE_USER');
  const hashText = readEnvValue(env, 'HABBLAUD_REMOTE_PASSWORD_HASH');
  return {
    store: new UserStore(join(dataDir, 'remote-users.json'), user && hashText ? { user, hashText } : undefined),
    audit: new AuditLog(join(dataDir, 'remote-audit.log'), { onError: (message) => console.error(tr('Não deu para gravar o registro de acessos: {0}', [message])) }),
  };
}

async function readPassword(name: string): Promise<{ hash: string; shown?: string }> {
  let password: string;
  let shown: string | undefined;
  if (process.stdin.isTTY) {
    password = randomBytes(15).toString('base64url');
    shown = password;
  } else {
    let raw = '';
    for await (const chunk of process.stdin) raw += String(chunk);
    password = raw.split(/\r?\n/)[0] ?? '';
  }
  const problem = passwordProblem(password, name);
  if (problem) throw new UserError(tr('senha recusada: {0}', [problem]));
  return { hash: await hashPassword(password), shown };
}

function need(value: string | undefined): string {
  if (!value) throw new UserError(USAGE);
  return value;
}

async function main(): Promise<void> {
  const [command, rawName, rawRole] = process.argv.slice(2);
  const { store, audit } = open();
  if (store.problem) throw new UserError(store.problem);
  const changed = (name: string, what: string) => audit.write('user.change', { by: 'cli', target: normalizeName(name), what });
  switch (command) {
    case 'list':
      for (const u of store.list()) console.log(`${u.name}\t${u.role}\t${u.disabled ? tr('Desativado') : tr('Ativo')}\t${u.totp ? tr('2FA ativo') : tr('sem 2FA')}`);
      return;
    case 'add': {
      const name = need(rawName).toLowerCase();
      if (!isRole(rawRole)) throw new UserError(tr('papel inválido'));
      const { hash, shown } = await readPassword(name);
      store.add(name, rawRole, hash);
      audit.write('user.add', { by: 'cli', target: name, what: `role=${rawRole}` });
      if (shown) console.log(tr('Senha de {0}: {1}', [name, shown]));
      return;
    }
    case 'passwd': {
      const name = need(rawName).toLowerCase();
      const { hash, shown } = await readPassword(name);
      store.update(name, { hash });
      changed(name, 'password');
      if (shown) console.log(tr('Senha de {0}: {1}', [name, shown]));
      return;
    }
    case 'role':
      if (!isRole(rawRole)) throw new UserError(tr('papel inválido'));
      store.update(need(rawName), { role: rawRole });
      changed(need(rawName), `role=${rawRole}`);
      return;
    case 'disable':
      store.update(need(rawName), { disabled: true });
      changed(need(rawName), 'disabled=true');
      return;
    case 'enable':
      store.update(need(rawName), { disabled: false });
      changed(need(rawName), 'disabled=false');
      return;
    case 'revoke':
      store.update(need(rawName), { revoke: true });
      changed(need(rawName), 'sessions');
      return;
    case 'remove':
      store.remove(need(rawName));
      audit.write('user.remove', { by: 'cli', target: normalizeName(need(rawName)) });
      return;
    case '2fa-off':
      store.update(need(rawName), { totpOff: true });
      audit.write('2fa.off', { by: 'cli', target: normalizeName(need(rawName)) });
      console.log(tr('2FA de {0} desativado; as sessões da conta caem.', [normalizeName(need(rawName))]));
      return;
    case 'audit': {
      const limit = rawName === undefined ? 50 : Number.parseInt(rawName, 10);
      if (!Number.isInteger(limit) || limit < 1) throw new UserError(USAGE);
      // Do mais antigo para o mais novo, como um log; a hora é a local deste servidor.
      for (const e of audit.read(limit).reverse()) {
        const { t, ev, ...rest } = e;
        const when = Number.isNaN(Date.parse(t)) ? t : new Date(t).toLocaleString();
        console.log(`${when}\t${ev}\t${Object.entries(rest).map(([k, v]) => `${k}=${v}`).join(' ')}`);
      }
      return;
    }
    default:
      throw new UserError(USAGE);
  }
}

main().catch((err: unknown) => {
  console.error(err instanceof UserError ? err.message : String(err));
  process.exitCode = 1;
});
