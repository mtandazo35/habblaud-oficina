#!/usr/bin/env bash
# Instalación rápida de habblaud-oficina en Debian o Ubuntu con systemd.
#
#   curl -fsSL https://raw.githubusercontent.com/mtandazo35/habblaud-oficina/main/install.sh | sudo bash
#
# Sirve también para actualizar: al repetirlo respalda los datos, trae la versión nueva y reinicia, sin cambiar la
# contraseña. No toca el firewall. Opciones por entorno (van después de sudo):
#
#   curl -fsSL .../install.sh | sudo HB_PERMISOS=permissions,messages,terminal,spawn bash
#
#   HB_USUARIO   cuenta del sistema y usuario del panel (habblaud)
#   HB_PUERTO    puerto HTTPS del panel (4748)
#   HB_NOMBRE    nombre <nombre>.local del certificado (habblaud)
#   HB_PERMISOS  qué se puede hacer por la red: permissions, messages, terminal, spawn, none (permissions,messages)
#   HB_IDIOMA    es, en, fr o pt-BR (es)
#   HB_MEMORIA   límite de memoria del servicio (600M)
#   HB_RAMA      rama o etiqueta del repo (main)
#   HB_REPO      URL del repo
#
# Todo va dentro de main(), llamada en la última línea: una descarga cortada no ejecuta nada a medias, y los comandos
# hijos no pueden comerse el resto del script por la entrada estándar.
set -Eeuo pipefail

HB_USUARIO="${HB_USUARIO:-habblaud}"
HB_PUERTO="${HB_PUERTO:-4748}"
HB_NOMBRE="${HB_NOMBRE:-habblaud}"
HB_PERMISOS="${HB_PERMISOS:-permissions,messages}"
HB_IDIOMA="${HB_IDIOMA:-es}"
HB_MEMORIA="${HB_MEMORIA:-600M}"
HB_RAMA="${HB_RAMA:-main}"
HB_REPO="${HB_REPO:-https://github.com/mtandazo35/habblaud-oficina.git}"

NODE_MINIMO_MAYOR=22
NODE_MINIMO_MENOR=12
PANEL_TXT=/root/habblaud-panel.txt
SERVICIO=habblaud
CASA=""
DIR=""
TEMPORAL=""

paso() { printf '\n==> %s\n' "$*"; }
aviso() { printf 'AVISO: %s\n' "$*" >&2; }
morir() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

como_usuario() {
  runuser -u "$HB_USUARIO" -- env HOME="$CASA" LANG=C.UTF-8 HABBLAUD_LANG="$HB_IDIOMA" \
    PATH="$CASA/.local/bin:/usr/local/bin:/usr/bin:/bin" TMPDIR="$CASA/.cache/hb-tmp" "$@"
}

validar() {
  [[ "$HB_USUARIO" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || morir "HB_USUARIO no es válido"
  [[ "$HB_PUERTO" =~ ^[0-9]{1,5}$ ]] && ((HB_PUERTO > 0 && HB_PUERTO < 65536)) || morir "HB_PUERTO no es válido"
  [[ "$HB_NOMBRE" =~ ^[a-z0-9][a-z0-9-]{0,62}$ ]] || morir "HB_NOMBRE no es válido"
  [[ "$HB_PERMISOS" =~ ^[a-z,]+$ ]] || morir "HB_PERMISOS no es válido"
  [[ "$HB_IDIOMA" =~ ^[A-Za-z-]+$ ]] || morir "HB_IDIOMA no es válido"
  [[ "$HB_MEMORIA" =~ ^[0-9]+[KMG]$ ]] || morir "HB_MEMORIA no es válido"
  [[ "$HB_RAMA" =~ ^[A-Za-z0-9._/-]+$ ]] || morir "HB_RAMA no es válida"
}

comprobar_sistema() {
  [[ "$(id -u)" == 0 ]] || morir "ejecútalo como root (con sudo)"
  command -v apt-get >/dev/null || morir "este instalador solo funciona en Debian o Ubuntu"
  [[ -d /run/systemd/system ]] || morir "hace falta systemd en marcha"
}

instalar_paquetes() {
  paso "Paquetes del sistema"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq </dev/null
  apt-get install -y -qq --no-upgrade ca-certificates curl git openssl xz-utils python3 build-essential </dev/null >/dev/null
}

node_sirve() {
  command -v node >/dev/null || return 1
  node -e "const [a,b]=process.versions.node.split('.').map(Number);process.exit(a>$NODE_MINIMO_MAYOR||(a===$NODE_MINIMO_MAYOR&&b>=$NODE_MINIMO_MENOR)?0:1)" </dev/null
}

instalar_node() {
  if node_sirve; then
    paso "Node $(node -v) ya instalado"
    return
  fi
  paso "Node 24 (nodejs.org, con suma SHA256 comprobada)"
  local arq base archivo carpeta
  case "$(uname -m)" in
    x86_64) arq=x64 ;;
    aarch64) arq=arm64 ;;
    *) morir "arquitectura no soportada: $(uname -m)" ;;
  esac
  base=https://nodejs.org/dist/latest-v24.x
  curl -fsSL -o "$TEMPORAL/sumas.txt" "$base/SHASUMS256.txt"
  archivo="$(awk -v f="linux-$arq.tar.xz" '$2 ~ f"$" {print $2}' "$TEMPORAL/sumas.txt")"
  [[ -n "$archivo" ]] || morir "no encuentro Node para linux-$arq"
  curl -fsSL -o "$TEMPORAL/$archivo" "$base/$archivo"
  (cd "$TEMPORAL" && grep " $archivo\$" sumas.txt | sha256sum -c --quiet -) || morir "la suma de Node no coincide"
  tar -xJf "$TEMPORAL/$archivo" -C /opt
  carpeta="/opt/${archivo%.tar.xz}"
  ln -sf "$carpeta/bin/node" "$carpeta/bin/npm" "$carpeta/bin/npx" /usr/local/bin/
  hash -r
  node_sirve || morir "Node no quedó instalado"
}

crear_usuario() {
  if ! id "$HB_USUARIO" >/dev/null 2>&1; then
    paso "Cuenta $HB_USUARIO"
    useradd -m -s /bin/bash "$HB_USUARIO"
  fi
  CASA="$(getent passwd "$HB_USUARIO" | cut -d: -f6)"
  DIR="$CASA/habblaud"
  como_usuario mkdir -p "$CASA/.cache/hb-tmp"
}

respaldar() {
  local destino
  destino="/root/backups/habblaud-pre-actualizar-$(date +%Y%m%d-%H%M%S).tar.gz"
  paso "Respaldo en $destino"
  mkdir -p /root/backups
  chmod 700 /root/backups
  local rutas=("${DIR#/}/.env")
  [[ -d "$CASA/.habblaud" ]] && rutas+=("${CASA#/}/.habblaud")
  (umask 077 && tar -czf "$destino" -C / "${rutas[@]}") || morir "falló el respaldo; no se cambió nada"
}

traer_codigo() {
  if [[ -d "$DIR/.git" ]]; then
    [[ -f "$DIR/.env" ]] && respaldar
    paso "Actualizando el código ($HB_RAMA)"
    como_usuario git -C "$DIR" fetch -q --tags origin </dev/null
    como_usuario git -C "$DIR" checkout -q "$HB_RAMA" </dev/null
    if como_usuario git -C "$DIR" symbolic-ref -q HEAD >/dev/null; then
      como_usuario git -C "$DIR" pull -q --ff-only </dev/null || morir "hay cambios locales en $DIR; no se pueden mezclar solos"
    fi
  else
    paso "Descargando el código ($HB_RAMA)"
    como_usuario git clone -q --branch "$HB_RAMA" "$HB_REPO" "$DIR" </dev/null
  fi
}

compilar() {
  paso "Dependencias y compilación (tarda unos minutos)"
  como_usuario bash -c "cd '$DIR' && npm ci --no-audit --no-fund --loglevel=error && npm run -s build" </dev/null >/dev/null
  if ! como_usuario bash -c "cd '$DIR' && node -e \"require('node-pty')\"" </dev/null >/dev/null 2>&1; then
    como_usuario bash -c "cd '$DIR' && npm rebuild node-pty --loglevel=error" </dev/null >/dev/null ||
      aviso "node-pty no compiló: el panel funciona, pero sin terminal"
  fi
}

instalar_claude() {
  if [[ ! -x "$CASA/.local/bin/claude" ]] && ! command -v claude >/dev/null; then
    paso "Claude Code"
    como_usuario bash -c 'curl -fsSL https://claude.ai/install.sh | bash' </dev/null >/dev/null ||
      aviso "no se pudo instalar Claude Code; instálalo a mano y corre: npm run mod:install"
  fi
  if como_usuario bash -c 'command -v claude' </dev/null >/dev/null; then
    paso "Plugins de Habblaud en Claude Code"
    como_usuario bash -c "cd '$DIR' && npm run -s mod:install" </dev/null >/dev/null ||
      aviso "falló mod:install; repítelo a mano en $DIR"
  fi
}

poner_env() {
  grep -q "^$1=" "$DIR/.env" || printf '%s=%s\n' "$1" "$2" >>"$DIR/.env"
}

configurar_acceso() {
  if [[ -f "$DIR/.env" ]] && grep -q '^HABBLAUD_REMOTE_PASSWORD_HASH=' "$DIR/.env"; then
    paso "El acceso ya estaba configurado: la contraseña no cambia"
  else
    paso "Acceso por red con HTTPS y contraseña nueva"
    local clave salida
    clave="$(openssl rand -base64 24 | tr -d '/+=\n')"
    # La contraseña entra por stdin: no aparece en la lista de procesos. El .env guarda solo el hash.
    if ! salida="$(printf '%s\n' "$clave" | como_usuario bash -c "cd '$DIR' && npm run -s remote:setup -- --password-stdin --user '$HB_USUARIO' --name '$HB_NOMBRE' --port '$HB_PUERTO' --allow '$HB_PERMISOS' --no-service" 2>&1)"; then
      printf '%s\n' "$salida" >&2
      morir "no se pudo configurar el acceso"
    fi
    (
      umask 077
      printf 'usuario: %s\ncontraseña: %s\n' "$HB_USUARIO" "$clave" >"$PANEL_TXT"
    )
  fi
  touch "$DIR/.env"
  poner_env HABBLAUD_PTY 1
  poner_env HABBLAUD_LANG "$HB_IDIOMA"
  chown "$HB_USUARIO:" "$DIR/.env"
  chmod 600 "$DIR/.env"
}

instalar_servicio() {
  paso "Servicio $SERVICIO"
  cat >"/etc/systemd/system/$SERVICIO.service" <<EOF
[Unit]
Description=Habblaud - oficina virtual de agentes
After=network-online.target
Wants=network-online.target

[Service]
User=$HB_USUARIO
WorkingDirectory=$DIR
Environment=HOME=$CASA
Environment=LANG=C.UTF-8
Environment=NODE_ENV=production
Environment=PATH=$CASA/.local/bin:/usr/local/bin:/usr/bin:/bin
EnvironmentFile=$DIR/.env
ExecStart=$(command -v node) dist/server/index.js
Restart=always
RestartSec=3
MemoryMax=$HB_MEMORIA

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable -q "$SERVICIO"
  systemctl restart "$SERVICIO"
}

comprobar_panel() {
  paso "Comprobando el panel"
  local puerto codigo="" i
  puerto="$(sed -n 's/^HABBLAUD_REMOTE_PORT=//p' "$DIR/.env")"
  for ((i = 0; i < 40; i++)); do
    codigo="$(curl -sk -o /dev/null -w '%{http_code}' "https://127.0.0.1:$puerto/" || true)"
    [[ "$codigo" == 200 || "$codigo" == 302 ]] && break
    sleep 1
  done
  if [[ "$codigo" != 200 && "$codigo" != 302 ]]; then
    journalctl -u "$SERVICIO" -n 30 --no-pager >&2 || true
    morir "el panel no responde en el puerto $puerto (último código: $codigo)"
  fi
  HB_PUERTO="$puerto"
}

resumen() {
  local ip huella
  ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  huella="$(openssl x509 -in "$CASA/.habblaud/remote-tls/ca/ca.crt" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 || true)"
  cat <<EOF

Habblaud instalado.

  Panel:       https://${ip:-IP_DEL_SERVIDOR}:$HB_PUERTO
  Credenciales: sudo cat $PANEL_TXT
  Huella CA:   ${huella:-no disponible}

Siguiente paso, iniciar la sesión de Claude Code:

  sudo su - $HB_USUARIO -c claude

Este instalador no toca el firewall: limita el puerto $HB_PUERTO a tu red si el servidor es accesible desde fuera.
EOF
}

main() {
  validar
  comprobar_sistema
  TEMPORAL="$(mktemp -d /root/.habblaud-instalar.XXXXXX)"
  trap 'rm -rf "$TEMPORAL"' EXIT
  instalar_paquetes
  instalar_node
  crear_usuario
  traer_codigo
  compilar
  instalar_claude
  configurar_acceso
  instalar_servicio
  comprobar_panel
  resumen
}

main "$@"
