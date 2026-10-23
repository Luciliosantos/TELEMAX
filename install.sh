#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="/opt/telemax/app/telemax"
BASE_DIR="/opt/telemax"
VENV="$BASE_DIR/venv"
ENV_FILE="$BASE_DIR/.env"
SERVICE_FILE="/etc/systemd/system/telemax.service"
REPO_URL="https://github.com/Luciliosantos/TELEMAX.git"

if [[ $EUID -ne 0 ]]; then
  echo "Execute como root: sudo bash install.sh"
  exit 1
fi

echo "=== TELEMAX: instalador ==="
echo "Este instalador não importa o banco de produção automaticamente."

if [[ -d "$APP_DIR" ]]; then
  echo "Instalação existente detectada: $APP_DIR"
  echo "Não será sobrescrita automaticamente."
  echo "Faça a instalação inicial em uma VPS limpa ou prepare uma migração separada."
  exit 2
fi

if [[ -e "$ENV_FILE" ]]; then
  echo "Já existe $ENV_FILE; não será sobrescrito."
else
  echo "Será necessário configurar as credenciais privadas depois."
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ ! -f "$SCRIPT_DIR/wsgi.py" || ! -f "$SCRIPT_DIR/requirements.txt" ]]; then
  echo "ERRO: execute a partir de uma cópia completa do repositório."
  exit 1
fi

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  python3 python3-venv python3-pip git build-essential

mkdir -p "$BASE_DIR/app"
cp -a "$SCRIPT_DIR" "$APP_DIR"
python3 -m venv "$VENV"
"$VENV/bin/pip" install --upgrade pip
"$VENV/bin/pip" install -r "$APP_DIR/requirements.txt"
"$VENV/bin/pip" install gunicorn

if [[ ! -f "$ENV_FILE" ]]; then
  SECRET="$("$VENV/bin/python" -c 'import secrets; print(secrets.token_hex(32))')"
  cat > "$ENV_FILE" <<EOF
FLASK_ENV=production
SECRET_KEY=$SECRET
BASE_URL=http://localhost
DATABASE_PATH=$APP_DIR/instance/telemax.db
SESSION_LIFETIME_HOURS=24
MAX_UPLOAD_BYTES=10485760
PIX_PROVIDER=manual
PIX_WEBHOOK_SECRET=
MERCADOPAGO_ACCESS_TOKEN=
MERCADOPAGO_WEBHOOK_SECRET=
EMAIL_BACKEND=
SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASSWORD=
EMAIL_FROM=
EOF
  chmod 600 "$ENV_FILE"
fi

mkdir -p "$APP_DIR/instance"
chmod 750 "$APP_DIR/instance"

echo
echo "=== Verificando inicialização do banco ==="
echo "Confira as instruções do projeto antes de aplicar migrations."
echo "Nenhuma migration será executada automaticamente por este instalador."

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=TeleMax Web Application (Gunicorn)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$APP_DIR
EnvironmentFile=$ENV_FILE
Environment=PYTHONUNBUFFERED=1
ExecStart=$VENV/bin/gunicorn --workers 1 --bind 127.0.0.1:8000 --timeout 60 --access-logfile - --error-logfile - wsgi:app
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
echo
echo "Instalação dos arquivos concluída."
echo "Configure BASE_URL, PIX, Mercado Pago e SMTP em $ENV_FILE."
echo "Antes de ativar o serviço, inicialize o banco conforme docs/DEPLOY.md."
echo "O serviço ainda NÃO foi iniciado."
