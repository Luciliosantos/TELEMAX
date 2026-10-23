#!/usr/bin/env bash
set -Eeuo pipefail

REPO_URL="https://github.com/Luciliosantos/TELEMAX.git"
BASE="/opt/telemax"
APP_DIR="$BASE/app/telemax"
VENV="$BASE/venv"
ENV_FILE="$BASE/.env"
SERVICE_FILE="/etc/systemd/system/telemax.service"
DOMAIN="${TELEMAX_DOMAIN:-telemax.lsnet.shop}"
TMP=""

cleanup() {
  if [[ -n "$TMP" && -d "$TMP" ]]; then rm -rf -- "$TMP"; fi
}
trap cleanup EXIT

if [[ $EUID -ne 0 ]]; then
  echo "Execute como root: sudo bash install.sh"
  exit 1
fi

if [[ -e "$APP_DIR" || -e "$ENV_FILE" || -e "$SERVICE_FILE" ]]; then
  echo "ERRO: já existe uma instalação ou configuração TELEMAX."
  echo "Nada foi sobrescrito. Use uma VPS nova."
  exit 2
fi

echo "=== 1/7 - Dependências do sistema ==="
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y git python3 python3-venv python3-pip \
  build-essential nginx rsync openssl

echo "=== 2/7 - Obtendo o projeto ==="
TMP="$(mktemp -d)"
git clone --depth 1 "$REPO_URL" "$TMP/repo"
SRC="$TMP/repo"

test -f "$SRC/wsgi.py" || { echo "wsgi.py não encontrado."; exit 1; }
test -f "$SRC/telemax/__init__.py" || { echo "Aplicação não encontrada."; exit 1; }
test -f "$SRC/scripts/create_admin.py" || { echo "Script de administrador não encontrado."; exit 1; }
test -d "$SRC/migrations" || { echo "Migrações não encontradas."; exit 1; }

echo "=== 3/7 - Instalando os arquivos ==="
mkdir -p "$BASE/app"
rsync -a \
  --exclude='.git/' \
  --exclude='.env' \
  --exclude='instance/' \
  --exclude='__pycache__/' \
  "$SRC/" "$APP_DIR/"
mkdir -p "$APP_DIR/instance"
chmod 750 "$APP_DIR/instance"

echo "=== 4/7 - Ambiente Python ==="
python3 -m venv "$VENV"
"$VENV/bin/pip" install --upgrade pip
"$VENV/bin/pip" install -r "$APP_DIR/requirements.txt"
"$VENV/bin/pip" install gunicorn python-dotenv

echo "=== 5/7 - Configuração segura ==="
SECRET_KEY="$(openssl rand -hex 32)"
PIX_SECRET="$(openssl rand -hex 32)"

cat > "$ENV_FILE" <<EOF
FLASK_ENV=production
SECRET_KEY=$SECRET_KEY
BASE_URL=https://$DOMAIN
DATABASE_PATH=$APP_DIR/instance/telemax.db
SESSION_LIFETIME_HOURS=24
MAX_UPLOAD_BYTES=10485760
PIX_PROVIDER=manual
PIX_WEBHOOK_SECRET=$PIX_SECRET
MERCADOPAGO_ACCESS_TOKEN=
MERCADOPAGO_WEBHOOK_SECRET=
EMAIL_BACKEND=console
SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASSWORD=
EMAIL_FROM=contato@$DOMAIN
EOF
chmod 600 "$ENV_FILE"

echo "=== 6/7 - Inicializando banco e administrador ==="
cd "$APP_DIR"
"$VENV/bin/python" -c 'from telemax import create_app; create_app()'
"$VENV/bin/python" scripts/create_admin.py

echo "=== 7/7 - Criando e iniciando serviço ==="
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=TELEMAX Web Application
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
systemctl enable --now telemax
sleep 2

if ! systemctl is-active --quiet telemax; then
  echo "ERRO: serviço não iniciou. Consulte:"
  journalctl -u telemax -n 60 --no-pager
  exit 1
fi

cat > /etc/nginx/sites-available/telemax <<EOF
server {
    listen 80;
    server_name $DOMAIN;

    client_max_body_size 10M;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host \\\$host;
        proxy_set_header X-Real-IP \\\$remote_addr;
        proxy_set_header X-Forwarded-For \\\$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \\\$scheme;
    }
}
EOF

ln -s /etc/nginx/sites-available/telemax /etc/nginx/sites-enabled/telemax
nginx -t
systemctl enable --now nginx
systemctl reload nginx

echo
echo "INSTALAÇÃO CONCLUÍDA."
echo "Aplicação: $APP_DIR"
echo "Configuração privada: $ENV_FILE"
echo "Serviço: systemctl status telemax"
echo "Domínio: http://$DOMAIN"
echo "Configure o DNS apontando para esta VPS."
echo "Depois de confirmar o DNS, configure HTTPS com Certbot."
