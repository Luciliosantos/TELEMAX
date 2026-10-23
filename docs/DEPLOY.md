# Implantação no domínio telemax.lsnet.shop

## 1. DNS (provedor onde o domínio lsnet.shop está hospedado)

| Tipo | Nome | Valor |
|------|------|-------|
| A    | telemax | IP_DO_SEU_VPS |
| AAAA | telemax | IPv6 (opcional) |

Aguarde propagação: `dig +short telemax.lsnet.shop`

## 2. Servidor (Ubuntu 22.04+)

```bash
sudo apt update && sudo apt install -y python3-venv python3-pip sqlite3 nginx certbot python3-certbot-nginx
mkdir -p /var/www/telemax && cd /var/www/telemax
# copie o conteúdo do ZIP para cá (rsync/scp/unzip)
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt gunicorn
cp .env.example .env && nano .env   # FLASK_ENV=production, SECRET_KEY, BASE_URL, segredos
export $(grep -v '^#' .env | xargs)
python -c "from telemax import create_app; create_app()"   # migrações
python scripts/create_admin.py                              # admin inicial
chown -R www-data:www-data instance/
```

## 3. systemd (`/etc/systemd/system/telemax.service`)

```ini
[Unit]
Description=TELEMAX
After=network.target
[Service]
User=www-data
WorkingDirectory=/var/www/telemax
EnvironmentFile=/var/www/telemax/.env
ExecStart=/var/www/telemax/venv/bin/gunicorn -w 4 -b 127.0.0.1:8000 wsgi:app
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now telemax
```

## 4. Expiração de destaques (systemd timer, 2x por dia)

`/etc/systemd/system/telemax-expire.service`:
```ini
[Unit]
Description=Expira promocoes TELEMAX
[Service]
User=www-data
WorkingDirectory=/var/www/telemax
ExecStart=/var/www/telemax/venv/bin/python scripts/expire_promotions.py
```
`/etc/systemd/system/telemax-expire.timer` com `OnCalendar=*-*-* 06,18:00` e `sudo systemctl enable --now telemax-expire.timer`.
(A plataforma também expira por demanda a cada acesso; o timer é a rede de segurança.)

## 5. Nginx (`/etc/nginx/sites-available/telemax`)

```nginx
server {
    server_name telemax.lsnet.shop;
    client_max_body_size 3M;
    location /static/ { alias /var/www/telemax/static/; expires 7d; }
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/telemax /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

## 6. HTTPS

```bash
sudo certbot --nginx -d telemax.lsnet.shop
# renovação automática: sudo certbot renew --dry-run
```

## 7. Backups

```bash
0 3 * * * /var/www/telemax/scripts/backup.sh /var/backups/telemax
```
Guarda o SQLite e os uploads com retenção de 14 dias.

## 8. Atualização e reversão

```bash
cd /var/www/telemax
./scripts/backup.sh /var/backups/telemax       # 1. backup
# 2. copie a nova versão por cima (menos instance/)
# 3. migrações:
#    export $(grep -v '^#' .env | xargs)
#    venv/bin/python -c "from telemax import create_app; create_app()"
# 4. venv/bin/python -m unittest discover -s tests   # valide antes de reiniciar
sudo systemctl restart telemax
# Reversão: restaurar o .db do backup + voltar o código anterior + restart
```

## 9. Logs

- Aplicação: `instance/logs/telemax.log` e `journalctl -u telemax -f`
- Auditoria administrativa: painel Admin → Logs
