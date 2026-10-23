"""Fábrica da aplicação TELEMAX."""
import logging
import os
from dotenv import load_dotenv
load_dotenv("/opt/telemax/.env", override=False)

from flask import (Flask, g, redirect, render_template, request, session, url_for)

from .config import Config
from .db import init_app as db_init, query, execute, run_migrations
from .security import (account_locked, audit, csrf_token, login_blocked, now,
                       record_login_attempt, register_failed_login, session_user)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DEV_SECRET_KEYS = {"", "telemax-dev-insecure-key", "dev-webhook-secret", "change-me"}

def _validate_production(app):
    """Em produção, recusa configuração insegura ANTES de servir qualquer pedido.

    - SECRET_KEY: obrigatória, com pelo menos 32 caracteres e diferente dos
      valores conhecidos de desenvolvimento.
    - PIX_PROVIDER=mercadopago: exige MERCADOPAGO_ACCESS_TOKEN com prefixo
      válido (APP_USR- produção / TEST- sandbox) e MERCADOPAGO_WEBHOOK_SECRET
      com no mínimo 16 caracteres.
    Em desenvolvimento apenas registra aviso.
    """
    if not app.config.get("IS_PROD"):
        if app.config.get("PIX_PROVIDER") == "mercadopago" and not (
                app.config.get("MERCADOPAGO_ACCESS_TOKEN") or "").strip():
            app.logger.warning("PIX_PROVIDER=mercadopago sem MERCADOPAGO_ACCESS_TOKEN: "
                              "cobranças serão recusadas até configurar o token")
        return
    sk = (app.config.get("SECRET_KEY") or "").strip()
    if sk in DEV_SECRET_KEYS or len(sk) < 32:
        raise RuntimeError(
            "SECRET_KEY insegura para produção: defina uma chave aleatória de 32+ "
            "caracteres (ex.: python -c \"import secrets; print(secrets.token_hex(32))\")")
    if app.config.get("PIX_PROVIDER") == "mercadopago":
        tok = (app.config.get("MERCADOPAGO_ACCESS_TOKEN") or "").strip()
        wsec = (app.config.get("MERCADOPAGO_WEBHOOK_SECRET") or "").strip()
        if not tok.startswith(("APP_USR-", "TEST-")):
            raise RuntimeError(
                "MERCADOPAGO_ACCESS_TOKEN ausente ou inválido: o provider "
                "mercadopago exige um token iniciando com APP_USR- (produção) "
                "ou TEST- (sandbox)")
        if len(wsec) < 16:
            raise RuntimeError(
                "MERCADOPAGO_WEBHOOK_SECRET ausente ou curto (mín. 16): "
                "configure a secret key do webhook no painel do Mercado Pago")

def create_app(config_object=Config):
    app = Flask(__name__,
                template_folder=os.path.join(ROOT, "templates"),
                static_folder=os.path.join(ROOT, "static"))
    app.config.from_object(config_object)
    _validate_production(app)
    os.makedirs(app.instance_path, exist_ok=True)
    os.makedirs(os.path.join(app.instance_path, "uploads"), exist_ok=True)
    os.makedirs(os.path.join(app.instance_path, "logs"), exist_ok=True)

    db_init(app)
    with app.app_context():
        run_migrations()

    # logs
    os.makedirs(os.path.join(app.instance_path, "logs"), exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[logging.FileHandler(os.path.join(app.instance_path, "logs", "telemax.log"), encoding="utf-8"),
                  logging.StreamHandler()])
    app.logger.setLevel(logging.INFO)

    # blueprints
    from .auth import bp as auth_bp
    from .public import bp as public_bp
    from .user import bp as user_bp
    from .admin import bp as admin_bp
    from .payments.pix import bp as pix_bp
    from .botvendas import bp as botvendas_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(public_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(pix_bp)
    app.register_blueprint(botvendas_bp)
    # retoma bots de clientes com assinatura ativa (nada em modo teste)
    try:
        from .botvendas import botruntime
        botruntime.retomar_todos(app)
    except Exception as e:
        app.logger.warning("retomar bots: %s", e)

    # ---------- sessao / usuario corrente ----------
    @app.before_request
    def load_user():
        g.user = session_user(request.cookies.get("tm_session"))
        g.csrf_token = csrf_token

    @app.before_request
    def lazy_expiry():
        """Expira promocoes e pagamentos vencidos a cada requisicao (barato e idempotente)."""
        t = now()
        execute("UPDATE promotions SET is_active = 0 WHERE is_active = 1 AND ends_at <= ?", (t,))
        execute("UPDATE payments SET status = 'expired' "
                 "WHERE status = 'pending' AND expires_at <= ?", (t,))

    @app.context_processor
    def inject_globals():
        cats = query("SELECT c.*, (SELECT COUNT(*) FROM telegram_groups tg "
                     "WHERE tg.category_id = c.id AND tg.status='approved') AS total "
                     "FROM categories c ORDER BY c.name")
        return dict(current_user=g.get("user"), categories=cats,
                    site_name=get_setting("site_name", "TELEMAX"),
                    site_tagline=get_setting("site_tagline",
                        "O diretório de grupos e canais do Telegram em português"),
                    csrf_token=g.get("csrf_token"))

    def get_setting(key, default=""):
        row = query("SELECT value FROM settings WHERE key = ?", (key,), one=True)
        return row["value"] if row else default
    app.jinja_env.globals["get_setting"] = get_setting

    # filtros utilitarios
    @app.template_filter("cents")
    def cents(v):
        try:
            return f"R$ {int(v)/100:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
        except Exception:
            return str(v)

    @app.template_filter("datebr")
    def datebr(v):
        if not v:
            return "-"
        return v[:10].split("-")[::-1] and "/".join(reversed(v[:10].split("-")))

    @app.errorhandler(404)
    def nf(e):
        return render_template("public/erro.html", code=404,
                               mensagem="Página não encontrada."), 404

    @app.errorhandler(403)
    def nf3(e):
        return render_template("public/erro.html", code=403,
                               mensagem="Você não tem permissão para acessar esta página."), 403

    @app.errorhandler(500)
    def err5(e):
        app.logger.exception("erro 500")
        return render_template("public/erro.html", code=500,
                               mensagem="Erro interno. Nossa equipe foi notificada."), 500

    return app
