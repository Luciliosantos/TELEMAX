import os

def _bool(v, default=False):
    if v is None:
        return default
    return v.lower() in ("1", "true", "yes", "on")

class Config:
    ENV = os.environ.get("FLASK_ENV", "development")
    IS_PROD = ENV == "production"
    SECRET_KEY = os.environ.get("SECRET_KEY", "telemax-dev-insecure-key")
    BASE_URL = os.environ.get("BASE_URL", "http://localhost:5000")
    DATABASE_PATH = os.environ.get("DATABASE_PATH", os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "instance", "telemax.db"))
    SESSION_LIFETIME_HOURS = int(os.environ.get("SESSION_LIFETIME_HOURS", "168"))
    MAX_UPLOAD_BYTES = int(os.environ.get("MAX_UPLOAD_BYTES", str(2 * 1024 * 1024)))
    PIX_PROVIDER = os.environ.get("PIX_PROVIDER", "demo")
    PIX_WEBHOOK_SECRET = os.environ.get("PIX_WEBHOOK_SECRET", "dev-webhook-secret")
    MERCADOPAGO_ACCESS_TOKEN = os.environ.get("MERCADOPAGO_ACCESS_TOKEN", "")
    MERCADOPAGO_WEBHOOK_SECRET = os.environ.get("MERCADOPAGO_WEBHOOK_SECRET", "")
    EMAIL_BACKEND = os.environ.get("EMAIL_BACKEND", "console")
    SMTP_HOST = os.environ.get("SMTP_HOST", "")
    SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
    SMTP_USER = os.environ.get("SMTP_USER", "")
    SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
    EMAIL_FROM = os.environ.get("EMAIL_FROM", "contato@telemax.lsnet.shop")
    # moderacao
    AUTO_APPROVE = _bool(os.environ.get("AUTO_APPROVE"), False)
    PER_PAGE_DEFAULT = 12
    LOGIN_MAX_ATTEMPTS = 10          # por IP+email em 15 min
    ACCOUNT_LOCK_MINUTES = 15       # apos N falhas na conta
