"""Helpers de seguranca: senha, sessao, CSRF, rate-limit, slug, upload."""
import hashlib
import hmac
import os
import re
import secrets
import time
import unicodedata
from datetime import datetime, timedelta, timezone

from werkzeug.security import check_password_hash, generate_password_hash

from .db import query, execute

def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

def hash_password(pw):
    return generate_password_hash(pw, method="scrypt")

def verify_password(pw, h):
    try:
        return check_password_hash(h, pw)
    except Exception:
        return False

def sha256(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def hmac_sign(secret, payload: bytes):
    return hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()

def hmac_verify(secret, payload: bytes, signature: str):
    if not signature:
        return False
    return hmac.compare_digest(hmac_sign(secret, payload), signature.strip().lower())

def new_token(nbytes=32):
    return secrets.token_urlsafe(nbytes)

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$")

def valid_email(e):
    return bool(e) and len(e) <= 254 and EMAIL_RE.match(e)

def valid_nickname(n):
    return bool(n) and 3 <= len(n) <= 30 and re.match(r"^[a-zA-Z0-9_.-]+$", n)

def valid_password(p):
    return bool(p) and len(p) >= 8 and re.search(r"[a-zA-Z]", p) and re.search(r"[0-9]", p)

TELEGRAM_LINK_RE = re.compile(
    r"^https?://(?:t\.me|telegram\.me|telegram\.dog)/"
    r"(?:[A-Za-z0-9_]{4,64}|\+[A-Za-z0-9_-]{4,128}|joinchat/[A-Za-z0-9_-]{4,128})/?$",
    re.I
)

def valid_telegram_link(link):
    if not link:
        return False
    return bool(TELEGRAM_LINK_RE.fullmatch(link.strip()))

def normalize_link(link):
    link = (link or "").strip()
    link = re.sub(
        r"^https?://(?:telegram\.me|telegram\.dog)/",
        "https://t.me/", link, flags=re.I
    )
    link = re.sub(r"[?#].*$", "", link)
    if re.match(r"^https?://t\.me/(?:\+|joinchat/)", link, flags=re.I):
        return link.rstrip("/")
    return link.rstrip("/").lower()

def slugify(text, fallback="item"):
    text = unicodedata.normalize("NFKD", (text or "").encode("ascii", "ignore").decode("ascii"))
    text = re.sub(r"[^a-zA-Z0-9]+", "-", text).strip("-").lower()
    return text[:80] or fallback

def unique_slug(base, table, exclude_id=None):
    slug, i = base, 2
    while True:
        if exclude_id is not None:
            row = query(f"SELECT id FROM {table} WHERE slug = ? AND id != ?", (slug, exclude_id), one=True)
        else:
            row = query(f"SELECT id FROM {table} WHERE slug = ?", (slug,), one=True)
        if not row:
            return slug
        slug = f"{base}-{i}"
        i += 1

# ---------------- sessoes (server-side) ----------------

def create_session(user_id, ip, ua):
    token = new_token()
    expires = (datetime.now(timezone.utc) +
               timedelta(hours=int(_cfg("SESSION_LIFETIME_HOURS", "168")))).strftime("%Y-%m-%d %H:%M:%S")
    execute("INSERT INTO user_sessions(token_hash, user_id, ip, user_agent, created_at, expires_at) "
            "VALUES (?,?,?,?,?,?)",
            (sha256(token), user_id, ip or "", (ua or "")[:200], now(), expires))
    return token

def session_user(token):
    if not token:
        return None
    row = query("SELECT * FROM user_sessions WHERE token_hash = ?", (sha256(token),), one=True)
    if not row:
        return None
    if row["revoked_at"] or (row["expires_at"] or "") < now():
        return None
    return query("SELECT * FROM users WHERE id = ? AND is_active = 1", (row["user_id"],), one=True)

def revoke_session(token):
    if token:
        execute("UPDATE user_sessions SET revoked_at = ? WHERE token_hash = ?",
                (now(), sha256(token)))

def revoke_all_sessions(user_id):
    execute("UPDATE user_sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
            (now(), user_id))

def _cfg(key, default):
    from flask import current_app
    try:
        return current_app.config.get(key, default)
    except RuntimeError:
        return default

# ---------------- protecao contra forca bruta ----------------

def login_blocked(ip, email):
    """Bloqueia por IP+email em janela de 15 minutos."""
    since = (datetime.now(timezone.utc) - timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M:%S")
    n = query("SELECT COUNT(*) AS n FROM login_attempts WHERE ip = ? AND email = ? AND ts > ?",
              (ip or "", (email or "").lower(), since), one=True)["n"]
    return n >= int(_cfg("LOGIN_MAX_ATTEMPTS", "10"))

def record_login_attempt(ip, email, ok):
    execute("INSERT INTO login_attempts(ip, email, ok, ts) VALUES (?,?,?,?)",
            (ip or "", (email or "").lower(), 1 if ok else 0, now()))
    if ok:
        execute("UPDATE users SET failed_logins = 0, locked_until = NULL WHERE email = ?",
               ((email or "").lower(),))

def account_locked(user):
    return bool(user and user["locked_until"] and user["locked_until"] > now())

def register_failed_login(user):
    fails = (user["failed_logins"] or 0) + 1
    if fails >= 10:
        until = (datetime.now(timezone.utc) +
                 timedelta(minutes=int(15))).strftime("%Y-%m-%d %H:%M:%S")
        execute("UPDATE users SET failed_logins = ?, locked_until = ? WHERE id = ?",
                (fails, until, user["id"]))
    else:
        execute("UPDATE users SET failed_logins = ? WHERE id = ?", (fails, user["id"]))

# ---------------- CSRF ----------------

def csrf_token():
    from flask import session
    if "_csrf" not in session:
        session["_csrf"] = new_token(16)
    return session["_csrf"]

def csrf_ok():
    from flask import request, session
    sent = request.form.get("_csrf", request.headers.get("X-CSRF-Token", ""))
    return bool(sent) and hmac.compare_digest(sent, session.get("_csrf", ""))

# ---------------- uploads ----------------

ALLOWED = {b"\xff\xd8\xff": "jpg", b"\x89PNG": "png", b"RIFF": "webp"}

def save_image(stream, kind):
    """Valida magic bytes + tamanho e grava com nome aleatorio. Retorna nome ou None."""
    data = stream.read()
    if not data or len(data) > int(_cfg("MAX_UPLOAD_BYTES", "2097152")):
        return None
    ext = None
    for magic, e in ALLOWED.items():
        if data.startswith(magic):
            if e == "webp" and data[8:12] != b"WEBP":
                continue
            ext = e
            break
    if not ext:
        return None
    name = f"{kind}_{new_token(12)}.{ext}"
    from flask import current_app
    folder = os.path.join(current_app.instance_path, "uploads")
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(folder, name), "wb") as fh:
        fh.write(data)
    return name

def audit(actor_id, action, entity, entity_id, details="", ip=""):
    execute("INSERT INTO audit_log(actor_id, action, entity, entity_id, details, ip, created_at) "
            "VALUES (?,?,?,?,?,?,?)", (actor_id, action, entity, entity_id, details, ip or "", now()))
