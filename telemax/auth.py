"""Autenticacao: cadastro, login, logout, recuperacao de senha."""
from datetime import datetime, timedelta, timezone

from flask import (Blueprint, current_app, flash, g, make_response, redirect,
                   render_template, request, url_for)

from .db import query, execute
from .emailer import send_email
from .security import (account_locked, audit, csrf_ok, hash_password, login_blocked,
                       new_token, now, record_login_attempt, register_failed_login,
                       revoke_all_sessions, revoke_session, sha256, valid_email,
                       valid_nickname, valid_password, verify_password)

bp = Blueprint("auth", __name__)

def _finish_login(user):
    token = None
    from .security import create_session
    token = create_session(user["id"], request.remote_addr, request.user_agent.string)
    execute("UPDATE users SET updated_at = ? WHERE id = ?", (now(), user["id"]))
    resp = make_response(redirect(url_for("user.dashboard")))
    resp.set_cookie("tm_session", token, httponly=True, samesite="Lax",
                    max_age=int(current_app.config["SESSION_LIFETIME_HOURS"]) * 3600,
                    secure=current_app.config["IS_PROD"])
    return resp

@bp.route("/cadastro", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("user.dashboard"))
    if request.method == "POST":
        if not csrf_ok():
            return "CSRF inválido", 400
        nick = (request.form.get("nickname") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        pw = request.form.get("password") or ""
        pw2 = request.form.get("password2") or ""
        err = None
        if not valid_nickname(nick):
            err = "Apelido inválido (3 a 30 caracteres; letras, números, ponto, hífen ou underline)."
        elif not valid_email(email):
            err = "E-mail inválido."
        elif not valid_password(pw):
            err = "A senha deve ter ao menos 8 caracteres, com letras e números."
        elif pw != pw2:
            err = "As senhas não conferem."
        elif query("SELECT id FROM users WHERE nickname = ?", (nick,), one=True):
            err = "Este apelido já está em uso."
        elif query("SELECT id FROM users WHERE email = ?", (email,), one=True):
            err = "Este e-mail já está cadastrado."
        if err:
            flash(err, "erro")
            return render_template("auth/cadastro.html", nickname=nick, email=email)
        uid = execute("INSERT INTO users(nickname, email, password_hash, role, created_at) "
                      "VALUES (?,?,?,'user',?)", (nick, email, hash_password(pw), now()))
        audit(uid, "register", "user", uid, ip=request.remote_addr)
        send_email(email, "Bem-vindo ao TELEMAX",
                   f"Olá {nick},\n\nSua conta no TELEMAX foi criada com sucesso!")
        flash("Conta criada com sucesso! Faça login.", "ok")
        return redirect(url_for("auth.login"))
    return render_template("auth/cadastro.html", nickname="", email="")

@bp.route("/entrar", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("user.dashboard"))
    if request.method == "POST":
        if not csrf_ok():
            return "CSRF inválido", 400
        email = (request.form.get("email") or "").strip().lower()
        pw = request.form.get("password") or ""
        if login_blocked(request.remote_addr, email):
            current_app.logger.warning("login bloqueado por tentativas excessivas ip=%s", request.remote_addr)
            flash("Muitas tentativas. Aguarde 15 minutos.", "erro")
            return render_template("auth/login.html", email=email)
        user = query("SELECT * FROM users WHERE email = ?", (email,), one=True)
        if user and account_locked(user):
            flash("Conta temporariamente bloqueada por tentativas incorretas. Tente em alguns minutos.", "erro")
            return render_template("auth/login.html", email=email)
        if user and user["is_active"] and verify_password(pw, user["password_hash"]):
            record_login_attempt(request.remote_addr, email, True)
            audit(user["id"], "login", "user", user["id"], ip=request.remote_addr)
            return _finish_login(user)
        if user:
            register_failed_login(user)
        record_login_attempt(request.remote_addr, email, False)
        flash("E-mail ou senha incorretos.", "erro")
        return render_template("auth/login.html", email=email)
    return render_template("auth/login.html", email="")

@bp.route("/sair")
def logout():
    revoke_session(request.cookies.get("tm_session"))
    resp = make_response(redirect(url_for("public.index")))
    resp.delete_cookie("tm_session")
    flash("Você saiu da sua conta.", "ok")
    return resp

@bp.route("/recuperar", methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        if not csrf_ok():
            return "CSRF inválido", 400
        email = (request.form.get("email") or "").strip().lower()
        user = query("SELECT * FROM users WHERE email = ?", (email,), one=True)
        # resposta neutra: nao revela se o e-mail existe
        if user and user["is_active"]:
            token = new_token(24)
            expires = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
            execute("INSERT INTO password_resets(user_id, token_hash, expires_at) VALUES (?,?,?)",
                    (user["id"], sha256(token), expires))
            link = current_app.config["BASE_URL"] + url_for("auth.reset", token=token)
            send_email(email, "Redefinição de senha TELEMAX",
                       "Redefina sua senha neste link (válido por 1 hora):\n" + link +
                       "\n\nSe não solicitou, ignore este e-mail.")
        flash("Se o e-mail estiver cadastrado, você receberá as instruções.", "ok")
        return redirect(url_for("auth.login"))
    return render_template("auth/recuperar.html")

@bp.route("/redefinir/<token>", methods=["GET", "POST"])
def reset(token):
    row = query("SELECT * FROM password_resets WHERE token_hash = ?", (sha256(token),), one=True)
    if not row or row["used_at"] or row["expires_at"] <= now():
        flash("Link inválido ou expirado. Solicite novamente.", "erro")
        return redirect(url_for("auth.forgot"))
    user = query("SELECT * FROM users WHERE id = ?", (row["user_id"],), one=True)
    if not user or not user["is_active"]:
        flash("Conta indisponível.", "erro")
        return redirect(url_for("auth.login"))
    if request.method == "POST":
        if not csrf_ok():
            return "CSRF inválido", 400
        pw = request.form.get("password") or ""
        pw2 = request.form.get("password2") or ""
        if not valid_password(pw):
            flash("A senha deve ter ao menos 8 caracteres, com letras e números.", "erro")
            return render_template("auth/redefinir.html", token=token)
        if pw != pw2:
            flash("As senhas não conferem.", "erro")
            return render_template("auth/redefinir.html", token=token)
        execute("UPDATE users SET password_hash = ?, failed_logins = 0, locked_until = NULL, "
                "updated_at = ? WHERE id = ?", (hash_password(pw), now(), user["id"]))
        execute("UPDATE password_resets SET used_at = ? WHERE id = ?", (now(), row["id"]))
        revoke_all_sessions(user["id"])
        audit(user["id"], "reset_password", "user", user["id"], ip=request.remote_addr)
        flash("Senha redefinida. Faça login com a nova senha.", "ok")
        return redirect(url_for("auth.login"))
    return render_template("auth/redefinir.html", token=token)
