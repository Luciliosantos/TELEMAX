"""Painel do usuário: conta, publicações, promoções, pagamentos."""
import math

from flask import (Blueprint, abort, flash, g, redirect, render_template, request, url_for)

from .db import query, execute
from .payments.pix import create_charge
from .security import (audit, csrf_ok, normalize_link, now, save_image, slugify,
                       unique_slug, valid_telegram_link, revoke_all_sessions,
                       hash_password, verify_password, valid_password, valid_email)

bp = Blueprint("user", __name__)

@bp.before_request
def require_login():
    if not g.get("user"):
        return redirect(url_for("auth.login", next=request.path))

@bp.route("/painel")
def dashboard():
    uid = g.user["id"]
    meus = query("SELECT tg.*, c.name AS category_name FROM telegram_groups tg "
                 "LEFT JOIN categories c ON c.id = tg.category_id WHERE tg.owner_id = ? "
                 "ORDER BY tg.created_at DESC", (uid,))
    promos = query("SELECT pr.*, tg.name AS group_name, pl.name AS plan_name, pl.days "
                   "FROM promotions pr JOIN telegram_groups tg ON tg.id = pr.group_id "
                   "LEFT JOIN plans pl ON pl.id = pr.plan_id "
                   "JOIN payments pay ON pay.id = pr.payment_id AND pay.user_id = ? "
                   "WHERE pr.is_active = 1 AND pr.ends_at > ? ORDER BY pr.ends_at", (uid, now()))
    pay_count = query("SELECT COUNT(*) AS n FROM payments WHERE user_id = ? AND status='paid'",
                      (uid,), one=True)["n"]
    return render_template("user/dashboard.html", meus=meus, promos=promos, pay_count=pay_count)

@bp.route("/painel/grupos")
def my_groups():
    rows = query("SELECT tg.*, c.name AS category_name FROM telegram_groups tg "
                 "LEFT JOIN categories c ON c.id = tg.category_id WHERE tg.owner_id = ? "
                 "ORDER BY tg.created_at DESC", (g.user["id"],))
    return render_template("user/grupos.html", rows=rows)

def _form_data():
    return dict(name=(request.form.get("name") or "").strip(),
                description=(request.form.get("description") or "").strip(),
                link=normalize_link(request.form.get("link") or ""),
                type=request.form.get("type") or "group",
                category_id=request.form.get("category_id", type=int),
                keywords=(request.form.get("keywords") or "").strip()[:200])

def _validate(d):
    if not (3 <= len(d["name"]) <= 100):
        return "Nome deve ter entre 3 e 100 caracteres."
    if len(d["description"]) < 10:
        return "A descrição deve ter pelo menos 10 caracteres."
    if not valid_telegram_link(d["link"]):
        return "Link inválido. Use https://t.me/nome_do_grupo (público)."
    if d["type"] not in ("group", "channel"):
        return "Tipo inválido."
    if not query("SELECT id FROM categories WHERE id = ?", (d["category_id"],), one=True):
        return "Categoria inválida."
    return None

@bp.route("/painel/grupos/novo", methods=["GET", "POST"])
def new_group():
    cats = query("SELECT * FROM categories ORDER BY name")
    if request.method == "POST":
        if not csrf_ok():
            return "CSRF inválido", 400
        d = _form_data()
        err = _validate(d)
        if not err and query("SELECT id FROM telegram_groups WHERE link = ?", (d["link"],), one=True):
            err = "Este link do Telegram já está publicado no TELEMAX."
        if err:
            flash(err, "erro")
            return render_template("user/grupo_form.html", d=d, cats=cats, editing=None)
        image = None
        if request.files.get("image"):
            image = save_image(request.files["image"], "group")
        auto = current_app_auto()
        status = "approved" if auto else "pending"
        gid = execute("INSERT INTO telegram_groups(slug, name, description, link, image_path, "
                      "category_id, type, keywords, owner_id, status, is_demo, created_at) "
                      "VALUES (?,?,?,?,?,?,?,? ,? ,?,0,?)",
                      (unique_slug(slugify(d["name"], "grupo"), "telegram_groups"),
                       d["name"], d["description"], d["link"], image,
                       d["category_id"], d["type"], d["keywords"],
                       g.user["id"], status, now()))
        if status == "approved":
            execute("UPDATE telegram_groups SET published_at = ? WHERE id = ?", (now(), gid))
        audit(g.user["id"], "create", "group", gid, ip=request.remote_addr)
        flash("Grupo enviado! " + ("Publicação criada." if status == "approved"
              else "Aguarde a aprovação da moderação."), "ok")
        return redirect(url_for("user.my_groups"))
    return render_template("user/grupo_form.html", d=None, cats=cats, editing=None)

def current_app_auto():
    from flask import current_app
    return current_app.config.get("AUTO_APPROVE", False)

@bp.route("/painel/grupos/<int:gid>/editar", methods=["GET", "POST"])
def edit_group(gid):
    row = query("SELECT * FROM telegram_groups WHERE id = ? AND owner_id = ?",
                (gid, g.user["id"]), one=True)
    if not row:
        abort(403)
    cats = query("SELECT * FROM categories ORDER BY name")
    if request.method == "POST":
        if not csrf_ok():
            return "CSRF inválido", 400
        d = _form_data()
        err = _validate(d)
        dup = query("SELECT id FROM telegram_groups WHERE link = ? AND id != ?", (d["link"], gid), one=True)
        if not err and dup:
            err = "Este link já está em outra publicação."
        if err:
            flash(err, "erro")
            return render_template("user/grupo_form.html", d=d, cats=cats, editing=row)
        image = row["image_path"]
        if request.files.get("image"):
            novo = save_image(request.files["image"], "group")
            if novo:
                image = novo
        reapprove = row["status"] == "approved"
        execute("UPDATE telegram_groups SET name=?, description=?, link=?, type=?, "
                "category_id=?, keywords=?, image_path=?, updated_at=? WHERE id=?",
                (d["name"], d["description"], d["link"], d["type"], d["category_id"],
                 d["keywords"], image, now(), gid))
        if reapprove:
            execute("UPDATE telegram_groups SET status='pending', published_at=NULL, updated_at=? "
                    "WHERE id=?", (now(), gid))
            flash("Alterações enviadas para nova revisão da moderação.", "ok")
        else:
            flash("Alterações salvas.", "ok")
        return redirect(url_for("user.my_groups"))
    d = dict(name=row["name"], description=row["description"], link=row["link"],
             type=row["type"], category_id=row["category_id"], keywords=row["keywords"])
    return render_template("user/grupo_form.html", d=d, cats=cats, editing=row)

# ---------------- promoções / pagamentos ----------------

@bp.route("/painel/promocoes")
def promotions_page():
    uid = g.user["id"]
    groups = query("SELECT id, name, status FROM telegram_groups WHERE owner_id = ? "
                   "ORDER BY name", (uid,))
    plans = query("SELECT * FROM plans WHERE is_active = 1 ORDER BY sort, days")
    pay = query("SELECT pay.*, tg.name AS group_name, pl.name AS plan_name, pl.days "
                "FROM payments pay LEFT JOIN telegram_groups tg ON tg.id = pay.group_id "
                "LEFT JOIN plans pl ON pl.id = pay.plan_id WHERE pay.user_id = ? "
                "ORDER BY pay.created_at DESC", (uid,))
    ativas = query("SELECT pr.*, tg.name AS group_name, pl.name AS plan_name "
                   "FROM promotions pr JOIN payments pay ON pay.id = pr.payment_id AND pay.user_id = ? "
                   "JOIN telegram_groups tg ON tg.id = pr.group_id "
                   "LEFT JOIN plans pl ON pl.id = pr.plan_id ORDER BY pr.is_active DESC, pr.ends_at DESC",
                   (uid,))
    return render_template("user/promocoes.html", groups=groups, plans=plans, pay=pay, ativas=ativas)

@bp.route("/painel/promocoes/contratar", methods=["POST"])
def hire():
    if not csrf_ok():
        return "CSRF inválido", 400
    gid = request.form.get("group_id", type=int)
    pid = request.form.get("plan_id", type=int)
    group = query("SELECT * FROM telegram_groups WHERE id = ? AND owner_id = ?",
                  (gid, g.user["id"]), one=True)
    plan = query("SELECT * FROM plans WHERE id = ? AND is_active = 1", (pid,), one=True)
    if not group or not plan:
        flash("Grupo ou plano inválido.", "erro")
        return redirect(url_for("user.promotions_page"))
    if group["status"] != "approved":
        flash("Apenas publicações aprovadas podem ser destacadas.", "erro")
        return redirect(url_for("user.promotions_page"))
    result = create_charge(g.user, group, plan)
    if not result or not result.get("ok"):
        flash("Não foi possível gerar a cobrança: " +
              (result.get("erro", "erro desconhecido") if result else "erro"), "erro")
        return redirect(url_for("user.promotions_page"))
    return redirect(url_for("user.payment_page", pay_id=result["payment_id"]))

@bp.route("/painel/pagamento/<int:pay_id>")
def payment_page(pay_id):
    pay = query("SELECT pay.*, tg.name AS group_name, tg.slug AS group_slug, "
                "pl.name AS plan_name, pl.days FROM payments pay "
                "LEFT JOIN telegram_groups tg ON tg.id = pay.group_id "
                "LEFT JOIN plans pl ON pl.id = pay.plan_id "
                "WHERE pay.id = ? AND pay.user_id = ?", (pay_id, g.user["id"]), one=True)
    if not pay:
        abort(403)
    promo = query("SELECT * FROM promotions WHERE payment_id = ?", (pay_id,), one=True)
    return render_template("user/pagamento.html", pay=pay, promo=promo)

@bp.route("/painel/pagamentos")
def payments_history():
    rows = query("SELECT pay.*, tg.name AS group_name, pl.name AS plan_name FROM payments pay "
                 "LEFT JOIN telegram_groups tg ON tg.id = pay.group_id "
                 "LEFT JOIN plans pl ON pl.id = pay.plan_id "
                 "WHERE pay.user_id = ? ORDER BY pay.created_at DESC", (g.user["id"],))
    return render_template("user/pagamentos.html", rows=rows)

# ---------------- conta ----------------

@bp.route("/painel/conta", methods=["GET", "POST"])
def account():
    if request.method == "POST":
        if not csrf_ok():
            return "CSRF inválido", 400
        nick = (request.form.get("nickname") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        if not valid_email(email):
            flash("E-mail inválido.", "erro")
        elif query("SELECT id FROM users WHERE email = ? AND id != ?", (email, g.user["id"]), one=True):
            flash("E-mail já usado por outra conta.", "erro")
        else:
            execute("UPDATE users SET nickname = ?, email = ?, updated_at = ? WHERE id = ?",
                    (nick, email, now(), g.user["id"]))
            flash("Dados atualizados.", "ok")
        return redirect(url_for("user.account"))
    return render_template("user/conta.html")

@bp.route("/painel/senha", methods=["POST"])
def change_password():
    if not csrf_ok():
        return "CSRF inválido", 400
    cur = request.form.get("current") or ""
    pw = request.form.get("password") or ""
    pw2 = request.form.get("password2") or ""
    if not verify_password(cur, g.user["password_hash"]):
        flash("Senha atual incorreta.", "erro")
    elif not valid_password(pw):
        flash("A nova senha deve ter ao menos 8 caracteres, com letras e números.", "erro")
    elif pw != pw2:
        flash("As senhas não conferem.", "erro")
    else:
        execute("UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
                (hash_password(pw), now(), g.user["id"]))
        revoke_all_sessions(g.user["id"])
        audit(g.user["id"], "change_password", "user", g.user["id"])
        flash("Senha alterada. Faça login novamente.", "ok")
        return redirect(url_for("auth.login"))
    return redirect(url_for("user.account"))
