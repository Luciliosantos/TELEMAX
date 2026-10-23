"""Rotas públicas: home, categorias, grupos, busca, páginas institucionais, SEO."""
import math

from flask import (Blueprint, Response, abort, g, redirect, render_template,
                   request, url_for)

from .db import query, execute
from .security import csrf_ok, now

bp = Blueprint("public", __name__)

def _banners():
    return query("SELECT * FROM banners WHERE is_active = 1 ORDER BY id DESC")

def _sponsored_ids():
    return [r["group_id"] for r in
            query("SELECT group_id FROM promotions WHERE is_active = 1 AND ends_at > ?", (now(),))]

def _listing(page, category_slug=None, q="", type_filter=""):
    per = 12
    page = max(1, page)
    args, where = [], ["tg.status = 'approved'"]
    joins = "FROM telegram_groups tg LEFT JOIN categories c ON c.id = tg.category_id"
    if category_slug:
        where.append("c.slug = ?")
        args.append(category_slug)
    if type_filter in ("group", "channel"):
        where.append("tg.type = ?")
        args.append(type_filter)
    if q:
        like = f"%{q.replace('%','')}%"
        where.append("(tg.name LIKE ? OR tg.description LIKE ? OR tg.keywords LIKE ? OR c.name LIKE ?)")
        args += [like, like, like, like]
    w = " AND ".join(where)
    total = query(f"SELECT COUNT(*) AS n {joins} WHERE {w}", args, one=True)["n"]
    rows = query(
        f"SELECT tg.*, c.name AS category_name, c.slug AS category_slug {joins} WHERE {w} "
        "ORDER BY tg.published_at DESC, tg.id DESC LIMIT ? OFFSET ?",
        args + [per, (page - 1) * per])
    sponsored = set(_sponsored_ids())
    return rows, total, per, sponsored

def _group_ctx(row):
    return dict(sponsored=row["id"] in set(_sponsored_ids()))

@bp.route("/")
def index():
    featured = query(
        "SELECT tg.*, c.name AS category_name, c.slug AS category_slug "
        "FROM telegram_groups tg JOIN promotions p ON p.group_id = tg.id AND p.is_active = 1 "
        "LEFT JOIN categories c ON c.id = tg.category_id "
        "WHERE tg.status='approved' AND p.ends_at > ? "
        "GROUP BY tg.id ORDER BY p.ends_at DESC LIMIT 8", (now(),))
    recent = query(
        "SELECT tg.*, c.name AS category_name, c.slug AS category_slug "
        "FROM telegram_groups tg LEFT JOIN categories c ON c.id = tg.category_id "
        "WHERE tg.status='approved' ORDER BY tg.published_at DESC LIMIT 8")
    popular = query(
        "SELECT tg.*, c.name AS category_name, c.slug AS category_slug "
        "FROM telegram_groups tg LEFT JOIN categories c ON c.id = tg.category_id "
        "WHERE tg.status='approved' ORDER BY tg.views DESC, tg.published_at DESC LIMIT 8")
    return render_template("public/index.html", featured=featured, recent=recent,
                           popular=popular, banners=_banners())

@bp.route("/categorias/<slug>")
def category(slug):
    cat = query("SELECT * FROM categories WHERE slug = ?", (slug,), one=True)
    if not cat:
        abort(404)
    page = request.args.get("page", 1, type=int)
    rows, total, per, sponsored = _listing(page, category_slug=slug)
    return render_template("public/categoria.html", cat=cat, rows=rows, total=total,
                           page=page, pages=math.ceil(total / per), sponsored=sponsored)

@bp.route("/grupos/<slug>")
def group(slug):
    row = query("SELECT tg.*, c.name AS category_name, c.slug AS category_slug "
                "FROM telegram_groups tg LEFT JOIN categories c ON c.id = tg.category_id "
                "WHERE tg.slug = ? AND tg.status = 'approved'", (slug,), one=True)
    if not row:
        abort(404)
    execute("UPDATE telegram_groups SET views = views + 1 WHERE id = ?", (row["id"],))
    related = query("SELECT tg.*, c.name AS category_name, c.slug AS category_slug "
                    "FROM telegram_groups tg LEFT JOIN categories c ON c.id = tg.category_id "
                    "WHERE tg.status='approved' AND tg.category_id = ? AND tg.id != ? "
                    "ORDER BY tg.views DESC LIMIT 4", (row["category_id"], row["id"]))
    return render_template("public/grupo.html", g_=row, sponsored=row["id"] in set(_sponsored_ids()),
                           related=related, banners=_banners())

@bp.route("/busca")
def search():
    q = (request.args.get("q") or "").strip()[:100]
    type_f = request.args.get("tipo", "")
    page = request.args.get("page", 1, type=int)
    rows, total, per, sponsored = _listing(page, q=q, type_filter=type_f)
    return render_template("public/busca.html", q=q, rows=rows, total=total,
                           page=page, pages=math.ceil(total / per) if total else 0,
                           sponsored=sponsored, tipo=type_f)

@bp.route("/sobre")
def about():
    return render_template("public/sobre.html")

@bp.route("/termos")
def terms():
    return render_template("public/termos.html")

@bp.route("/privacidade")
def privacy():
    return render_template("public/privacidade.html")

@bp.route("/contato", methods=["GET", "POST"])
def contact():
    sent = False
    if request.method == "POST":
        if not csrf_ok():
            return "CSRF inválido", 400
        name = (request.form.get("name") or "").strip()[:100]
        email = (request.form.get("email") or "").strip()[:200]
        message = (request.form.get("message") or "").strip()[:3000]
        if len(name) >= 2 and "@" in email and len(message) >= 10:
            from .security import audit
            execute("INSERT INTO contact_messages(name, email, message, created_at) VALUES (?,?,?,?)",
                    (name, email, message, now()))
            sent = True
        else:
            from flask import flash
            flash("Preencha todos os campos corretamente.", "erro")
    return render_template("public/contato.html", sent=sent)

@bp.route("/uploads/<path:filename>")
def upload(filename):
    """Serve uploads apenas de dentro da pasta, com nome validado."""
    import os
    from flask import current_app, send_from_directory
    safe = os.path.normpath(filename).replace("\\", "/")
    if safe.startswith("..") or "/" in safe and ".." in safe.split("/"):
        abort(404)
    folder = os.path.join(current_app.instance_path, "uploads")
    return send_from_directory(folder, safe)

@bp.route("/banner/<int:bid>")
def banner_click(bid):
    row = query("SELECT * FROM banners WHERE id = ? AND is_active = 1", (bid,), one=True)
    if not row or not row["link"].startswith(("http://", "https://")):
        abort(404)
    execute("UPDATE banners SET clicks = clicks + 1 WHERE id = ?", (bid,))
    return redirect(row["link"])

# ---------------- SEO ----------------

@bp.route("/sitemap.xml")
def sitemap():
    parts = ['<?xml version="1.0" encoding="UTF-8"?>',
             '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']
    base = request.host_url.rstrip("/")
    def add(loc, changefreq="weekly", priority="0.6"):
        parts.append(f"<url><loc>{loc}</loc><changefreq>{changefreq}</changefreq><priority>{priority}</priority></url>")
    add(base + "/", "daily", "1.0")
    add(base + "/sobre", "monthly", "0.3")
    add(base + "/termos", "yearly", "0.2")
    add(base + "/privacidade", "yearly", "0.2")
    add(base + "/contato", "monthly", "0.3")
    for c in query("SELECT slug FROM categories ORDER BY name"):
        add(base + "/categorias/" + c["slug"])
    for tg in query("SELECT slug, updated_at FROM telegram_groups "
                    "WHERE status='approved' ORDER BY published_at DESC LIMIT 2000"):
        lastmod = (tg["updated_at"] or "")[:10]
        tag = f"<lastmod>{lastmod}</lastmod>" if lastmod else ""
        parts.append(f"<url><loc>{base}/grupos/{tg['slug']}</loc>{tag}"
                     f"<changefreq>weekly</changefreq><priority>0.7</priority></url>")
    parts.append("</urlset>")
    return Response("\n".join(parts), mimetype="application/xml")

@bp.route("/robots.txt")
def robots():
    lines = ["User-agent: *",
             "Allow: /",
             "Disallow: /painel",
             "Disallow: /admin",
             "Disallow: /entrar",
             "Disallow: /cadastro",
             "Disallow: /recuperar",
             "Disallow: /redefinir",
             "Disallow: /webhook",
             f"Sitemap: {request.host_url.rstrip('/')} /sitemap.xml".replace(" /", "/")]
    return Response("\n".join(lines), mimetype="text/plain")
