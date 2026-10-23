"""Administração dos planos/assinaturas do módulo Bot Vendas VPN (só admins)."""
from flask import abort, flash, redirect, render_template, request, url_for

from ..db import execute, query
from ..security import now
from . import bp
from .helpers import admin_required, bv_audit


@bp.route("/admin")
@admin_required
def bv_admin():
    stats = {}
    for st in ("ativa", "pendente", "expirada", "cancelada", "suspensa"):
        stats[st] = query("SELECT COUNT(*) n FROM bv_subscriptions WHERE status=?",
                          (st,), one=True)["n"]
    receita = query("SELECT COALESCE(SUM(amount_cents),0) t FROM payments "
                    "WHERE purpose='bv_sub' AND status='paid'", one=True)["t"]
    planos = query("SELECT p.*, (SELECT COUNT(*) FROM bv_subscriptions s "
                   "WHERE s.plan_id=p.id AND s.status='ativa') ativos FROM bv_plans p "
                   "ORDER BY p.sort, p.price_cents")
    return render_template("botvendas/admin.html", stats=stats, receita=receita,
                          planos=planos)


@bp.route("/admin/planos/salvar", methods=["POST"])
@admin_required
def admin_plano_salvar():
    try:
        preco = int(float(request.form.get("price", "0").replace(",", ".")) * 100)
        dias = int(request.form.get("days", "30"))
        limite = int(request.form.get("max_vpn_plans", "3"))
    except ValueError:
        flash("Valores inválidos.", "erro")
        return redirect(url_for_bv())
    nome = (request.form.get("name") or "").strip()[:80]
    if not nome or preco < 0 or dias <= 0:
        flash("Preencha nome, preço e duração.", "erro")
        return redirect(url_for_bv())
    desc = (request.form.get("description") or "").strip()[:500]
    feats = (request.form.get("features") or "").strip()[:500]
    pid = request.form.get("id")
    if pid:
        execute("UPDATE bv_plans SET name=?, description=?, price_cents=?, days=?, "
                "max_vpn_plans=?, features=?, is_active=?, updated_at=? WHERE id=?",
                (nome, desc, preco, dias, max(1, limite), feats,
                 1 if request.form.get("is_active") else 0, now(), pid))
        flash("Plano atualizado (sem tocar em código).", "ok")
    else:
        execute("INSERT INTO bv_plans(name, description, price_cents, days, "
                "max_vpn_plans, features, is_active, sort, created_at, updated_at) "
                "VALUES (?,?,?,?,?,?,1,0,?,?)",
                (nome, desc, preco, dias, max(1, limite), feats, now(), now()))
        flash("Plano criado.", "ok")
    bv_audit(None, "admin_plan_saved", f"name={nome}")
    return redirect(url_for_bv())


def url_for_bv():
    from flask import url_for
    return url_for("botvendas.bv_admin")


@bp.route("/admin/planos/<int:pid>/toggle", methods=["POST"])
@admin_required
def admin_plano_toggle(pid):
    execute("UPDATE bv_plans SET is_active=1-is_active, updated_at=? WHERE id=?",
            (now(), pid))
    flash("Plano atualizado.", "ok")
    return redirect(url_for_bv())


@bp.route("/admin/planos/<int:pid>/remover", methods=["POST"])
@admin_required
def admin_plano_remover(pid):
    tem = query("SELECT COUNT(*) n FROM bv_subscriptions WHERE plan_id=?",
                (pid,), one=True)["n"]
    if tem:
        flash("Plano possui assinaturas no histórico: desative em vez de remover.", "erro")
        return redirect(url_for_bv())
    execute("DELETE FROM bv_plans WHERE id=?", (pid,))
    flash("Plano removido da oferta.", "ok")
    return redirect(url_for_bv())


@bp.route("/admin/assinaturas")
@admin_required
def admin_assinaturas():
    st = request.args.get("status", "")
    where, args = "", ()
    if st in ("ativa", "pendente", "expirada", "cancelada", "suspensa"):
        where, args = "WHERE s.status=?", (st,)
    subs = query(
        "SELECT s.*, p.name AS plano, u.email, u.nickname FROM bv_subscriptions s "
        "JOIN bv_plans p ON p.id=s.plan_id JOIN users u ON u.id=s.user_id "
        f"{where} ORDER BY s.id DESC LIMIT 300", args)
    return render_template("botvendas/admin_subs.html", subs=subs, filtro=st)


@bp.route("/admin/assinaturas/<int:sid>/acao", methods=["POST"])
@admin_required
def admin_sub_acao(sid):
    sub = query("SELECT * FROM bv_subscriptions WHERE id=?", (sid,), one=True)
    if not sub:
        abort(404)
    op = request.form.get("op")
    motivo = (request.form.get("motivo") or "").strip()[:300]
    if op == "suspender":
        execute("UPDATE bv_subscriptions SET status='suspensa', suspend_reason=?, "
                "updated_at=? WHERE id=?", (motivo or "motivo não informado", now(), sid))
        bv_audit(sub["user_id"], "subscription_suspended", motivo)
        flash("Assinatura suspensa.", "ok")
    elif op == "reativar":
        execute("UPDATE bv_subscriptions SET status='ativa', suspend_reason=NULL, "
                "updated_at=? WHERE id=? AND ends_at > ?", (now(), sid, now()))
        flash("Assinatura reativada (se ainda dentro da validade).", "ok")
    elif op == "cancelar":
        execute("UPDATE bv_subscriptions SET status='cancelada', cancel_reason=?, "
                "updated_at=? WHERE id=?", (motivo or "a pedido", now(), sid))
        bv_audit(sub["user_id"], "subscription_cancelled", motivo)
        flash("Assinatura cancelada.", "ok")
    return redirect(url_for("botvendas.admin_assinaturas"))


@bp.route("/admin/pagamentos")
@admin_required
def admin_pagamentos():
    pags = query("SELECT p.*, u.email FROM payments p LEFT JOIN users u ON u.id=p.user_id "
                 "WHERE p.purpose='bv_sub' ORDER BY p.id DESC LIMIT 300")
    return render_template("botvendas/admin_pays.html", pags=pags)
