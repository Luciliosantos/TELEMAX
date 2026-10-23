"""Estado de assinatura, guarda de acesso e auditoria do módulo."""
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import abort, current_app, g, redirect, request, url_for

from ..db import execute, get_db, query
from ..security import audit, now

ESTADOS = ("ativa", "pendente", "expirada", "cancelada", "suspensa")


def bv_audit(user_id, action, detail=""):
    """Auditoria do módulo — NUNCA registra segredos, só o fato."""
    execute("INSERT INTO bv_audit(user_id, action, detail, ts) VALUES (?,?,?,?)",
            (user_id, action, detail[:500], now()))


def expirar_assinaturas():
    """Expiração automática (lazy, idempotente) — nunca confia só na tela."""
    execute("UPDATE bv_subscriptions SET status='expirada', updated_at=? "
            "WHERE status='ativa' AND ends_at <= ?", (now(), now()))


def assinatura_ativa(user_id):
    expirar_assinaturas()
    return query(
        "SELECT s.*, p.name AS plan_name, p.max_vpn_plans "
        "FROM bv_subscriptions s JOIN bv_plans p ON p.id = s.plan_id "
        "WHERE s.user_id=? AND s.status='ativa' AND s.ends_at > ? "
        "ORDER BY s.ends_at DESC LIMIT 1", (user_id, now()), one=True)


def config_do_cliente(user_id):
    """1 linha de configuração por usuário TELEMAX (cria se não existir)."""
    cfg = query("SELECT * FROM bv_client_config WHERE user_id=?", (user_id,), one=True)
    if cfg:
        return cfg
    execute("INSERT INTO bv_client_config(user_id, link_code, created_at, updated_at) "
            "VALUES (?,?,?,?)", (user_id, "TM" + secrets.token_hex(6), now(), now()))
    return query("SELECT * FROM bv_client_config WHERE user_id=?", (user_id,), one=True)


def plano_por_id(plan_id):
    return query("SELECT * FROM bv_plans WHERE id=?", (plan_id,), one=True)


def expirar_contas_vencidas(user_id):
    """Revoga contas SSH entregues cuja validade passou (execução remota).

    Só conecta se o dono confirmou o fingerprint da VPS. Falha de conexão NÃO
    derruba a página: as contas seguem 'delivered' e serão tentadas depois.
    """
    from .sshops import RemoteVPS, ErroSSH
    from .botruntime import _cfg_vps
    vencidas = query(
        "SELECT * FROM bv_sales WHERE user_id=? AND status='delivered' "
        "AND ssh_expires_at IS NOT NULL AND ssh_expires_at <= ?",
        (user_id, now()))
    if not vencidas:
        return 0
    cfg = config_do_cliente(user_id)
    if not cfg["vps_fingerprint"] or not cfg["vps_fp_confirmed_at"]:
        return 0
    try:
        vps = RemoteVPS(_cfg_vps(cfg))
    except ErroSSH:
        return 0
    n = 0
    for v in vencidas:
        if vps.remover_conta(v["ssh_user"]):
            execute("UPDATE bv_sales SET status='expired', updated_at=? WHERE id=?",
                    (now(), v["id"]))
            n += 1
    return n


def ativar_assinatura(payment_id):
    """Ativa/renova a assinatura do módulo a partir de um payment confirmado.

    Mesma disciplina transacional do destaque: reivindicação do pagamento +
    escritura da assinatura em UMA transação. Falha → rollback, pagamento
    volta a pending e o webhook pode tentar de novo. Renovação soma dias na
    assinatura ativa; idempotente via UPDATE condicional + unique idempotency.
    """
    pay = query("SELECT * FROM payments WHERE id=?", (payment_id,), one=True)
    if not pay or pay["purpose"] != "bv_sub":
        return False
    plan = query("SELECT * FROM bv_plans WHERE id=?", (pay["target_id"],), one=True)
    if not plan:
        execute("UPDATE payments SET status='cancelled' WHERE id=?", (pay["id"],))
        return False
    # a cobrança paga tem de ser EXATAMENTE a do plano: valor, dono e plano ativo
    user = query("SELECT id FROM users WHERE id=?", (pay["user_id"],), one=True)
    if (not user or pay["amount_cents"] != plan["price_cents"]
            or not plan["is_active"] or pay["group_id"] is not None):
        bv_audit(pay["user_id"], "subscription_rejected",
                 f"payment={pay['id']} motivo=cobranca_inconsistente")
        current_app.logger.error(
            "ativar_assinatura recusada: payment=%s valor=%s plano=%s(%s) ativo=%s",
            pay["id"], pay["amount_cents"], plan["id"], plan["price_cents"],
            plan["is_active"])
        return False
    t = now()
    db = get_db()
    try:
        db.execute("BEGIN IMMEDIATE")
        cur = db.execute(
            "UPDATE payments SET status='paid', paid_at=? WHERE id=? AND status='pending'",
            (t, pay["id"]))
        if cur.rowcount != 1:
            db.execute("ROLLBACK")
            return False
        atual = db.execute(
            "SELECT id, ends_at FROM bv_subscriptions WHERE user_id=? AND status='ativa' "
            "ORDER BY ends_at DESC LIMIT 1", (pay["user_id"],)).fetchone()
        if atual:
            base = datetime.strptime(atual["ends_at"], "%Y-%m-%d %H:%M:%S")
            if base < datetime.strptime(t, "%Y-%m-%d %H:%M:%S"):
                base = datetime.strptime(t, "%Y-%m-%d %H:%M:%S")
            novo_fim = (base + timedelta(days=plan["days"])).strftime("%Y-%m-%d %H:%M:%S")
            db.execute("UPDATE bv_subscriptions SET ends_at=?, last_payment_id=?, "
                       "updated_at=? WHERE id=?",
                       (novo_fim, pay["id"], t, atual["id"]))
        else:
            fim = (datetime.now(timezone.utc) +
                   timedelta(days=plan["days"])).strftime("%Y-%m-%d %H:%M:%S")
            db.execute(
                "INSERT INTO bv_subscriptions(user_id, plan_id, status, starts_at, "
                "ends_at, last_payment_id, created_at, updated_at) "
                "VALUES (?,?, 'ativa', ?,?,?,?,?)",
                (pay["user_id"], plan["id"], t, fim, pay["id"], t, t))
        db.execute("COMMIT")
    except Exception:
        try:
            db.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        current_app.logger.exception("ativar_assinatura falhou (payment %s)", payment_id)
        return False
    bv_audit(pay["user_id"], "subscription_activated",
             f"plan={plan['id']} payment={pay['id']}")
    return True


def bv_required(f):
    """Porta do módulo: login + assinatura ativa SEMPRE verificada no servidor."""
    @wraps(f)
    def wrapper(*a, **kw):
        if not g.user:
            return redirect(url_for("auth.login"))
        expirar_assinaturas()
        if not assinatura_ativa(g.user["id"]):
            abort(403)
        return f(*a, **kw)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not g.user or g.user["role"] != "admin":
            abort(403)
        return f(*a, **kw)
    return wrapper
