"""Gateway Pix: criação de cobranças, webhook e ativação de destaques.

Providers:
  - mercadopago: produção (requer MERCADOPAGO_ACCESS_TOKEN). Cria cobrança Pix
    real e devolve QR Code + copia-e-cola. O webhook NUNCA ativa destaque com
    base apenas na notificação: localiza a cobrança por provider_ref, valida a
    assinatura x-signature (quando MERCADOPAGO_WEBHOOK_SECRET está configurado)
    e RECONSULTA a API do gateway, conferindo status, valor e external_reference
    antes de qualquer ativação.
  - demo: APENAS desenvolvimento/sandbox. BR Code com chave fictícia,
    claramente identificado; o webhook exige assinatura HMAC de teste.

Ativação é idempotente e atômica: o pagamento é "reivindicado" com um único
UPDATE condicional (rowcount), a promoção tem UNIQUE(payment_id) e a segunda
inserção é bloqueada, não duplicada.
"""
import hashlib
import hmac
import json
import urllib.request
from datetime import datetime, timedelta, timezone

from flask import Blueprint, Response, current_app, g, redirect, request, url_for

from ..db import get_db, query, execute
from ..security import audit, hmac_sign, hmac_verify, new_token, now

bp = Blueprint("pix", __name__)
CHARGE_TTL_MIN = 60

# ---------------- providers ----------------

class DemoProvider:
    name = "demo"

    def create(self, payment, plan, group):
        from .brcode import build_brcode, qr_png_b64
        code = build_brcode("demo@telemax.pix", payment["amount_cents"],
                            txid=f"TM{payment['id']}")
        return dict(ok=True,
                    provider_ref=f"DEMO-{payment['id']}",
                    pix_code=code,
                    pix_qr_b64=qr_png_b64(code),
                    expires_at=None)

    def check_paid(self, payment):
        """Sandbox: pagamento é confirmado SOMENTE via webhook assinado."""
        return None

    def find_payment(self, webhook_id):
        """No demo, a notificação carrega o id INTERNO do pagamento."""
        return query("SELECT * FROM payments WHERE id = ? AND provider = 'demo'",
                      (str(webhook_id),), one=True)


class MercadoPagoProvider:
    name = "mercadopago"
    API = "https://api.mercadopago.com"

    def _req(self, method, path, body=None):
        token = current_app.config["MERCADOPAGO_ACCESS_TOKEN"]
        if not token:
            return None, "MERCADOPAGO_ACCESS_TOKEN não configurado"
        url = self.API + path
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Authorization", "Bearer " + token)
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                return json.loads(r.read().decode()), None
        except Exception as e:
            current_app.logger.error("Mercado Pago %s falhou: %s", path, e)
            return None, f"Gateway indisponível: {e}"

    def create(self, payment, plan, group):
        body = {
            "transaction_amount": round(payment["amount_cents"] / 100, 2),
            "description": (
                f"TELEMAX Bot Vendas - {plan['name'][:100]}"
                if payment["purpose"] == "bv_sub"
                else f"TELEMAX destaque {plan['name']} - {group['name'][:80]}"
            ),
            "payment_method_id": "pix",
            "external_reference": f"telemax-{payment['id']}",
            "notification_url": "https://telemax.lsnet.shop/webhook/pix",
            "payer": {"email": payment["email"] or "cliente@telemax.local"},
        }
        resp, err = self._req("POST", "/v1/payments", body)
        if err:
            return dict(ok=False, erro=err)
        try:
            tx = resp["point_of_interaction"]["transaction_data"]
            return dict(ok=True,
                        provider_ref=str(resp["id"]),
                        pix_code=tx["qr_code"],
                        pix_qr_b64=tx["qr_code_base64"],
                        expires_at=resp.get("date_of_expiration"))
        except (KeyError, TypeError):
            current_app.logger.error("resposta inesperada do Mercado Pago: %s", resp)
            return dict(ok=False, erro="Resposta do gateway sem QR Pix (conta possui chave Pix?)")

    def check_paid(self, payment):
        """Confirma com a API do gateway. Autoridade máxima da confirmação.

        Confere três coisas, não só o status:
        1. status == "approved"
        2. transaction_amount == amount_cents (valor pago é o valor cobrado)
        3. external_reference == "telemax-{id}" (a cobrança do gateway é
           EXATAMENTE a cobrança criada para este pagamento nosso)
        """
        resp, err = self._req("GET", f"/v1/payments/{payment['provider_ref']}")
        if err:
            return None
        if resp.get("status") != "approved":
            return None
        try:
            amount = int(round(float(resp["transaction_amount"]) * 100))
        except (KeyError, TypeError, ValueError):
            return None
        if amount != payment["amount_cents"]:
            current_app.logger.error(
                "Pagamento %s: valor divergente (cobrado %s, pago %s). Ignorado.",
                payment["id"], payment["amount_cents"], amount)
            return None
        if resp.get("external_reference") != f"telemax-{payment['id']}":
            current_app.logger.error(
                "Pagamento %s: external_reference divergente. Ignorado.", payment["id"])
            return None
        return True

    def verify_signature(self, raw_body, data):
        """Valida o header x-signature do Mercado Pago (HMAC-SHA256).

        Formato documentado pelo MP: header 'ts=<unix>,v1=<hmac>' e manifesto
        'id:{data.id};request-id:{x-request-id};ts:{ts};' assinado com a
        secret key do webhook. Se MERCADOPAGO_WEBHOOK_SECRET não estiver
        configurado, a validação é pulada (a reconsulta na API continua sendo
        obrigatória e é ela quem autoriza a ativação).
        """
        secret = current_app.config.get("MERCADOPAGO_WEBHOOK_SECRET") or ""
        if not secret:
            return True
        header = request.headers.get("X-Signature", "")
        parts = {}
        for item in header.split(","):
            if "=" in item:
                k, v = item.split("=", 1)
                parts[k.strip()] = v.strip()
        ts, v1 = parts.get("ts"), parts.get("v1")
        if not ts or not v1:
            return False
        manifest = (f"id:{(data.get('data') or {}).get('id', '')};"
                    f"request-id:{request.headers.get('X-Request-Id', '')};"
                    f"ts:{ts};")
        expected = hmac.new(secret.encode(), manifest.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, v1.lower())

    def find_payment(self, webhook_id):
        """No MP, a notificação carrega o id do GATEWAY (nosso provider_ref).

        Nunca busca por id interno: impede que uma notificação com o id de
        outra cobrança alcance um pagamento diferente.
        """
        return query("SELECT * FROM payments WHERE provider_ref = ? "
                     "AND provider = 'mercadopago'", (str(webhook_id),), one=True)


def get_provider():
    name = current_app.config.get("PIX_PROVIDER", "demo")
    if name == "mercadopago":
        return MercadoPagoProvider()
    return DemoProvider()

# ---------------- criação de cobrança ----------------

def create_charge(user, group, plan):
    """Cria payment + cobrança no provider. Preço SEMPRE vem do banco (plan)."""
    provider = get_provider()
    if provider.name == "mercadopago" and not current_app.config["MERCADOPAGO_ACCESS_TOKEN"]:
        return dict(ok=False,
                    erro="Mercado Pago sem MERCADOPAGO_ACCESS_TOKEN configurado")
    try:
        idem = new_token(10)
        pay_id = execute(
            "INSERT INTO payments(user_id, group_id, plan_id, amount_cents, status, "
            "provider, created_at, expires_at, idempotency) "
            "VALUES (?,?,?,?,'pending',?,?,?,?)",
            (user["id"], group["id"], plan["id"], plan["price_cents"],
             provider.name, now(),
             (datetime.now(timezone.utc) + timedelta(minutes=CHARGE_TTL_MIN)).strftime("%Y-%m-%d %H:%M:%S"),
             idem))
        payment = query("SELECT pay.*, u.email FROM payments pay JOIN users u ON u.id = pay.user_id "
                        "WHERE pay.id = ?", (pay_id,), one=True)
        res = provider.create(payment, plan, group)
        if not res.get("ok"):
            execute("UPDATE payments SET status = 'cancelled' WHERE id = ?", (pay_id,))
            return dict(ok=False, erro=res.get("erro", "falha no gateway"))
        try:
            execute("UPDATE payments SET provider_ref = ?, pix_code = ?, pix_qr_b64 = ? WHERE id = ?",
                    (res["provider_ref"], res["pix_code"], res.get("pix_qr_b64"), pay_id))
        except Exception:
            # erro após criação no gateway: cancela para não deixar cobrança sem referência
            execute("UPDATE payments SET status = 'cancelled' WHERE id = ?", (pay_id,))
            return dict(ok=False, erro="falha ao gravar cobrança; tente novamente")
        audit(user["id"], "charge_created", "payment", pay_id,
              f"plan={plan['id']} amount={plan['price_cents']}", request.remote_addr)
        return dict(ok=True, payment_id=pay_id)
    except Exception as e:
        current_app.logger.exception("create_charge")
        # nenhum pagamento fica pendente sem cobrança no gateway
        try:
            execute("UPDATE payments SET status = 'cancelled' "
                    "WHERE id = ? AND status = 'pending'", (pay_id,))
        except Exception:
            current_app.logger.exception("create_charge: falha ao cancelar pagamento %s", pay_id)
        return dict(ok=False, erro="gateway indisponível ou falha interna; tente novamente")

# ---------------- ativação ----------------

def activate_promotion(payment_id):
    """Ativa o destaque UMA vez, em TRANSAÇÃO ÚNICA ATÔMICA.

    A reivindicação do pagamento (UPDATE condicional) e a criação da promoção
    acontecem dentro da MESMA transação: se a inserção da promoção falhar,
    o ROLLBACK devolve o pagamento a 'pending' (webhooks seguintes tentam de
    novo). Nunca fica 'paid' sem promoção. Proteções mantidas:
    - rowcount != 1 -> outro processo processou antes (webhook simultâneo);
    - UNIQUE(payment_id) -> promoção nunca duplica;
    - IntegrityError significa que a promoção JÁ existia: o pagamento é
      re-marcado como paid (promocao ativa) sem duplicar nada.
    - Valor, plano, usuário e grupo vêm SEMPRE do registro do pagamento.
    """
    import sqlite3
    pay = query("SELECT * FROM payments WHERE id = ?", (payment_id,), one=True)
    if not pay:
        return False
    plan = query("SELECT * FROM plans WHERE id = ?", (pay["plan_id"],), one=True)
    if not plan:
        execute("UPDATE payments SET status = 'cancelled' WHERE id = ?", (pay["id"],))
        return False
    t = now()
    ends = (datetime.now(timezone.utc) +
            timedelta(days=plan["days"])).strftime("%Y-%m-%d %H:%M:%S")
    db = get_db()
    try:
        db.execute("BEGIN IMMEDIATE")                     # tran única começa aqui
        cur = db.execute(
            "UPDATE payments SET status = 'paid', paid_at = ? "
            "WHERE id = ? AND status = 'pending'", (t, pay["id"]))
        if cur.rowcount != 1:
            db.execute("ROLLBACK")                       # outro processo ganhou
            return False
        db.execute(
            "INSERT INTO promotions(group_id, payment_id, plan_id, starts_at, ends_at, is_active) "
            "VALUES (?,?,?,?,?,1)", (pay["group_id"], pay["id"], pay["plan_id"], t, ends))
        db.execute("COMMIT")                             # tudo junto ou nada
    except sqlite3.IntegrityError:
        # ROLLBACK primeiro: o pagamento volta a pending, nada foi gravado
        try:
            db.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        # A IntegrityError significa "promoção já existe" SOMENTE se ela
        # realmente existir no banco (verificado, não inferido da mensagem).
        if query("SELECT 1 FROM promotions WHERE payment_id = ?", (pay["id"],), one=True):
            execute("UPDATE payments SET status = 'paid', paid_at = ? "
                    "WHERE id = ? AND status = 'pending'", (t, pay["id"]))
            current_app.logger.warning(
                "promocao ja existia para o pagamento %s; pagamento marcado paid sem duplicar",
                pay["id"])
            return True
        # não existe promoção: foi falha REAL na inserção (trigger, abort, etc.)
        # pagamento permanece pending; webhook pode tentar novamente
        current_app.logger.error(
            "insercao da promocao falhou para o pagamento %s; rollback completo",
            pay["id"])
        return False
    except Exception:
        # falha real na insercao: ROLLBACK COMPLETO, pagamento volta a pending
        try:
            db.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        current_app.logger.exception(
            "ativacao falhou para o pagamento %s; rollback completo (pagamento volta a pending)",
            pay["id"])
        return False
    audit(pay["user_id"], "promotion_activated", "payment", pay["id"],
          f"group={pay['group_id']} until={ends}", request.remote_addr)
    return True

# ---------------- webhook ----------------

def _ativar(pay):
    """Despacho para o módulo Bot Vendas VPN (import local evita ciclo)."""
    from ..botvendas.helpers import ativar_assinatura
    return ativar_assinatura(pay["id"])


@bp.route("/webhook/pix", methods=["POST"])
def webhook():
    raw = request.get_data()
    provider = get_provider()
    if provider.name == "demo":
        # sandbox: exige assinatura HMAC do segredo de teste
        sig = request.headers.get("X-Telemax-Signature", "")
        if not hmac_verify(current_app.config["PIX_WEBHOOK_SECRET"], raw, sig):
            current_app.logger.warning("webhook demo com assinatura inválida")
            return Response('{"erro":"assinatura invalida"}', 401, mimetype="application/json")
        data = json.loads(raw.decode() or "{}")
        pay_id = data.get("payment_id")
        if data.get("event") == "test.ping":
            return Response('{"ok":true}', 200, mimetype="application/json")
    else:
        # produção (Mercado Pago): notificação carrega o id do gateway
        data = json.loads(raw.decode() or "{}")
        pay_id = (data.get("data") or {}).get("id") or data.get("payment_id")
        if pay_id and not provider.verify_signature(raw, data):
            current_app.logger.warning("webhook MP com assinatura inválida")
            return Response('{"erro":"assinatura invalida"}', 401, mimetype="application/json")
    if not pay_id:
        return Response('{"erro":"id ausente"}', 400, mimetype="application/json")
    pay = provider.find_payment(pay_id)
    if not pay:
        return Response('{"ok":true,"ignorado":"pagamento inexistente"}', 200,
                        mimetype="application/json")
    if pay["status"] == "pending":
        confirmed = provider.check_paid(pay)
        if provider.name == "demo":
            confirmed = True  # webhook assinado confirma no sandbox
        if confirmed:
            ativado = (_ativar(pay) if pay["purpose"] == "bv_sub"
                       else activate_promotion(pay["id"]))
            if ativado:
                return Response('{"ok":true,"ativado":true}', 200, mimetype="application/json")
            # ativacao falhou com rollback: pagamento segue pending (webhook pode tentar de novo)
            return Response('{"ok":true,"status":"ainda pendente"}', 200, mimetype="application/json")
        return Response('{"ok":true,"status":"ainda pendente"}', 200, mimetype="application/json")
    return Response('{"ok":true,"status":"ja processado"}', 200, mimetype="application/json")

@bp.route("/painel/pagamento/<int:pay_id>/simular", methods=["POST"])
def simulate_payment(pay_id):
    """ROTA SÓ PARA SANDBOX/TESTES: exige login, CSRF e PIX_PROVIDER=demo."""
    if current_app.config.get("PIX_PROVIDER") != "demo":
        return "Disponível apenas com PIX_PROVIDER=demo (sandbox).", 403
    if not g.get("user"):
        from flask import abort
        abort(403)
    from ..security import csrf_ok
    if not csrf_ok():
        return "CSRF inválido", 400
    pay = query("SELECT * FROM payments WHERE id = ? AND user_id = ?",
                (pay_id, g.user["id"]), one=True)
    if not pay:
        from flask import abort
        abort(403)
    if pay["purpose"] == "bv_sub":
        _ativar(pay)
        from flask import redirect as _r, url_for as _u
        return _r(_u("botvendas.pagamento", pay_id=pay_id))
    activate_promotion(pay["id"])
    return redirect(url_for("user.payment_page", pay_id=pay_id))
