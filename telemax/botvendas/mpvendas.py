"""Mercado Pago INDIVIDUAL de cada cliente (adaptado de gerar_pix.sh /
acompanhar_pagamento.sh do BOT Vendas). Token vem da configuração do cliente,
criptografado em repouso; cobranças de um cliente nunca usam o token de outro.
Confirmação SEMPRE via consulta na API do MP — nunca por comprovante/mensagem.

SEGURANÇA (endurecimento 2026-10): aprovar NÃO basta. `consultar_pix` devolve o
estado real E os campos que provam que a cobrança é a desta venda:
valor (transaction_amount) e referência (external_reference == tm-<venda>).
Este módulo é SEPARADO de telemax/payments/pix.py (assinatura do módulo no
TELEMAX): token, tabela e fluxo de cada um nunca se misturam.
"""
import json
import urllib.error
import urllib.request
import uuid

from . import crypto
from .helpers import config_do_cliente


class MPError(Exception):
    pass


def _http(url, token, payload=None, idem=None, timeout=20):
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    if idem:
        headers["X-Idempotency-Key"] = idem
    req = urllib.request.Request(url, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read().decode())
        except Exception:
            raise MPError(f"HTTP {e.code}") from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise MPError("Mercado Pago indisponível") from None


def referencia(sale_id):
    """Referência única e verificável que liga a cobrança à venda."""
    return f"tm-{sale_id}"


def criar_pix(user_id, sale_id, amount_cents, description, idem=None):
    """Cria cobrança Pix com o token do CLIENTE.

    `idem` (opcional) torna a criação idempotente: repetir a chamada com a
    mesma chave devolve a MESMA cobrança no Mercado Pago, sem cobrar em dobro.
    """
    cfg = config_do_cliente(user_id)
    token = crypto.dec(cfg["mp_token_enc"])
    if not token or not token.startswith(("APP_USR-", "TEST-")):
        return dict(ok=False, erro="Credencial Mercado Pago do cliente ausente ou inválida")
    if not isinstance(amount_cents, int) or amount_cents <= 0:
        return dict(ok=False, erro="Valor inválido")
    idem = idem or f"tm-{user_id}-{sale_id}"
    payload = {
        "transaction_amount": round(amount_cents / 100, 2),
        "description": description[:200],
        "payment_method_id": "pix",
        "external_reference": referencia(sale_id),
        "payer": {"email": f"cliente{sale_id}@botvendas.telemax.com.br"},
    }
    try:
        resp = _http("https://api.mercadopago.com/v1/payments", token, payload, idem)
    except MPError as e:
        return dict(ok=False, erro=str(e))
    pay_id = resp.get("id")
    qr = ((resp.get("point_of_interaction") or {}).get("transaction_data") or {}).get("qr_code")
    if resp.get("status") in ("approved", "in_process") or not pay_id or not qr:
        return dict(ok=False, erro=resp.get("message") or "falha ao gerar Pix")
    return dict(ok=True, mp_payment_id=str(pay_id), qr=qr, amount_cents=amount_cents)


def consultar_pix_detalhe(user_id, mp_payment_id):
    """Estado REAL no provedor + campos para conferência (valor, referência)."""
    cfg = config_do_cliente(user_id)
    token = crypto.dec(cfg["mp_token_enc"])
    if not token:
        raise MPError("sem token")
    resp = _http(f"https://api.mercadopago.com/v1/payments/{mp_payment_id}", token)
    try:
        valor = int(round(float(resp.get("transaction_amount")) * 100))
    except (TypeError, ValueError):
        valor = None
    return dict(status=resp.get("status", ""), amount_cents=valor,
                external_reference=resp.get("external_reference"),
                id=str(resp.get("id", "")))


def consultar_pix(user_id, mp_payment_id):
    """Compatível com o uso antigo: só o status."""
    return consultar_pix_detalhe(user_id, mp_payment_id)["status"]


def confere(detalhe, sale):
    """True SOMENTE se aprovado E a cobrança é desta venda (valor + referência + id)."""
    if detalhe.get("status") != "approved":
        return False
    if detalhe.get("amount_cents") != sale["amount_cents"]:
        return False
    if detalhe.get("external_reference") != referencia(sale["id"]):
        return False
    if detalhe.get("id") and str(detalhe["id"]) != str(sale["mp_payment_id"]):
        return False
    return True
