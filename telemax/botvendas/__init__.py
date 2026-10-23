"""Módulo Bot Vendas VPN — assinatura paga integrada ao TELEMAX.

Cada cliente (usuário TELEMAX com assinatura ativa) configura seu próprio bot
Telegram, sua VPS e suas credenciais do Mercado Pago. Nada é compartilhado
entre clientes.
"""
from flask import Blueprint

bp = Blueprint("botvendas", __name__, url_prefix="/bot-vendas",
                template_folder="../templates/botvendas")

from . import panel, adminpanel, helpers  # noqa: E402,F401


@bp.before_request
def _csrf_guard():
    """Todo POST do módulo exige CSRF válido (mesma proteção do restante do site)."""
    from flask import abort, request
    from ..security import csrf_ok
    if request.method == "POST" and not csrf_ok():
        abort(400)
