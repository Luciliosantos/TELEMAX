"""Proteção de tokens/credenciais em repouso (Fernet, chave derivada da SECRET_KEY)."""
import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken
from flask import current_app


def _fernet():
    key = hashlib.sha256(("bv::" + current_app.config["SECRET_KEY"]).encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def enc(texto):
    """Criptografa segredo do cliente; vazio permanece vazio."""
    if not texto:
        return ""
    return _fernet().encrypt(texto.encode()).decode()


def dec(blob):
    """Descriptografa segredo; nunca levanta erro para a interface."""
    if not blob:
        return ""
    try:
        return _fernet().decrypt(blob.encode()).decode()
    except (InvalidToken, Exception):
        return ""


def mask(texto, visivel=4):
    """Máscara para exibição: nunca devolve o segredo intero à tela."""
    if not texto:
        return ""
    return "…" + texto[-visivel:] if len(texto) > visivel else "***"
