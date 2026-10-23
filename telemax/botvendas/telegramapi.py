"""Cliente mínimo da Bot API do Telegram (substitui o ShellBot.sh original).

Usa apenas HTTPS + urllib da stdlib: zero dependências novas. O bot original
em Bash usava ShellBot (getUpdates long-polling, sendMessage, sendDocument,
InlineKeyboard). Aqui cada bot do cliente roda numa thread própria.
"""
import json
import time
import urllib.parse
import urllib.request

API = "https://api.telegram.org"


class TelegramError(Exception):
    pass


def _call(token, metodo, dados=None, timeout=35):
    url = f"{API}/bot{token}/{metodo}"
    data = None
    if dados is not None:
        data = json.dumps(dados).encode()
    req = urllib.request.Request(url, data=data,
                                headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            resp = json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            resp = json.loads(e.read().decode())
        except Exception:
            raise TelegramError(f"HTTP {e.code}") from None
    if not resp.get("ok"):
        raise TelegramError(resp.get("description", "erro desconhecido"))
    return resp.get("result")


def get_me(token):
    return _call(token, "getMe", {}, timeout=15)


def get_updates(token, offset=0, timeout=25):
    return _call(token, "getUpdates",
                 {"offset": offset, "timeout": timeout, "allowed_updates": []},
                 timeout=timeout + 10) or []


def send_message(token, chat_id, text, buttons=None, edit_message_id=None):
    dados = {"chat_id": chat_id, "text": text, "parse_mode": "HTML"}
    if buttons:
        dados["reply_markup"] = {"inline_keyboard": buttons}
    if edit_message_id:
        dados["message_id"] = edit_message_id
        return _call(token, "editMessageText", dados)
    return _call(token, "sendMessage", dados)


def send_document(token, chat_id, arquivo_bytes, nome):
    url = f"{API}/bot{token}/sendDocument"
    boundary = "TM" + str(int(time.time()))
    parts = []
    parts.append(f'--{boundary}\r\nContent-Disposition: form-data; '
                 f'name="chat_id"\r\n\r\n{chat_id}\r\n'.encode())
    parts.append(f'--{boundary}\r\nContent-Disposition: form-data; '
                 f'name="document"; filename="{nome}"\r\n'
                 f'Content-Type: application/octet-stream\r\n\r\n'.encode()
                 + arquivo_bytes + b"\r\n")
    body = b"".join(parts) + f"--{boundary}--\r\n".encode()
    req = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
    with urllib.request.urlopen(req, timeout=60) as r:
        resp = json.loads(r.read().decode())
    if not resp.get("ok"):
        raise TelegramError(resp.get("description", "falha ao enviar documento"))
    return resp.get("result")


def answer_callback(token, callback_id, text=""):
    try:
        return _call(token, "answerCallbackQuery",
                     {"callback_query_id": callback_id, "text": text[:190]}, timeout=10)
    except TelegramError:
        return None


def delete_message(token, chat_id, message_id):
    try:
        return _call(token, "deleteMessage",
                     {"chat_id": chat_id, "message_id": message_id}, timeout=10)
    except TelegramError:
        return None
