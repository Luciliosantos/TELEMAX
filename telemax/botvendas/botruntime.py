"""Runtime dos bots Telegram — um processo (thread) por cliente, sob demanda.

Reaproveita as funções do BOT Vendas original (menu, teste, compra, APK,
administração e verificação do proprietário) reinterpretadas no TELEMAX:
- ShellBot (bash) -> cliente HTTP mínimo da Bot API (telegramapi.py)
- comandos locais -> SSH remoto na VPS do cliente (sshops.RemoteVPS)
- mercadopago.token do servidor -> token individual do cliente (mpvendas.py)
- at-job de expiração -> expiração central (helpers.expirar_contas_vencidas)
Proteções que o layout visual NÃO desativa: botão de administração (injetado
para o dono), verificação de pagamento por consulta na API e limite de teste.
"""
import json
import threading
from datetime import datetime, timedelta, timezone

from flask import current_app

from ..db import execute, query
from ..security import now
from . import crypto, telegramapi
from .helpers import bv_audit, config_do_cliente
from .mpvendas import confere, consultar_pix_detalhe, criar_pix
from .sshops import RemoteVPS, gerar_credenciais_ssh

def get_db_():
    from ..db import get_db
    return get_db()


def _cfg_vps(cfg):
    """Config da VPS para o RemoteVPS: chave descriptografada + fingerprint confiável.

    Só entra _fingerprint quando o dono CONFIRMOU; sem isso nenhuma operação conecta.
    """
    return dict(cfg, _key_data=crypto.dec(cfg["vps_sshkey_enc"]),
                _fingerprint=(cfg["vps_fingerprint"] or "")
                if cfg["vps_fp_confirmed_at"] else "")


REGISTRY = {}          # user_id -> BotProcess
_registry_lock = threading.Lock()


class BotProcess:
    """Um bot de cliente: long-polling + entrega de contas."""

    def __init__(self, app, user_id, token, offset):
        self.app = app
        self.user_id = user_id
        self.token = token
        self.offset = offset
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._loop, daemon=True,
                                       name=f"botvendas-{user_id}")
        self.pollers = set()
        self._last_expire = 0.0

    # ---------------- infra ----------------
    def start(self):
        self.thread.start()

    def halt(self):
        self.stop.set()

    def _cfg(self):
        return query("SELECT * FROM bv_client_config WHERE user_id=?",
                     (self.user_id,), one=True)

    LAYOUT_PADRAO = {"welcome": "Bem-vindo!", "support": "Suporte.",
                      "menus": {"main": {"text": "Menu principal", "rows": []}}}

    def _layout(self):
        cfg = self._cfg()
        try:
            return json.loads(cfg["published_layout"]) if cfg["published_layout"] \
                else json.loads(json.dumps(self.LAYOUT_PADRAO))
        except (ValueError, TypeError):
            return json.loads(json.dumps(self.LAYOUT_PADRAO))

    # ---------------- loop principal ----------------
    def _loop(self):
        with self.app.app_context():
            falhas = 0
            while not self.stop.is_set():
                try:
                    updates = telegramapi.get_updates(self.token, self.offset)
                    falhas = 0
                    for u in updates:
                        self.offset = max(self.offset, u["update_id"] + 1)
                        execute("UPDATE bv_client_config SET tg_offset=? WHERE user_id=?",
                                (self.offset, self.user_id))
                        self._handle(u)
                    self._tarefas_periodicas()
                    self._limpar_pollers()
                except Exception as e:               # rede fora, token revogado...
                    falhas += 1
                    current_app.logger.warning("botvendas[%s] falha %s: %s",
                                              self.user_id, falhas, e)
                    if falhas >= 10:
                        execute("UPDATE bv_client_config SET bot_status='error', "
                                "bot_error=? WHERE user_id=?",
                                (f"{type(e).__name__}: {e}"[:300], self.user_id))
                        break
                    self.stop.wait(min(60, 5 * falhas))
            with _registry_lock:
                REGISTRY.pop(self.user_id, None)

    def _tarefas_periodicas(self):
        t = datetime.now(timezone.utc).timestamp()
        if t - self._last_expire > 300:              # a cada ~5 min
            self._last_expire = t
            try:
                from .helpers import expirar_contas_vencidas
                expirar_contas_vencidas(self.user_id)
            except Exception as e:
                current_app.logger.warning("expirar contas %s: %s", self.user_id, e)
            try:
                self._recuperar_incompletas()
            except Exception as e:
                current_app.logger.warning("recuperar vendas %s: %s", self.user_id, e)

    def _limpar_pollers(self):
        self.pollers = {p for p in self.pollers if p.is_alive()}

    # ---------------- despacho de eventos ----------------
    def _handle(self, u):
        msg = u.get("message") or {}
        cb = u.get("callback_query") or {}
        if msg:
            self._on_message(msg)
        elif cb:
            self._on_callback(cb)

    def _on_message(self, msg):
        chat = msg["chat"]["id"]
        texto = (msg.get("text") or "").strip()
        de = str(msg["from"]["id"])
        if texto.startswith("/start"):
            self._render_menu(chat, de, "main")
            return
        if texto.lower().startswith("/vincular"):
            import hmac
            import secrets as _sec
            # só em chat PRIVADO: código colado em grupo vaza para todos
            if msg["chat"].get("type", "private") != "private":
                telegramapi.send_message(self.token, chat,
                    "Por segurança, vincule em conversa privada com o bot.")
                return
            cfg = self._cfg()
            partes = texto.split()
            codigo = partes[1].strip() if len(partes) > 1 else ""
            esperado = cfg["link_code"] or ""
            if not codigo or not esperado or not hmac.compare_digest(
                    codigo.encode(), esperado.encode()):
                telegramapi.send_message(self.token, chat,
                    "Código inválido. Copie o comando completo no painel TELEMAX.")
                return
            if cfg["owner_tg_id"] and cfg["owner_tg_id"] != de:
                telegramapi.send_message(self.token, chat,
                    "Este bot já possui um proprietário vinculado. Desvincule no painel.")
                return
            # uso único: vincular CONSOME o código (novo código gerado)
            execute("UPDATE bv_client_config SET owner_tg_id=?, link_code=?, "
                    "updated_at=? WHERE user_id=?",
                    (de, "TM" + _sec.token_hex(6), now(), self.user_id))
            bv_audit(self.user_id, "owner_linked", f"tg_id={de}")
            telegramapi.send_message(self.token, chat,
                "✅ <b>Vínculo confirmado!</b> Você agora administra este bot.")
            self._render_menu(chat, de, "main")
            return
        if texto.lower().startswith("/ajuda"):
            telegramapi.send_message(self.token, chat,
                "Comandos: /start — menu principal\n/vincular CÓDIGO — vincular proprietário")
            return
        # texto livre: mensagens do dono fora de fluxo são ignoradas com dica
        telegramapi.send_message(self.token, chat,
            "Use /start para abrir o menu.", None)

    def _on_callback(self, cb):
        chat = cb["message"]["chat"]["id"]
        msg_id = cb["message"]["message_id"]
        de = str(cb["from"]["id"])
        dados = (cb.get("data") or "")[:64]
        cfg = self._cfg()
        dono = (cfg["owner_tg_id"] or "")
        eh_dono = bool(dono) and de == dono         # sem dono vinculado = ninguém é admin
        if dados == "admin":
            if not eh_dono:                         # administração SÓ do dono
                telegramapi.answer_callback(self.token, cb["id"], "⛔ Acesso restrito.")
                return
            self._menu_admin(chat, de, msg_id)
            return
        if eh_dono and dados.startswith(("adm_",)):
            self._acao_admin(chat, de, msg_id, dados)
            return
        acao = dados.split(":", 1)
        tipo = acao[0]
        arg = acao[1] if len(acao) > 1 else ""
        if tipo == "menu" and arg:
            telegramapi.answer_callback(self.token, cb["id"])
            self._render_menu(chat, de, arg, msg_id)
        elif tipo == "test":
            telegramapi.answer_callback(self.token, cb["id"])
            self._gerar_teste(chat, de, cb["from"].get("first_name", ""))
        elif tipo == "buy":
            telegramapi.answer_callback(self.token, cb["id"])
            self._comprar(chat, de, arg, cb["from"].get("first_name", ""))
        elif tipo == "apk":
            telegramapi.answer_callback(self.token, cb["id"])
            self._enviar_apk(chat)
        elif tipo == "support":
            telegramapi.answer_callback(self.token, cb["id"])
            layout = self._layout()
            telegramapi.send_message(self.token, chat,
                                     layout.get("support") or "Suporte: contate o proprietário.")
        elif tipo == "link" and arg.startswith(("http://", "https://")):
            telegramapi.answer_callback(self.token, cb["id"])
            telegramapi.send_message(self.token, chat,
                                     "Clique no botão abaixo 👇",
                                     [[{"text": "Abrir link", "url": arg}]])
        elif tipo == "msg" and arg:
            telegramapi.answer_callback(self.token, cb["id"])
            telegramapi.send_message(self.token, chat, arg[:3500])

    # ---------------- renderização do layout ----------------
    def _render_menu(self, chat, de, key, edit_message_id=None):
        layout = self._layout()
        menu = (layout.get("menus") or {}).get(key) or layout["menus"].get("main")
        if not menu:
            return
        kb = self._keyboard(menu.get("rows") or [], de)
        telegramapi.send_message(self.token, chat, menu.get("text") or "Menu",
                                 kb, edit_message_id)

    def _keyboard(self, rows, de):
        cfg = self._cfg()
        kb = []
        for row in rows:
            linha = []
            for b in row:
                b = dict(b)
                acao = (b.get("action") or "msg:")
                texto = (b.get("text") or "Botão")[:64]
                if acao.startswith("link:"):
                    url = acao[5:]
                    if url.startswith(("http://", "https://")):
                        linha.append({"text": texto, "url": url})
                else:
                    linha.append({"text": texto, "callback_data": acao[:64]})
            if linha:
                kb.append(linha)
        if cfg["owner_tg_id"] and de == cfg["owner_tg_id"]:
            kb.append([{"text": "⚙️ ADMINISTRAÇÃO", "callback_data": "admin"}])
        return kb

    def _menu_admin(self, chat, de, msg_id):
        total = query("SELECT COUNT(*) n FROM bv_sales WHERE user_id=? AND status='delivered'",
                      (self.user_id,), one=True)["n"]
        pend = query("SELECT COUNT(*) n FROM bv_sales WHERE user_id=? AND status='pending'",
                     (self.user_id,), one=True)["n"]
        ult = query("SELECT * FROM bv_sales WHERE user_id=? ORDER BY id DESC LIMIT 5",
                    (self.user_id,))
        linhas = "\n".join(
            f"• {v['buyer_name'] or v['buyer_tg_id']} — {v['status']} — {v['ssh_user'] or '-'}"
            for v in ult) or "—"
        cfg = self._cfg()
        kb = [[{"text": "↩️ Voltar", "callback_data": "menu:main"}]]
        telegramapi.send_message(
            self.token, chat,
            f"⚙️ <b>ADMINISTRAÇÃO</b>\n\n✅ Contas entregues: <b>{total}</b>\n"
            f"⏳ Pagamentos aguardando: <b>{pend}</b>\n"
            f"🖥️ VPS: {'OK' if cfg['vps_ok'] else 'não testada'}\n"
            f"🤖 Bot: {cfg['bot_status']}\n\nÚltimas vendas:\n{linhas}",
            kb, msg_id)

    def _acao_admin(self, chat, de, msg_id, dados):
        pass  # ações administrativas adicionais (renovação/revogação) ficam no painel web

    # ---------------- ações de negócio (protegidas no servidor) ----------------
    def _vpn_plano(self, plan_id):
        # buy: só resolve plano de VENDA (is_test=0). Plano de teste é
        # exclusivo do fluxo GERAR TESTE; vendê-lo por botão era um bug real.
        return query("SELECT * FROM bv_vpn_plans WHERE id=? AND user_id=? "
                     "AND is_active=1 AND is_test=0",
                     (plan_id, self.user_id), one=True)

    def _gerar_teste(self, chat, de, nome):
        plano = query("SELECT * FROM bv_vpn_plans WHERE user_id=? AND is_test=1 "
                      "AND is_active=1 ORDER BY sort LIMIT 1", (self.user_id,), one=True)
        if not plano:
            telegramapi.send_message(self.token, chat,
                "❌ Testes indisponíveis no momento.")
            return
        hoje = now()[:10]
        ja = query("SELECT 1 FROM bv_sales WHERE user_id=? AND buyer_tg_id=? AND "
                   "kind='test' AND substr(created_at,1,10)=?",
                   (self.user_id, de, hoje), one=True)
        if ja:
            telegramapi.send_message(self.token, chat,
                "Você já criou um teste hoje. Volte amanhã! ⏳")
            return
        horas = int(plano["test_hours"] or 2)
        self._criar_e_entregar(chat, de, nome, plano, kind="test",
                               dias=max(1, round(horas / 24)),
                               horas=horas)

    def _comprar(self, chat, de, plan_id, nome):
        plano = self._vpn_plano(plan_id)
        if not plano:
            telegramapi.send_message(self.token, chat, "❌ Plano indisponível.")
            return
        sale_id = execute(
            "INSERT INTO bv_sales(user_id, vpn_plan_id, buyer_tg_id, buyer_name, kind, "
            "status, amount_cents, created_at, updated_at) VALUES "
            "(?,?,?,?,'sale','pending',?,?,?)",
            (self.user_id, plano["id"], de, nome[:120], plano["price_cents"], now(), now()))
        res = criar_pix(self.user_id, sale_id, plano["price_cents"],
                        f"ACESSO VPN {plano['name']} - {plano['days']} dias")
        if not res.get("ok"):
            execute("UPDATE bv_sales SET status='failed', updated_at=? WHERE id=?",
                    (now(), sale_id))
            telegramapi.send_message(self.token, chat,
                "❌ Não foi possível gerar o Pix agora. Tente novamente.")
            return
        execute("UPDATE bv_sales SET mp_payment_id=? WHERE id=?",
                (res["mp_payment_id"], sale_id))
        telegramapi.send_message(
            self.token, chat,
            f"💰 <b>{plano['name']}</b>\n💵 Valor: <b>R$ {plano['price_cents']/100:.2f}</b>\n"
            f"📲 <b>PIX COPIA E COLA:</b>\n<pre>{res['qr']}</pre>\n"
            f"⏳ Após o pagamento a confirmação é automática.\n"
            f"🔐 O acesso será enviado aqui mesmo.\n🧾 ID: <code>{res['mp_payment_id']}</code>")
        self._iniciar_poller(sale_id)

    def _iniciar_poller(self, sale_id):
        """Thread de acompanhamento (adaptacao do acompanhar_pagamento.sh)."""
        t = threading.Thread(target=self._acompanhar, args=(sale_id,), daemon=True)
        self.pollers.add(t)
        t.start()

    def _acompanhar(self, sale_id, intervalo=15, minutos_max=90):
        """Equivalente ao acompanhar_pagamento.sh: consulta a API até aprovar.

        Aprovação exige status approved E valor E referência E id conferidos.
        """
        with self.app.app_context():
            fim = datetime.now(timezone.utc) + timedelta(minutes=minutos_max)
            while datetime.now(timezone.utc) < fim and not self.stop.is_set():
                sale = query("SELECT * FROM bv_sales WHERE id=?", (sale_id,), one=True)
                if not sale or sale["status"] != "pending":
                    return
                if sale["user_id"] != self.user_id or not sale["mp_payment_id"]:
                    return                       # venda não é deste cliente
                try:
                    det = consultar_pix_detalhe(self.user_id, sale["mp_payment_id"])
                except Exception as e:
                    current_app.logger.warning("consultar_pix %s: %s", sale_id, e)
                    self.stop.wait(intervalo)
                    continue
                if det.get("status") in ("rejected", "cancelled"):
                    execute("UPDATE bv_sales SET status='cancelled', updated_at=? "
                            "WHERE id=? AND status='pending'", (now(), sale_id))
                    return
                if det.get("status") == "expired":
                    execute("UPDATE bv_sales SET status='expired', updated_at=? "
                            "WHERE id=? AND status='pending'", (now(), sale_id))
                    return
                if confere(det, sale):
                    self._entregar(sale_id)
                    return
                self.stop.wait(intervalo)

    def _entregar(self, sale_id):
        """Entrega idempotente e RECUPERÁVEL.

        1. Reivindica a venda (pending -> provisioning) de forma atômica: só um
           processo toca a VPS por venda. Sem conta dupla.
        2. Cria a conta na VPS com credenciais geradas aqui (nunca do usuário).
        3. Sucesso -> delivered (credenciais cifradas). Falha -> volta a pending
           (nada foi entregue; nova tentativa possível; comprador não perde o
           pagamento e a VPS não fica com conta órfã).
        Se o processo MORRER no meio, a linha fica em provisioning e
        _recuperar_incompletas() a devolve a pending para nova tentativa.
        """
        db = get_db_()
        cur = db.execute(
            "UPDATE bv_sales SET status='provisioning', provision_attempts="
            "provision_attempts+1, updated_at=? WHERE id=? AND status='pending' "
            "AND user_id=?", (now(), sale_id, self.user_id))
        db.commit()
        if cur.rowcount != 1:
            return                                   # outro processo reivindicou
        sale = query("SELECT * FROM bv_sales WHERE id=?", (sale_id,), one=True)
        plano = query("SELECT * FROM bv_vpn_plans WHERE id=? AND user_id=?",
                      (sale["vpn_plan_id"], self.user_id), one=True)
        cfg = self._cfg()
        if not plano or not cfg["vps_fingerprint"] or not cfg["vps_fp_confirmed_at"]:
            execute("UPDATE bv_sales SET status='pending', updated_at=? WHERE id=? "
                    "AND status='provisioning'", (now(), sale_id))
            bv_audit(self.user_id, "delivery_blocked", f"sale={sale_id}")
            return
        vps = RemoteVPS(_cfg_vps(cfg))
        dias = plano["days"]
        expira = (datetime.now(timezone.utc) +
                  timedelta(days=dias)).strftime("%Y-%m-%d %H:%M:%S")
        usuario, senha = gerar_credenciais_ssh("ssh")
        if not vps.criar_conta(usuario, senha, dias, plano["max_connections"]):
            execute("UPDATE bv_sales SET status='pending', updated_at=? WHERE id=? "
                    "AND status='provisioning'", (now(), sale_id))
            bv_audit(self.user_id, "delivery_retry", f"sale={sale_id}")
            return
        cur = db.execute(
            "UPDATE bv_sales SET status='delivered', ssh_user=?, ssh_pass_enc=?, "
            "ssh_expires_at=?, delivered_at=?, updated_at=? "
            "WHERE id=? AND status='provisioning'",
            (usuario, crypto.enc(senha), expira, now(), now(), sale_id))
        db.commit()
        if cur.rowcount != 1:
            vps.remover_conta(usuario)               # compensação: conta órfã
            return
        telegramapi.send_message(
            self.token, int(sale["buyer_tg_id"]),
            f"✅ <b>Acesso criado com sucesso</b> ✅\n\n"
            f"SERVIDOR: {cfg['vps_host']}\nUSUARIO: <code>{usuario}</code>\n"
            f"SENHA: <code>{senha}</code>\n⏳ Expira em {dias} dias")
        bv_audit(self.user_id, "sale_delivered", f"sale={sale_id}")

    def _recuperar_incompletas(self, limite_min=10):
        """Devolve a pending vendas paradas em provisioning (processo morreu).

        Nenhuma cobrança nova é criada (mp_payment_id UNIQUE) e a entrega segue
        idempotente: a recuperação só permite NOVA tentativa segura.
        """
        corte = (datetime.now(timezone.utc) -
                 timedelta(minutes=limite_min)).strftime("%Y-%m-%d %H:%M:%S")
        db = get_db_()
        cur = db.execute("UPDATE bv_sales SET status='pending', updated_at=? "
                         "WHERE user_id=? AND status='provisioning' AND updated_at <= ?",
                         (now(), self.user_id, corte))
        db.commit()
        if cur.rowcount:
            current_app.logger.info("botvendas[%s]: %s venda(s) recuperada(s)",
                                    self.user_id, cur.rowcount)

    def _criar_e_entregar(self, chat, de, nome, plano, kind, dias, horas):
        """Teste grátis: RESERVA atômica (índice único no banco) -> VPS -> confirma.

        - Dois toques simultâneos: o índice uq_bvsale_test_dia deixa passar UM.
        - Falha na VPS: a reserva é liberada (comprador pode tentar de novo hoje).
        - Falha após criar a conta: compensação remove a conta (sem órfã).
        """
        import sqlite3
        cfg = self._cfg()
        if not cfg["vps_fingerprint"] or not cfg["vps_fp_confirmed_at"]:
            telegramapi.send_message(self.token, chat,
                "❌ Serviço temporariamente indisponível. Avise o suporte.")
            return
        usuario, senha = gerar_credenciais_ssh("lite")
        expira = (datetime.now(timezone.utc) +
                  timedelta(hours=horas)).strftime("%Y-%m-%d %H:%M:%S")
        try:
            sale_id = execute(
                "INSERT INTO bv_sales(user_id, vpn_plan_id, buyer_tg_id, buyer_name, "
                "kind, status, test_day, created_at, updated_at) "
                "VALUES (?,?,?,?,'test','provisioning',?,?,?)",
                (self.user_id, plano["id"], de, nome[:120], now()[:10], now(), now()))
        except sqlite3.IntegrityError:
            telegramapi.send_message(self.token, chat,
                "Você já criou um teste hoje. Volte amanhã! ⏳")
            return
        vps = RemoteVPS(_cfg_vps(cfg))
        if not vps.criar_conta(usuario, senha, max(1, dias), 1):
            execute("DELETE FROM bv_sales WHERE id=? AND status='provisioning'",
                    (sale_id,))                      # libera a reserva do dia
            telegramapi.send_message(self.token, chat,
                "❌ Falha temporária ao criar o teste. Tente novamente.")
            return
        cur = get_db_().execute(
            "UPDATE bv_sales SET status='delivered', ssh_user=?, ssh_pass_enc=?, "
            "ssh_expires_at=?, delivered_at=?, updated_at=? "
            "WHERE id=? AND status='provisioning'",
            (usuario, crypto.enc(senha), expira, now(), now(), sale_id))
        get_db_().commit()
        if cur.rowcount != 1:
            vps.remover_conta(usuario)               # compensação
            return
        telegramapi.send_message(
            self.token, chat,
            f"✅ <b>Teste criado</b> ✅\n\nSERVIDOR: {cfg['vps_host']}\n"
            f"USUARIO: <code>{usuario}</code>\nSENHA: <code>{senha}</code>\n"
            f"⏳ Expira em {horas} hora(s)")


# ---------------- API do registry (painel + boot) ----------------
def publicar_bot(app, user_id):
    """Publica: valida requisitos e sobe a thread do bot."""
    cfg = config_do_cliente(user_id)
    token = crypto.dec(cfg["bot_token_enc"])
    problemas = []
    if not token:
        problemas.append("Token do bot")
    if not cfg["owner_tg_id"]:
        problemas.append("Vínculo do proprietário Telegram")
    if not cfg["vps_fingerprint"] or not cfg["vps_fp_confirmed_at"]:
        problemas.append("Impressão digital (fingerprint) da VPS confirmada")
    if not cfg["vps_ok"]:
        problemas.append("VPS testada")
    if not crypto.dec(cfg["mp_token_enc"]):
        problemas.append("Token Mercado Pago")
    if problemas:
        return dict(ok=False, erro="Pendências: " + ", ".join(problemas))
    with _registry_lock:
        if user_id in REGISTRY:
            return dict(ok=False, erro="Bot já está em execução")
    info = telegramapi.get_me(token)
    bp = BotProcess(app, user_id, token, cfg["tg_offset"] or 0)
    execute("UPDATE bv_client_config SET bot_status='running', bot_error='', "
            "bot_username=?, updated_at=? WHERE user_id=?",
            (info.get("username", ""), now(), user_id))
    REGISTRY[user_id] = bp
    bp.start()
    bv_audit(user_id, "bot_published")
    return dict(ok=True)


def parar_bot(user_id):
    with _registry_lock:
        bp = REGISTRY.pop(user_id, None)
    if bp:
        bp.halt()
    execute("UPDATE bv_client_config SET bot_status='stopped', updated_at=? "
            "WHERE user_id=?", (now(), user_id))
    bv_audit(user_id, "bot_stopped")


def bot_vivo(user_id):
    with _registry_lock:
        return user_id in REGISTRY


def retomar_todos(app):
    """No boot: retoma bots de clientes com assinatura ativa e status running."""
    if app.config.get("TESTING") or app.config.get("TM_NO_BOTS"):
        return
    from .helpers import assinatura_ativa
    with app.app_context():
        for cfg in query("SELECT * FROM bv_client_config WHERE bot_status='running'"):
            if assinatura_ativa(cfg["user_id"]) and crypto.dec(cfg["bot_token_enc"]):
                try:
                    publicar_bot(app, cfg["user_id"])
                except Exception as e:
                    app.logger.warning("retomar bot %s: %s", cfg["user_id"], e)
