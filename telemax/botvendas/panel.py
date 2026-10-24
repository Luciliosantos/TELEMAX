"""Painel de gerenciamento do Bot Vendas VPN (cliente com assinatura ativa)."""
import json
import os

from flask import (abort, current_app, flash, g, redirect, render_template,
                   request, url_for)

from ..db import execute, query
from ..security import audit, now
from . import crypto, telegramapi
from . import botruntime
from .helpers import (bv_audit, config_do_cliente, expirar_assinaturas,
                      expirar_contas_vencidas)
from .sshops import ErroSSH, RE_VPS_USER, RemoteVPS, SSHResult, testar_conexao_completo
from .botruntime import _cfg_vps

APK_MAX = 30 * 1024 * 1024
RE_HOST = __import__("re").compile(
    r"^(?=.{1,190}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)"
    r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")


def _host_valido(host):
    """IP ou hostname RFC; rejeita vazio/símbolos e destinos internos do próprio
    servidor central (evita o cliente apontar o módulo para o TELEMAX central)."""
    import ipaddress
    if not host or not RE_HOST.match(host):
        return False
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast:
            return False
    except ValueError:
        if host.lower() in ("localhost", "localhost.localdomain"):
            return False
    return True


def _assinatura_ou_403():
    from .helpers import assinatura_ativa
    sub = assinatura_ativa(g.user["id"])
    if not sub:
        abort(403)
    return sub


# ---------------- entrada do módulo ----------------
from . import bp  # noqa: E402


@bp.route("")
@bp.route("/")
def panel():
    if not g.user:
        # Visitante (sem login): pagina publica de apresentacao do modulo.
        # Nada de configuracoes, tokens, dados de clientes ou acoes protegidas —
        # apenas o nome, a descricao e os planos com preco. O botao de contratacao
        # vira um convite para entrar/cadastrar; contratar() continua exigindo login.
        planos = query("SELECT * FROM bv_plans WHERE is_active=1 ORDER BY sort, price_cents")
        return render_template("botvendas/landing.html", planos=planos, visitante=True)
    expirar_assinaturas()
    from .helpers import assinatura_ativa
    sub = assinatura_ativa(g.user["id"])
    if not sub:
        planos = query("SELECT * FROM bv_plans WHERE is_active=1 ORDER BY sort, price_cents")
        return render_template("botvendas/landing.html", planos=planos)
    cfg = config_do_cliente(g.user["id"])
    vendas = query("SELECT * FROM bv_sales WHERE user_id=? ORDER BY id DESC LIMIT 20",
                   (g.user["id"],))
    stats = query("SELECT status, COUNT(*) n FROM bv_sales WHERE user_id=? "
                  "GROUP BY status", (g.user["id"],))
    expirar_contas_vencidas(g.user["id"])
    return render_template("botvendas/panel.html", sub=sub, cfg=cfg,
                           vendas=vendas, stats=stats,
                           token_mask=crypto.mask(crypto.dec(cfg["bot_token_enc"])),
                           mp_mask=crypto.mask(crypto.dec(cfg["mp_token_enc"])),
                           vivo=botruntime.bot_vivo(g.user["id"]))


# ---------------- contratação da assinatura ----------------
@bp.route("/contratar", methods=["POST"])
def contratar():
    if not g.user:
        return redirect(url_for("auth.login"))
    plan = query("SELECT * FROM bv_plans WHERE id=? AND is_active=1",
                 (request.form.get("plan_id", "0"),), one=True)
    if not plan:
        flash("Plano indisponível.", "erro")
        return redirect(url_for("botvendas.panel"))
    from ..payments.pix import get_provider, CHARGE_TTL_MIN
    from datetime import datetime, timedelta, timezone
    from ..security import new_token
    provider = get_provider()
    idem = new_token(10)
    pay_id = execute(
        "INSERT INTO payments(user_id, amount_cents, status, provider, purpose, "
        "target_id, created_at, expires_at, idempotency) "
        "VALUES (?,?, 'pending', ?, 'bv_sub', ?,?,?,?)",
        (g.user["id"], plan["price_cents"], provider.name, plan["id"], now(),
         (datetime.now(timezone.utc) +
          timedelta(minutes=CHARGE_TTL_MIN)).strftime("%Y-%m-%d %H:%M:%S"), idem))
    payment = query(
        "SELECT payments.*, users.email AS email "
        "FROM payments LEFT JOIN users ON users.id = payments.user_id "
        "WHERE payments.id=?",
        (pay_id,), one=True
    )
    res = provider.create(payment, plan, None)
    if not res.get("ok"):
        execute("UPDATE payments SET status='cancelled' WHERE id=?", (pay_id,))
        flash("Falha no gateway: " + res.get("erro", ""), "erro")
        return redirect(url_for("botvendas.panel"))
    execute("UPDATE payments SET provider_ref=?, pix_code=?, pix_qr_b64=? WHERE id=?",
            (res["provider_ref"], res["pix_code"], res.get("pix_qr_b64"), pay_id))
    audit(g.user["id"], "bv_charge_created", "payment", pay_id,
          f"plan={plan['id']}", request.remote_addr)
    return redirect(url_for("botvendas.pagamento", pay_id=pay_id))


@bp.route("/pagamento/<int:pay_id>")
def pagamento(pay_id):
    if not g.user:
        return redirect(url_for("auth.login"))
    pay = query("SELECT * FROM payments WHERE id=? AND user_id=? AND purpose='bv_sub'",
                (pay_id, g.user["id"]), one=True)
    if not pay:
        abort(404)
    from ..payments.pix import get_provider
    demo = get_provider().name == "demo"
    return render_template("botvendas/pagamento.html", pay=pay, demo=demo)


# ---------------- configuração do bot / vps / mp / apk ----------------
@bp.route("/vps", methods=["GET"])
def vps_page():
    """Pagina propria Servidor/VPS (requisito 8 do briefing): separada da
    configuracao do bot, preservando acoes, permissões e dados por cliente."""
    if not g.user:
        return redirect(url_for("auth.login"))
    sub = _assinatura_ou_403()
    cfg = config_do_cliente(g.user["id"])
    return render_template("botvendas/vps.html", sub=sub, cfg=cfg)


@bp.route("/config", methods=["GET"])
def config_page():
    if not g.user:
        return redirect(url_for("auth.login"))
    sub = _assinatura_ou_403()
    cfg = config_do_cliente(g.user["id"])
    return render_template("botvendas/config.html", sub=sub, cfg=cfg,
                           token_mask=crypto.mask(crypto.dec(cfg["bot_token_enc"])),
                           mp_mask=crypto.mask(crypto.dec(cfg["mp_token_enc"])))


@bp.route("/config/bot", methods=["POST"])
def config_bot():
    if not g.user:
        return redirect(url_for("auth.login"))
    _assinatura_ou_403()
    config_do_cliente(g.user["id"])
    uid = g.user["id"]
    acao = request.form.get("acao")
    token = (request.form.get("bot_token") or "").strip()
    if token:                                   # salvar OU substituir
        try:
            info = telegramapi.get_me(token)
        except Exception:
            # nunca ecoa o token nem o texto bruto do erro
            flash("Token inválido ou Telegram inacessível.", "erro")
            return redirect(url_for("botvendas.config_page"))
        execute("UPDATE bv_client_config SET bot_token_enc=?, bot_username=?, "
                "tg_offset=0, updated_at=? WHERE user_id=?",
                (crypto.enc(token), info.get("username", ""), now(), uid))
        botruntime.parar_bot(uid)               # token novo exige reinício consciente
        bv_audit(uid, "bot_token_saved")
        flash("Token do bot salvo (@" + info.get("username", "?") + "). "
              "Publique novamente para iniciar.", "ok")
    if acao == "salvar_owner_id":
        owner_id = (request.form.get("owner_tg_id") or "").strip()
        if not owner_id.isdigit() or not (5 <= len(owner_id) <= 15):
            flash("Informe um ID numérico válido do Telegram (5 a 15 dígitos).", "erro")
        else:
            execute(
                "UPDATE bv_client_config SET owner_tg_id=?, updated_at=? WHERE user_id=?",
                (owner_id, now(), uid),
            )
            botruntime.parar_bot(uid)
            bv_audit(uid, "owner_id_saved", f"tg_id={owner_id}")
            flash("ID do proprietário salvo. Publique novamente para iniciar o bot.", "ok")
    elif acao == "revogar_token":
        execute("UPDATE bv_client_config SET bot_token_enc=NULL, bot_username=NULL, "
                "bot_status='stopped', updated_at=? WHERE user_id=?", (now(), uid))
        botruntime.parar_bot(uid)
        bv_audit(uid, "bot_token_revoked")
        flash("Token removido do TELEMAX e bot parado. Revogue-o também no "
              "@BotFather.", "ok")
    elif acao == "desvincular":
        execute("UPDATE bv_client_config SET owner_tg_id=NULL, updated_at=? "
                "WHERE user_id=?", (now(), uid))
        botruntime.parar_bot(uid)
        bv_audit(uid, "owner_unlinked")
        flash("Vínculo desfeito e bot parado.", "ok")
    elif acao == "novocodigo":
        import secrets
        execute("UPDATE bv_client_config SET link_code=?, updated_at=? WHERE user_id=?",
                ("TM" + secrets.token_hex(6), now(), uid))
        flash("Novo código de vinculação gerado.", "ok")
    return redirect(url_for("botvendas.config_page"))


def _gerar_par_chave():
    """Par Ed25519 do CLIENTE (autenticação). Privada fica criptografada no banco."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    chave = Ed25519PrivateKey.generate()
    priv = chave.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                               serialization.NoEncryption()).decode()
    pub = chave.public_key().public_bytes(serialization.Encoding.OpenSSH,
                                          serialization.PublicFormat.OpenSSH).decode()
    return priv, pub


def _salvar_dados_vps(uid, cfg, form):
    """Valida e grava IP/porta/usuário/sudo. Mudar o destino zera a identidade."""
    host = (form.get("vps_host") or "").strip()[:190]
    if not _host_valido(host):
        flash("Endereço da VPS inválido (use IP ou domínio, sem espaços ou símbolos).", "erro")
        return None
    try:
        port = int(form.get("vps_port") or 22)
    except ValueError:
        port = 0
    if not (1 <= port <= 65535):
        flash("Porta inválida (1 a 65535).", "erro")
        return None
    user = (form.get("vps_user") or "botvendas").strip()[:32]
    if not RE_VPS_USER.match(user):
        flash("Usuário SSH inválido (use a-z, 0-9, _ ou -).", "erro")
        return None
    use_sudo = 1 if form.get("vps_use_sudo") else 0
    mudou = (host != (cfg["vps_host"] or "") or port != cfg["vps_port"]
             or user != cfg["vps_user"])
    execute("UPDATE bv_client_config SET vps_host=?, vps_port=?, vps_user=?, "
            "vps_use_sudo=?, updated_at=? WHERE user_id=?",
            (host, port, user, use_sudo, now(), uid))
    if mudou:       # outro destino = outra identidade de servidor: zera a confiança
        execute("UPDATE bv_client_config SET vps_fingerprint=NULL, vps_fp_type=NULL, "
                "vps_fp_confirmed_at=NULL, vps_ok=0 WHERE user_id=?", (uid,))
        botruntime.parar_bot(uid)
        bv_audit(uid, "vps_target_changed")
    return config_do_cliente(uid)


def _testar_conexao(uid, cfg, senha_form):
    """Botão TESTAR CONEXÃO: executa todas as etapas e grava o resultado."""
    keydata = crypto.dec(cfg["vps_sshkey_enc"])
    if not keydata or not cfg["vps_pubkey"]:
        keydata, pub = _gerar_par_chave()
        execute("UPDATE bv_client_config SET vps_sshkey_enc=?, vps_pubkey=?, vps_ok=0, "
                "updated_at=? WHERE user_id=?", (crypto.enc(keydata), pub, now(), uid))
        bv_audit(uid, "vps_key_generated")
        cfg = config_do_cliente(uid)
    senha = senha_form or crypto.dec(cfg["vps_password_enc"] or "")
    res = testar_conexao_completo(dict(cfg, _key_data=keydata), senha=senha)
    senha = ""                                   # descarta a senha da memória
    if res.get("ok"):
        # Confirma somente após o teste completo e a validação da fingerprint.
        if res.get("fingerprint"):
            execute("UPDATE bv_client_config SET vps_fingerprint=?, vps_fp_type=?, "
                    "vps_fp_confirmed_at=?, updated_at=? WHERE user_id=?",
                    (res["fingerprint"], res["tipo"], now(), now(), uid))
            bv_audit(uid, "vps_fingerprint_registered", res["fingerprint"])
        else:
            execute("UPDATE bv_client_config SET vps_fp_confirmed_at=?, updated_at=? "
                    "WHERE user_id=?",
                    (now(), now(), uid))
        cfg = config_do_cliente(uid)
    if res["chave_instalada"]:
        bv_audit(uid, "vps_key_installed")
    ok = res["ok"]
    falha = next((e for e in res["etapas"] if not e["ok"]), None)
    resultado = "\n".join(("OK" if e["ok"] else "FALHA") + " | " + e["nome"] + " | " + e["msg"]
                          for e in res["etapas"])
    # a senha só é apagada depois que a chave funciona (ela não é mais necessária)
    limpar_senha = ", vps_password_enc=NULL" if ok else ""
    execute("UPDATE bv_client_config SET vps_ok=?, vps_last_test=?, vps_last_result=?, "
            "updated_at=?" + limpar_senha + " WHERE user_id=?",
            (1 if ok else 0, now(), resultado[:4000], now(), uid))
    bv_audit(uid, "vps_test", "ok" if ok else "fail:" + (falha["nome"] if falha else "?"))
    if ok:
        flash("Conexão SSH confirmada: a VPS está pronta para criar contas.", "ok")
    else:
        flash("Falha em \"" + (falha["nome"] if falha else "conexão") + "\": "
              + (falha["msg"] if falha else "erro desconhecido"), "erro")


@bp.route("/config/vps", methods=["POST"])
def config_vps():
    if not g.user:
        return redirect(url_for("auth.login"))
    _assinatura_ou_403()
    uid = g.user["id"]
    acao = request.form.get("acao", "salvar")
    cfg = config_do_cliente(uid)

    # ---- revogações (uso avançado) ----
    if acao == "revogar_fp":
        execute("UPDATE bv_client_config SET vps_fingerprint=NULL, vps_fp_type=NULL, "
                "vps_fp_confirmed_at=NULL, vps_ok=0, updated_at=? WHERE user_id=?",
                (now(), uid))
        botruntime.parar_bot(uid)
        bv_audit(uid, "vps_fingerprint_revoked")
        flash("Identidade do servidor removida. O próximo TESTAR CONEXÃO registra de novo.", "ok")
        return redirect(url_for("botvendas.vps_page"))
    if acao == "revogar_chave":
        execute("UPDATE bv_client_config SET vps_sshkey_enc=NULL, vps_pubkey=NULL, "
                "vps_password_enc=NULL, vps_ok=0, updated_at=? WHERE user_id=?", (now(), uid))
        botruntime.parar_bot(uid)
        bv_audit(uid, "vps_key_revoked")
        flash("Chave SSH removida do TELEMAX e bot parado. Remova também a chave "
              "pública do authorized_keys da VPS.", "ok")
        return redirect(url_for("botvendas.vps_page"))

    if acao not in ("salvar", "confirmar_senha", "testar_conexao"):
        flash("Ação desconhecida.", "erro")
        return redirect(url_for("botvendas.vps_page"))

    cfg = _salvar_dados_vps(uid, cfg, request.form)
    if cfg is None:
        return redirect(url_for("botvendas.vps_page"))

    if acao == "salvar":
        flash("Dados da VPS salvos.", "ok")
    elif acao == "confirmar_senha":
        senha = request.form.get("vps_password") or ""
        if not senha or len(senha) > 200:
            flash("Informe a senha SSH da VPS (até 200 caracteres).", "erro")
        else:
            execute("UPDATE bv_client_config SET vps_password_enc=?, vps_ok=0, "
                    "updated_at=? WHERE user_id=?", (crypto.enc(senha), now(), uid))
            senha = ""
            bv_audit(uid, "vps_password_saved")
            flash("Senha SSH guardada de forma criptografada. Agora clique em TESTAR CONEXÃO.",
                  "ok")
    elif acao == "testar_conexao":
        _testar_conexao(uid, cfg, request.form.get("vps_password") or "")
    return redirect(url_for("botvendas.vps_page"))


@bp.route("/config/mp", methods=["POST"])
def config_mp():
    if not g.user:
        return redirect(url_for("auth.login"))
    _assinatura_ou_403()
    config_do_cliente(g.user["id"])
    uid = g.user["id"]
    if request.form.get("acao") == "revogar_mp":
        execute("UPDATE bv_client_config SET mp_token_enc=NULL, updated_at=? "
                "WHERE user_id=?", (now(), uid))
        botruntime.parar_bot(uid)
        bv_audit(uid, "mp_token_revoked")
        flash("Token Mercado Pago removido e bot parado. Revogue-o também no "
              "painel do Mercado Pago.", "ok")
        return redirect(url_for("botvendas.config_page"))
    token = (request.form.get("mp_token") or "").strip()
    if token:
        if not token.startswith(("APP_USR-", "TEST-")) or len(token) < 20 \
                or any(c.isspace() for c in token):
            flash("Token deve começar com APP_USR- (produção) ou TEST- (sandbox).", "erro")
            return redirect(url_for("botvendas.config_page"))
        execute("UPDATE bv_client_config SET mp_token_enc=?, updated_at=? WHERE user_id=?",
                (crypto.enc(token), now(), uid))
        bv_audit(uid, "mp_token_saved")
        flash("Token Mercado Pago salvo.", "ok")
    return redirect(url_for("botvendas.config_page"))


def _apk_valido(dados):
    """Um APK é um ZIP que contém AndroidManifest.xml e classes.dex."""
    import io
    import zipfile
    if not dados.startswith(b"PK\x03\x04"):
        return False
    try:
        with zipfile.ZipFile(io.BytesIO(dados)) as z:
            nomes = set(z.namelist())
            return "AndroidManifest.xml" in nomes and any(
                n.endswith(".dex") for n in nomes)
    except zipfile.BadZipFile:
        return False


@bp.route("/apk", methods=["POST"])
def apk_upload():
    if not g.user:
        return redirect(url_for("auth.login"))
    _assinatura_ou_403()
    config_do_cliente(g.user["id"])
    arq = request.files.get("apk")
    if not arq or not arq.filename.lower().endswith(".apk"):
        flash("Envie um arquivo .apk.", "erro")
        return redirect(url_for("botvendas.config_page"))
    dados = arq.read(APK_MAX + 1)
    if len(dados) > APK_MAX:
        flash("APK maior que 30MB.", "erro")
        return redirect(url_for("botvendas.config_page"))
    if not _apk_valido(dados):
        flash("O arquivo não é um APK válido (falta AndroidManifest.xml/classes.dex).",
              "erro")
        return redirect(url_for("botvendas.config_page"))
    # nome só como RÓTULO de exibição (sanitizado); o caminho em disco é fixo
    import re as _re
    rotulo = _re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(arq.filename))[:80]
    pasta = os.path.join(current_app.instance_path, "uploads",
                         "botvendas", str(g.user["id"]))
    os.makedirs(pasta, exist_ok=True)
    with open(os.path.join(pasta, "base.apk"), "wb") as fh:
        fh.write(dados)
    execute("UPDATE bv_client_config SET apk_filename=?, apk_size=?, updated_at=? "
            "WHERE user_id=?", (rotulo, len(dados), now(), g.user["id"]))
    bv_audit(g.user["id"], "apk_uploaded", f"size={len(dados)}")
    flash("APK cadastrado.", "ok")
    return redirect(url_for("botvendas.config_page"))


def caminho_apk(user_id):
    p = os.path.join(current_app.instance_path, "uploads", "botvendas",
                     str(user_id), "base.apk")
    return p if os.path.exists(p) else None


# ---------------- planos VPN do cliente ----------------
@bp.route("/vpn-planos")
def vpn_planos():
    if not g.user:
        return redirect(url_for("auth.login"))
    sub = _assinatura_ou_403()
    planos = query("SELECT * FROM bv_vpn_plans WHERE user_id=? AND is_test=0 ORDER BY sort",
                   (g.user["id"],))
    cfg = config_do_cliente(g.user["id"])
    vendas_por_plano = {r["vpn_plan_id"]: r["n"] for r in query(
        "SELECT vpn_plan_id, COUNT(*) n FROM bv_sales WHERE user_id=? "
        "GROUP BY vpn_plan_id", (g.user["id"],))}
    refs_por_plano = {p["id"]: len(_refs_do_plano(g.user["id"], p["id"]))
                      for p in planos}
    return render_template("botvendas/vpnplans.html", sub=sub, planos=planos, cfg=cfg,
                           vendas_por_plano=vendas_por_plano,
                           refs_por_plano=refs_por_plano)


@bp.route("/vpn-planos/salvar", methods=["POST"])
def vpn_plano_salvar():
    if not g.user or not _assinatura_ou_403():
        abort(403)
    sub = _assinatura_ou_403()
    try:
        preco = int(round(float(request.form.get("price", "0").replace(",", ".")) * 100))
        dias = int(request.form.get("days", "30"))
        conns = max(1, int(request.form.get("max_connections", "1")))
        e_teste = 1 if request.form.get("is_test") else 0
        horas = max(1, min(24, int(request.form.get("test_hours", "2")))) if e_teste else None
    except ValueError:
        flash("Valores inválidos.", "erro")
        return redirect(url_for("botvendas.vpn_planos"))
    nome = (request.form.get("name") or "").strip()[:80]
    if not nome or dias <= 0 or preco < 0 or (preco == 0 and not e_teste):
        flash("Preencha nome, preço e validade (preço 0 só para plano de teste).", "erro")
        return redirect(url_for("botvendas.vpn_planos"))
    pid = request.form.get("id")
    if pid:
        atual = query(
            "SELECT is_active FROM bv_vpn_plans WHERE id=? AND user_id=?",
            (pid, g.user["id"]), one=True
        )
        if not atual:
            flash("Plano não encontrado.", "erro")
            return redirect(url_for("botvendas.vpn_planos"))

        ativo = atual["is_active"]
        if "is_active" in request.form:
            ativo = 1 if request.form.get("is_active") == "1" else 0

        execute(
            "UPDATE bv_vpn_plans SET name=?, price_cents=?, days=?, "
            "max_connections=?, is_test=?, test_hours=?, is_active=? "
            "WHERE id=? AND user_id=?",
            (nome, preco, dias, conns, e_teste, horas, ativo,
             int(pid), g.user["id"])
        )
        flash("Plano atualizado e disponibilidade preservada.", "ok")
    else:
        limite = sub["max_vpn_plans"]
        total = query("SELECT COUNT(*) n FROM bv_vpn_plans WHERE user_id=?",
                      (g.user["id"],), one=True)["n"]
        if total >= limite:
            flash(f"Seu plano de assinatura permite até {limite} planos VPN.", "erro")
            return redirect(url_for("botvendas.vpn_planos"))
        execute("INSERT INTO bv_vpn_plans(user_id, name, price_cents, days, "
                "max_connections, is_test, test_hours, is_active, sort, created_at) "
                "VALUES (?,?,?,?,?,?,?,1,0,?)",
                (g.user["id"], nome, preco, dias, conns, e_teste, horas, now()))
        flash("Plano criado.", "ok")
    return redirect(url_for("botvendas.vpn_planos"))


@bp.route("/vpn-planos/<int:pid>/toggle", methods=["POST"])
def vpn_plano_toggle(pid):
    if not g.user or not _assinatura_ou_403():
        abort(403)
    execute("UPDATE bv_vpn_plans SET is_active = 1-is_active WHERE id=? AND user_id=?",
            (pid, g.user["id"]))
    ativo = query("SELECT is_active FROM bv_vpn_plans WHERE id=? AND user_id=?",
                  (pid, g.user["id"]), one=True)
    if ativo and not ativo["is_active"]:
        refs = _refs_do_plano(g.user["id"], pid)
        if refs:
            publicados = sum(1 for r in refs if r[0] == "publicado")
            flash("Plano desativado. Atenção: %d botão(ões) publicados ainda o "
                  "referenciam — o Telegram responderá \"Plano indisponível\" "
                  "até você trocar a associação no Editor e publicar de novo."
                  % publicados, "erro")
            return redirect(url_for("botvendas.vpn_planos"))
    flash("Plano atualizado.", "ok")
    return redirect(url_for("botvendas.vpn_planos"))


@bp.route("/vpn-planos/<int:pid>/remover", methods=["POST"])
def vpn_plano_remover(pid):
    if not g.user or not _assinatura_ou_403():
        abort(403)
    plano = query("SELECT * FROM bv_vpn_plans WHERE id=? AND user_id=?",
                  (pid, g.user["id"]), one=True)
    if not plano:
        flash("Plano não encontrado.", "erro")
        return redirect(url_for("botvendas.vpn_planos"))
    refs = _refs_do_plano(g.user["id"], pid)
    if refs:
        detalhe = "; ".join("%s: menu %s, botão \"%s\"" % r for r in refs[:5])
        flash("Exclusão bloqueada: este plano é usado por %d botão(ões) [%s]. "
              "Desative o plano ou corrija os botões no Editor antes de remover."
              % (len(refs), detalhe), "erro")
        return redirect(url_for("botvendas.vpn_planos"))
    vendas = query("SELECT COUNT(*) n FROM bv_sales WHERE vpn_plan_id=?",
                   (pid,), one=True)["n"]
    if vendas:
        flash("Exclusão bloqueada: este plano tem %d venda(s) no histórico. "
              "Para preservar o histórico, desative o plano em vez de excluir."
              % vendas, "erro")
        return redirect(url_for("botvendas.vpn_planos"))
    execute("DELETE FROM bv_vpn_plans WHERE id=? AND user_id=?", (pid, g.user["id"]))
    bv_audit(g.user["id"], "vpn_plan_deleted", "plano=%s" % plano["name"][:80])
    flash("Plano removido (nenhum botão ou venda o referenciava).", "ok")
    return redirect(url_for("botvendas.vpn_planos"))


@bp.route("/vpn-planos/teste/salvar", methods=["POST"])
def vpn_teste_salvar():
    if not g.user or not _assinatura_ou_403():
        abort(403)
    try:
        habilitado = 1 if request.form.get("test_enabled") == "1" else 0
        horas = int(request.form.get("test_duration_hours", "2"))
        if not 1 <= horas <= 24:
            raise ValueError
    except (ValueError, TypeError):
        flash("A duração do teste deve ser de 1 a 24 horas.", "erro")
        return redirect(url_for("botvendas.vpn_planos"))

    config_do_cliente(g.user["id"])  # garante a linha antes de gravar
    execute(
        "UPDATE bv_client_config SET test_enabled=?, test_duration_hours=?, updated_at=? "
        "WHERE user_id=?",
        (habilitado, horas, now(), g.user["id"])
    )
    flash("Configuração do teste grátis salva.", "ok")
    return redirect(url_for("botvendas.vpn_planos"))


# ---------------- vendas ----------------
@bp.route("/vendas")
def vendas():
    if not g.user:
        return redirect(url_for("auth.login"))
    _assinatura_ou_403()
    linhas = query("SELECT v.*, p.name AS plano FROM bv_sales v LEFT JOIN bv_vpn_plans p "
                   "ON p.id=v.vpn_plan_id WHERE v.user_id=? ORDER BY v.id DESC LIMIT 200",
                   (g.user["id"],))
    return render_template("botvendas/sales.html", vendas=linhas)


@bp.route("/vendas/<int:sid>/revogar", methods=["POST"])
def venda_revogar(sid):
    if not g.user:
        return redirect(url_for("auth.login"))
    _assinatura_ou_403()
    sale = query("SELECT * FROM bv_sales WHERE id=? AND user_id=?", (sid, g.user["id"]),
                 one=True)
    if sale and sale["status"] == "delivered" and sale["ssh_user"]:
        cfg = config_do_cliente(g.user["id"])
        if not cfg["vps_fp_confirmed_at"]:
            flash("Confirme a impressão digital da VPS antes de revogar contas.", "erro")
            return redirect(url_for("botvendas.vendas"))
        try:
            r = RemoteVPS(_cfg_vps(cfg)).remover_conta(sale["ssh_user"])
        except ErroSSH as e:
            r = SSHResult(False, err=str(e))
        if not r.ok:                              # só marca se a VPS confirmou
            flash("Não foi possível revogar na VPS: " + (r.err or "")[:200], "erro")
            return redirect(url_for("botvendas.vendas"))
        execute("UPDATE bv_sales SET status='cancelled', updated_at=? WHERE id=?",
                (now(), sid))
        bv_audit(g.user["id"], "sale_revoked", f"sale={sid}")
        flash("Conta revogada na VPS.", "ok")
    return redirect(url_for("botvendas.vendas"))


# ---------------- editor visual do bot ----------------
LAYOUT_PADRAO = {
    "welcome": "👋 Bem-vindo! Escolha uma opção no menu abaixo.",
    "support": "📞 Suporte: contate o proprietário pelo Telegram.",
    "menus": {"main": {"text": "📶 MENU PRINCIPAL", "rows": [
        [{"text": "♻️ GERAR TESTE ⏳", "action": "test"}],
        [{"text": "📲 BAIXAR APLICATIVO ⚡", "action": "apk"}],
        # CAUSA RAIZ do "Plano indisponível": o padrao antigo era buy:0, um
        # plano que nao existe. Agora o botao-padrao pede configuracao e o
        # cliente associa um plano real pelo Editor (buy:<id> de um plano ativo).
        [{"text": "💰 COMPRAR ACESSO 🔐",
          "action": "msg:Estamos finalizando a configuração dos planos. "
                    "Use SUPORTE para falar com o dono do bot."}],
        [{"text": "🆘 SUPORTE", "action": "support"}],
    ]}},
}


def _draft(user_id):
    cfg = config_do_cliente(user_id)
    if cfg["draft_layout"]:
        try:
            return json.loads(cfg["draft_layout"])
        except ValueError:
            pass
    return json.loads(json.dumps(LAYOUT_PADRAO))


def _salvar_draft(user_id, layout):
    execute("UPDATE bv_client_config SET draft_layout=?, updated_at=? WHERE user_id=?",
            (json.dumps(layout, ensure_ascii=False), now(), user_id))


def _validar_acao(acao):
    a = (acao or "").strip()
    if a in ("test", "apk", "support"):
        return a
    if a.startswith(("menu:", "buy:")):
        return a[:64]
    return None


def _montar_acao(form):
    """Monta a ação de um botão a partir do formulário (novo e editar).

    Devolve (acao, erro). Link e mensagem são validados aqui, e não aceitos
    como texto livre no campo de ação, para que nenhum caminho grave
    'link:' ou 'msg:' sem validação.
    """
    tipo = (form.get("action") or "").strip()
    if tipo == "link":
        url = (form.get("url") or "").strip()
        if not url.startswith(("https://", "http://")) or len(url) > 500 or " " in url:
            return None, "Informe um link válido começando com https:// ou http://."
        return "link:" + url, None
    if tipo == "msg":
        mensagem = (form.get("message") or "").strip()
        if not mensagem:
            return None, "Digite a mensagem que será enviada ao cliente."
        return "msg:" + mensagem[:3500], None
    acao = _validar_acao(tipo)
    if not acao:
        return None, "Escolha uma ação válida para o botão."
    return acao, None


def _planos_ids_ativos(user_id):
    """IDs dos planos VPN de venda (ativos, não-teste) do cliente."""
    return {p["id"]: p["name"] for p in query(
        "SELECT id, name FROM bv_vpn_plans WHERE user_id=? AND is_active=1 AND is_test=0",
        (user_id,))}


def _validar_layout(layout, user_id):
    """Valida um layout antes de publicar. Devolve lista de problemas legiveis.

    Verifica cada botao: buy:<id> precisa apontar para um plano existente,
    ativo, do proprio cliente; menu:<key> precisa existir; link: precisa ser
    http(s) e nenhum botao pode ficar sem acao.
    """
    problemas = []
    ativos = _planos_ids_ativos(user_id)
    menus = layout.get("menus") or {}
    for menu_key, menu in menus.items():
        for row in menu.get("rows") or []:
            for btn in row:
                texto = (btn.get("text") or "?").strip()[:40]
                acao = (btn.get("action") or "").strip()
                if acao.startswith("buy:"):
                    raw = acao[4:]
                    try:
                        pid = int(raw)
                    except ValueError:
                        problemas.append(
                            'Botao "%s" tem referencia de plano invalida ("%s").'
                            % (texto, acao))
                        continue
                    if pid not in ativos:
                        problemas.append(
                            'Botao "%s" aponta para o plano #%d, que nao existe '
                            "ou esta desativado." % (texto, pid))
                elif acao.startswith("menu:") and acao[5:] and acao[5:] not in menus:
                    problemas.append(
                        'Botao "%s" aponta para o menu "%s", que nao existe.'
                        % (texto, acao[5:]))
                elif acao.startswith("link:") and not acao[5:].startswith(
                        ("http://", "https://")):
                    problemas.append('Botao "%s" tem um link invalido.' % texto)
                elif acao in ("msg:", ""):
                    problemas.append('Botao "%s" esta sem acao.' % texto)
    return problemas


def _refs_do_plano(user_id, pid):
    """Onde um plano e referenciado: [(local, menu, texto_do_botao), ...].

    Local: 'publicado' ou 'rascunho'. Usado para avisar antes de excluir/
    desativar um plano e para nao deixar botoes apontando para nada.
    """
    refs = []
    cfg = config_do_cliente(user_id)
    for local, campo in (("publicado", "published_layout"),
                         ("rascunho", "draft_layout")):
        raw = cfg[campo]
        if not raw:
            continue
        try:
            layout = json.loads(raw)
        except (ValueError, TypeError):
            continue
        for menu_key, menu in (layout.get("menus") or {}).items():
            for row in menu.get("rows") or []:
                for btn in row:
                    a = (btn.get("action") or "")
                    if a.startswith("buy:") and a[4:] == str(pid):
                        refs.append((local, menu_key,
                                     (btn.get("text") or "?").strip()[:40]))
    return refs


@bp.route("/editor")
def editor():
    if not g.user:
        return redirect(url_for("auth.login"))
    sub = _assinatura_ou_403()
    layout = _draft(g.user["id"])
    cfg = config_do_cliente(g.user["id"])
    vpn = query("SELECT id, name FROM bv_vpn_plans WHERE user_id=? AND is_active=1 "
                "AND is_test=0", (g.user["id"],))
    return render_template("botvendas/editor.html", sub=sub, layout=layout,
                           cfg=cfg, vpn=vpn)


@bp.route("/editor/texto", methods=["POST"])
def editor_texto():
    if not g.user or not _assinatura_ou_403():
        abort(403)
    layout = _draft(g.user["id"])
    campo = request.form.get("campo")
    if campo in ("welcome", "support"):
        layout[campo] = (request.form.get("valor") or "")[:1000]
        _salvar_draft(g.user["id"], layout)
        flash("Texto salvo no rascunho.", "ok")
    return redirect(url_for("botvendas.editor"))


@bp.route("/editor/menu/novo", methods=["POST"])
def editor_menu_novo():
    if not g.user or not _assinatura_ou_403():
        abort(403)
    layout = _draft(g.user["id"])
    n = len(layout["menus"]) + 1
    while f"sub_{n}" in layout["menus"]:
        n += 1
    layout["menus"][f"sub_{n}"] = {
        "text": "Novo submenu",
        "rows": [[{
            "text": "⬅️ Voltar ao menu principal",
            "action": "menu:main"
        }]]
    }
    _salvar_draft(g.user["id"], layout)
    flash("Submenu criado.", "ok")
    return redirect(url_for("botvendas.editor"))


@bp.route("/editor/menu/<key>/remover", methods=["POST"])
def editor_menu_remover(key):
    if not g.user or not _assinatura_ou_403():
        abort(403)

    if key == "main":
        abort(400)

    layout = _draft(g.user["id"])
    menus = layout.get("menus", {})

    if key not in menus:
        abort(404)

    menus.pop(key)

    for menu in menus.values():
        for row in menu.get("rows", []):
            row[:] = [
                button for button in row
                if button.get("action") != "menu:" + key
            ]
        menu["rows"] = [row for row in menu.get("rows", []) if row]

    _salvar_draft(g.user["id"], layout)
    flash("Submenu excluído.", "ok")
    return redirect(url_for("botvendas.editor"))


@bp.route("/editor/menu/<key>/texto", methods=["POST"])
def editor_menu_texto(key):
    if not g.user or not _assinatura_ou_403():
        abort(403)
    layout = _draft(g.user["id"])
    if key in layout["menus"]:
        layout["menus"][key]["text"] = (request.form.get("valor") or "")[:1000]
        _salvar_draft(g.user["id"], layout)
    return redirect(url_for("botvendas.editor"))


@bp.route("/editor/menu/<key>/botao/novo", methods=["POST"])
def editor_botao_novo(key):
    if not g.user or not _assinatura_ou_403():
        abort(403)

    layout = _draft(g.user["id"])
    menu = layout["menus"].get(key)
    if not menu:
        abort(404)

    texto = (request.form.get("text") or "").strip()[:64]
    acao, erro = _montar_acao(request.form)
    if erro:
        flash(erro, "erro")
        return redirect(url_for("botvendas.editor"))
    if not texto:
        flash("Informe o texto do botão.", "erro")
        return redirect(url_for("botvendas.editor"))

    menu["rows"].append([{"text": texto, "action": acao}])
    _salvar_draft(g.user["id"], layout)
    flash("Botão adicionado.", "ok")
    return redirect(url_for("botvendas.editor"))

@bp.route("/editor/menu/<key>/botao/<int:rid>/<int:bid>", methods=["POST"])
def editor_botao_acao(key, rid, bid):
    if not g.user or not _assinatura_ou_403():
        abort(403)
    layout = _draft(g.user["id"])
    menu = layout["menus"].get(key)
    if not menu or rid >= len(menu["rows"]) or bid >= len(menu["rows"][rid]):
        abort(404)
    op = request.form.get("op")
    row = menu["rows"][rid]
    if op == "up" and rid > 0:
        menu["rows"].insert(rid - 1, menu["rows"].pop(rid))
    elif op == "down" and rid < len(menu["rows"]) - 1:
        menu["rows"].insert(rid + 1, menu["rows"].pop(rid))
    elif op == "remove":
        row.pop(bid)
        if not row:
            menu["rows"].pop(rid)
    elif op == "edit":
        texto = (request.form.get("text") or "").strip()[:64]
        acao, erro = _montar_acao(request.form)
        if erro or not texto:
            flash(erro or "Informe o texto do botão.", "erro")
            return redirect(url_for("botvendas.editor"))
        row[bid] = {"text": texto, "action": acao}
        _salvar_draft(g.user["id"], layout)
        flash("Botão atualizado no rascunho.", "ok")
        return redirect(url_for("botvendas.editor"))
    _salvar_draft(g.user["id"], layout)
    return redirect(url_for("botvendas.editor"))


@bp.route("/editor/preview")
def editor_preview():
    if not g.user:
        return redirect(url_for("auth.login"))
    _assinatura_ou_403()
    layout = _draft(g.user["id"])
    return render_template("botvendas/preview.html", layout=layout)


@bp.route("/editor/publicar", methods=["POST"])
def editor_publicar():
    if not g.user:
        return redirect(url_for("auth.login"))
    _assinatura_ou_403()
    config_do_cliente(g.user["id"])   # garante a linha antes do UPDATE
    layout = _draft(g.user["id"])
    try:
        json.dumps(layout)
    except ValueError:
        flash("Rascunho inválido.", "erro")
        return redirect(url_for("botvendas.editor"))
    problemas = _validar_layout(layout, g.user["id"])
    if problemas:
        # Publicacao bloqueada: a ultima versao valida publicada continua ativa.
        flash("Publicação bloqueada — %d problema(s) no menu:" % len(problemas), "erro")
        for pr in problemas[:8]:
            flash("• " + pr, "erro")
        if len(problemas) > 8:
            flash("… e mais %d problema(s)." % (len(problemas) - 8), "erro")
        return redirect(url_for("botvendas.editor"))
    execute("UPDATE bv_client_config SET published_layout=?, updated_at=? WHERE user_id=?",
            (json.dumps(layout, ensure_ascii=False), now(), g.user["id"]))
    bv_audit(g.user["id"], "layout_published")
    flash("Configuração validada e publicada.", "ok")
    return redirect(url_for("botvendas.editor"))


@bp.route("/editor/validar", methods=["POST"])
def editor_validar():
    """Valida o rascunho sem publicar (requisito 3.5 do briefing)."""
    if not g.user:
        return redirect(url_for("auth.login"))
    _assinatura_ou_403()
    problemas = _validar_layout(_draft(g.user["id"]), g.user["id"])
    if problemas:
        flash("Rascunho com %d problema(s) — publicação será bloqueada:"
              % len(problemas), "erro")
        for pr in problemas[:8]:
            flash("• " + pr, "erro")
    else:
        flash("Rascunho válido: todos os botões apontam para planos e menus "
              "existentes.", "ok")
    return redirect(url_for("botvendas.editor"))


# ---------------- start/stop do bot ----------------
@bp.route("/bot", methods=["POST"])
def bot_controle():
    if not g.user:
        return redirect(url_for("auth.login"))
    _assinatura_ou_403()
    acao = request.form.get("acao")
    if acao == "publicar":
        res = botruntime.publicar_bot(current_app._get_current_object(), g.user["id"])
        flash(res.get("erro", "Bot publicado e em execução.")
              if not res.get("ok") else "Bot publicado e em execução.",
              "ok" if res.get("ok") else "erro")
    elif acao == "parar":
        botruntime.parar_bot(g.user["id"])
        flash("Bot parado.", "ok")
    return redirect(url_for("botvendas.panel"))
