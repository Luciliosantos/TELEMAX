"""Operações SSH na VPS do cliente — comandos ADAPTADOS do BOT Vendas original.

Fonte real (botvenda-main/botvenda.sh e acompanhar_pagamento.sh):
- teste: useradd -M -N -s /bin/false <u> -e <data>; passwd; /etc/SSHPlus/senha/<u>;
         /root/usuarios.db "<u> <limite>"; expiração por at-job (aqui: central)
- compra: useradd 30 dias + chpasswd + /etc/SSHPlus/senha/<u> + usuarios.db
Adaptado para execução REMOTA (paramiko), sob demanda, com timeout, sem sessão
permanente. Os comandos de usuário NUNCA rodam no servidor central.

SEGURANÇA
- A identidade do servidor é verificada em TODA conexão: a chave pública do
  servidor precisa ter a impressão digital (SHA256) registrada. Nenhuma chave
  desconhecida é aceita (política _PinnedHostKey). Se a chave mudar, a conexão
  é interrompida com erro explícito.
- A chave pública do SERVIDOR (identidade da VPS) é tratada à parte da chave
  pública do CLIENTE (autenticação), que é gerada aqui e instalada na VPS.
- A senha SSH é usada apenas para instalar a chave pública e nunca aparece em
  logs ou mensagens. Os erros carregam uma etapa (`etapa`), não segredos.
"""
import base64
import datetime
import hashlib
import io
import re
import secrets
import socket
import string

import paramiko

# ---------------- validação rígida de tudo que chega à VPS ----------------
RE_USER = re.compile(r"^[a-z_][a-z0-9_-]{0,10}$")     # useradd: <=32, minúsculas
RE_VPS_USER = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
RE_PUBKEY = re.compile(r"^ssh-ed25519 [A-Za-z0-9+/=]{20,}(?: [A-Za-z0-9@._-]{1,64})?$")
SENHA_CHARSET = string.ascii_letters + string.digits   # sem metacaracteres
RE_DATA = re.compile(r"^\d{4}-\d{2}-\d{2}$")

MSG_FP_MUDOU = ("A identidade do servidor mudou: a chave do servidor não confere com a "
                "impressão digital registrada. Conexão bloqueada por segurança. Se você "
                "trocou ou reinstalou a VPS, remova a identidade registrada no painel "
                "(REDEFINIR IDENTIDADE) e teste de novo.")


def _shquote(valor):
    """Shell-quote à prova de injeção: envolve em aspas simples e escapa ' ."""
    return "'" + str(valor).replace("'", "'\\''") + "'"


def validar_usuario_ssh(nome):
    """Usuário de sistema na VPS do cliente: charset estrito, sem shell meta."""
    return bool(nome) and bool(RE_USER.match(nome)) and "root" not in nome


def validar_data_exp(dia):
    try:
        datetime.date.fromisoformat(dia)
    except ValueError:
        return False
    return bool(RE_DATA.match(dia))


def _fingerprint(key):
    """Impressão digital no formato OpenSSH: SHA256:... (base64 sem padding)."""
    h = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(h).decode().rstrip("=")


# ---------------- scripts remotos FIXOS ----------------
# O corpo NUNCA contém dado de usuário: os valores chegam como argumentos
# posicionais ($1, $2...) já validados + shell-quoted.
# `set -eu` aborta no 1º erro (sem `|| true` mascarando).
SCRIPT_CRIAR = r"""set -eu
U="$1"; S="$2"; EXP="$3"; LIM="$4"
useradd -M -N -s /bin/false -e "$EXP" "$U"
printf '%s:%s\n' "$U" "$S" | chpasswd
mkdir -p /etc/SSHPlus/senha
printf '%s\n' "$S" > "/etc/SSHPlus/senha/$U"
chmod 600 "/etc/SSHPlus/senha/$U"
touch /root/usuarios.db
grep -q "^$U " /root/usuarios.db || printf '%s %s\n' "$U" "$LIM" >> /root/usuarios.db
echo TM_CRIADO
"""
SCRIPT_REMOVER = r"""set -u
U="$1"
pkill -u "$U" 2>/dev/null || true
if id "$U" >/dev/null 2>&1; then userdel --force "$U"; fi
rm -f "/etc/SSHPlus/senha/$U"
if [ -f /root/usuarios.db ]; then sed -i "/^$U /d" /root/usuarios.db; fi
if id "$U" >/dev/null 2>&1; then echo TM_FALHOU; exit 1; fi
echo TM_REMOVIDO
"""
SCRIPT_RENOVAR = r"""set -eu
U="$1"; EXP="$2"
id "$U" >/dev/null 2>&1
usermod -e "$EXP" "$U"
echo TM_RENOVADO
"""
SCRIPT_CONSULTAR = r"""set -eu
U="$1"
id "$U"
chage -l "$U"
"""


class SSHResult:
    def __init__(self, ok, out="", err="", rc=0, etapa=None):
        self.ok, self.out, self.err, self.rc = ok, out, err, rc
        self.etapa = etapa          # onde falhou: conexao, handshake, fingerprint, auth...

    def __bool__(self):
        return self.ok


class ErroSSH(Exception):
    """Erro de conexão/protocolo com mensagem SEGURA (sem segredos) e etapa."""

    def __init__(self, mensagem, etapa="conexao"):
        super().__init__(mensagem)
        self.etapa = etapa


class _FingerprintDiferente(Exception):
    """Chave do servidor não confere com a impressão digital registrada."""


class _PinnedHostKey(paramiko.MissingHostKeyPolicy):
    """Aceita SOMENTE a chave de servidor cuja impressão digital é a registrada.

    O paramiko consulta esta política para toda chave que não está em known_hosts
    (known_hosts do sistema é ignorado de propósito). Sem impressão digital, nada
    é aceito.
    """

    def __init__(self, fingerprint):
        self.fingerprint = fingerprint or ""

    def missing_host_key(self, client, hostname, key):
        if not self.fingerprint or _fingerprint(key) != self.fingerprint:
            raise _FingerprintDiferente(hostname)


def _erro_conexao(e):
    """Mapeia exceções de rede/protocolo para uma ErroSSH com etapa clara."""
    if isinstance(e, _FingerprintDiferente):
        return ErroSSH(MSG_FP_MUDOU, "fingerprint")
    if isinstance(e, paramiko.AuthenticationException):
        return ErroSSH("Autenticação recusada pela VPS.", "auth")
    if isinstance(e, (socket.timeout, TimeoutError)):
        return ErroSSH("Tempo esgotado ao conectar na VPS (verifique IP e porta).",
                       "conexao")
    if isinstance(e, paramiko.SSHException):
        return ErroSSH("A porta respondeu, mas o servidor não completou o handshake SSH "
                       "(verifique se o sshd está ativo nessa porta).", "handshake")
    return ErroSSH("VPS inacessível: não foi possível conectar (IP, porta ou firewall).",
                   "conexao")


def _obter_chave_servidor(host, port, timeout):
    """Só o handshake SSH, sem autenticar: lê a chave pública do SERVIDOR.

    Equivale ao ssh-keyscan. Nenhuma credencial do cliente é enviada aqui.
    """
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as e:
        raise _erro_conexao(e) from None
    transport = None
    try:
        transport = paramiko.Transport(sock)
        transport.start_client(timeout=timeout)
        return transport.get_remote_server_key()
    except (paramiko.SSHException, EOFError, OSError) as e:
        raise _erro_conexao(e) from None
    finally:
        if transport is not None:
            transport.close()
        else:
            sock.close()


class RemoteVPS:
    """Conecta por SSH sob demanda, executa e ENCERRA a conexão.

    cfg além dos campos do banco aceita:
    - _key_data: chave privada do cliente (OpenSSH), já descriptografada
    - _fingerprint: impressão digital registrada da chave do servidor (SHA256:...)
    """

    def __init__(self, cfg):
        self.host = (cfg.get("vps_host") or "").strip()
        bruto = cfg.get("vps_port")
        try:
            self.port = 22 if bruto in (None, "") else int(bruto)
        except (TypeError, ValueError):
            raise ErroSSH("Porta SSH inválida", "dados") from None
        if not (1 <= self.port <= 65535):
            raise ErroSSH("Porta SSH inválida", "dados")
        if not self.host:
            raise ErroSSH("Endereço da VPS não configurado", "dados")
        self.user = (cfg.get("vps_user") or "botvendas").strip()
        if not RE_VPS_USER.match(self.user):
            raise ErroSSH("Usuário SSH da VPS inválido (use a-z, 0-9, _ ou -)", "dados")
        self.keydata = cfg.get("_key_data") or ""
        self.fingerprint = (cfg.get("_fingerprint") or "").strip()
        self.sudo = bool(cfg.get("vps_use_sudo", 1)) and self.user != "root"
        self.timeout = 15

    # ---------------- chave privada do cliente ----------------
    def _pkey(self):
        """Carrega Ed25519, RSA ou ECDSA (OpenSSH/PEM), sem senha.

        A mensagem de erro NUNCA inclui o conteúdo da chave.
        """
        if not self.keydata:
            raise ErroSSH("Chave privada ausente: clique em TESTAR CONEXÃO para gerá-la.",
                          "chave")
        for cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
            try:
                return cls.from_private_key(io.StringIO(self.keydata))
            except (paramiko.SSHException, ValueError, TypeError):
                continue
        raise ErroSSH("Chave privada inválida ou incompatível.", "chave")

    # ---------------- conexão autenticada por chave ----------------
    def _cliente(self):
        key = self._pkey()
        if not self.fingerprint:
            raise ErroSSH("Identidade do servidor ainda não registrada. "
                          "Clique em TESTAR CONEXÃO.", "fingerprint")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(_PinnedHostKey(self.fingerprint))
        try:
            client.connect(self.host, port=self.port, username=self.user, pkey=key,
                           timeout=self.timeout, banner_timeout=self.timeout,
                           auth_timeout=self.timeout, allow_agent=False,
                           look_for_keys=False)
            return client
        except Exception as e:
            client.close()
            raise _erro_conexao(e) from None

    # ---------------- captura da identidade do servidor ----------------
    def capturar_fingerprint(self):
        """Lê a impressão digital do servidor (handshake, sem autenticar)."""
        key = _obter_chave_servidor(self.host, self.port, self.timeout)
        return _fingerprint(key), key.get_name()

    # ---------------- instalação da chave pública do cliente ----------------
    def instalar_chave_com_senha(self, password, pubkey):
        """Grava a chave pública em ~/.ssh/authorized_keys usando a senha SSH.

        A identidade do servidor é validada ANTES de a senha ser enviada.
        A senha não é guardada nem registrada em log.
        """
        if not RE_PUBKEY.match(pubkey or ""):
            return SSHResult(False, err="Chave pública em formato inesperado.",
                             etapa="chave")
        if not self.fingerprint:
            return SSHResult(False, err="Identidade do servidor não registrada.",
                             etapa="fingerprint")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(_PinnedHostKey(self.fingerprint))
        try:
            client.connect(self.host, port=self.port, username=self.user,
                           password=password, timeout=self.timeout,
                           banner_timeout=self.timeout, auth_timeout=self.timeout,
                           allow_agent=False, look_for_keys=False)
        except Exception as e:
            client.close()
            erro = _erro_conexao(e)
            if erro.etapa == "auth":
                return SSHResult(False, err="Senha SSH recusada pela VPS.",
                                 etapa="auth_senha")
            return SSHResult(False, err=str(erro), etapa=erro.etapa)
        try:
            chave = _shquote(pubkey)
            cmd = ("mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys"
                   " && chmod 600 ~/.ssh/authorized_keys"
                   f" && (grep -qxF {chave} ~/.ssh/authorized_keys"
                   f" || echo {chave} >> ~/.ssh/authorized_keys) && echo TM_CHAVE_OK")
            _, stdout, _ = client.exec_command(cmd, timeout=30)
            rc = stdout.channel.recv_exit_status()
            out = stdout.read().decode(errors="replace")
            if rc == 0 and "TM_CHAVE_OK" in out:
                return SSHResult(True, out="TM_CHAVE_OK")
            return SSHResult(False, err="Não foi possível gravar a chave em "
                                        "~/.ssh/authorized_keys (verifique permissões).",
                             etapa="instalar_chave")
        except (paramiko.SSHException, OSError):
            return SSHResult(False, err="Conexão perdida durante a instalação da chave.",
                             etapa="instalar_chave")
        finally:
            client.close()

    # ---------------- execução ----------------
    def _exec_script(self, script, args):
        """Executa um script FIXO via `bash -s -- args`, script no stdin."""
        cmd = "bash -s -- " + " ".join(_shquote(a) for a in args)
        return self._run_cmd(self._p(cmd), stdin_data=script)

    def _run_cmd(self, cmd, stdin_data=None):
        try:
            client = self._cliente()
        except ErroSSH as e:
            return SSHResult(False, err=str(e), etapa=e.etapa)
        try:
            stdin, stdout, stderr = client.exec_command(cmd, timeout=30)
            if stdin_data is not None:
                stdin.write(stdin_data)
                stdin.flush()
                stdin.channel.shutdown_write()
            rc = stdout.channel.recv_exit_status()
            out = stdout.read().decode(errors="replace").strip()
            err = stderr.read().decode(errors="replace").strip()
            return SSHResult(rc == 0, out, err, rc, None if rc == 0 else "comando")
        except paramiko.SSHException as e:
            return SSHResult(False, err=f"Desconexão SSH durante o comando "
                                        f"({type(e).__name__}).", etapa="comando")
        except OSError:
            return SSHResult(False, err="Conexão perdida com a VPS.", etapa="comando")
        finally:
            client.close()

    def _p(self, cmd):
        """Prefixa sudo -n quando o usuário dedicado não é root."""
        return f"sudo -n {cmd}" if self.sudo else cmd

    # ---------------- verificação de requisitos ----------------
    def checar_requisitos(self):
        """Confere se a VPS tem o necessário para criar contas (conexão já feita)."""
        r = self._run_cmd("command -v useradd chpasswd chage usermod sed grep "
                          ">/dev/null 2>&1 && echo TM_REQ_OK")
        if not (r.ok and "TM_REQ_OK" in r.out):
            return SSHResult(False, err="Servidor sem os utilitários necessários "
                                        "(useradd, chpasswd, chage, usermod, sed, grep).",
                             etapa="requisitos")
        if self.sudo:
            r = self._run_cmd("sudo -n true && echo TM_SUDO_OK")
            if not (r.ok and "TM_SUDO_OK" in r.out):
                return SSHResult(False, err="O usuário não tem sudo sem senha (sudo -n). "
                                            "Configure o sudoers ou desmarque a opção sudo.",
                                 etapa="requisitos")
        return SSHResult(True, out="TM_REQ_OK")

    # ---------------- operações adaptadas do BOT Vendas ----------------
    def conectividade(self):
        return self._run_cmd("echo TMOK && id -un")

    def criar_conta(self, usuario, senha, dias, limite=1):
        if not validar_usuario_ssh(usuario):
            return SSHResult(False, err="Nome de usuário inválido para a VPS")
        if not senha or any(c not in SENHA_CHARSET for c in senha):
            return SSHResult(False, err="Senha inválida (use alfanumérico)")
        if not isinstance(dias, int) or not (1 <= dias <= 3650):
            return SSHResult(False, err="Validade em dias inválida")
        if not isinstance(limite, int) or not (1 <= limite <= 999):
            return SSHResult(False, err="Limite de conexões inválido")
        exp = (datetime.datetime.now(datetime.timezone.utc) +
               datetime.timedelta(days=dias)).strftime("%Y-%m-%d")
        r = self._exec_script(SCRIPT_CRIAR, [usuario, senha, exp, str(limite)])
        r.ok = r.ok and "TM_CRIADO" in r.out
        return r

    def renovar_conta(self, usuario, dias):
        if not validar_usuario_ssh(usuario):
            return SSHResult(False, err="Nome de usuário inválido para a VPS")
        if not isinstance(dias, int) or not (1 <= dias <= 3650):
            return SSHResult(False, err="Validade em dias inválida")
        exp = (datetime.datetime.now(datetime.timezone.utc) +
               datetime.timedelta(days=dias)).strftime("%Y-%m-%d")
        r = self._exec_script(SCRIPT_RENOVAR, [usuario, exp])
        r.ok = r.ok and "TM_RENOVADO" in r.out
        return r

    def remover_conta(self, usuario):
        if not validar_usuario_ssh(usuario):
            return SSHResult(False, err="Nome de usuário inválido para a VPS")
        r = self._exec_script(SCRIPT_REMOVER, [usuario])
        r.ok = r.ok and "TM_REMOVIDO" in r.out
        return r

    def consultar(self, usuario):
        if not validar_usuario_ssh(usuario):
            return SSHResult(False, err="Nome de usuário inválido para a VPS")
        return self._exec_script(SCRIPT_CONSULTAR, [usuario])


# ---------------- fluxo único do botão TESTAR CONEXÃO ----------------
def testar_conexao_completo(cfg, senha=""):
    """Executa, em ordem, todas as etapas da conexão com a VPS.

    Devolve dict:
      ok              -> True só se TODAS as etapas passaram
      etapas          -> lista de {"nome", "ok", "msg"} (para exibir no painel)
      fingerprint     -> impressão digital do servidor (nova, se não havia)
      chave_instalada -> True se a chave pública foi instalada nesta execução
      senha_aceita    -> True se a senha foi aceita pela VPS
    Para na primeira falha, com a etapa e a causa. Nunca inclui segredos.
    """
    etapas = []
    res = {"ok": False, "etapas": etapas, "fingerprint": None, "tipo": None,
           "chave_instalada": False, "senha_aceita": False}

    def passo(nome, ok, msg):
        etapas.append({"nome": nome, "ok": ok, "msg": msg})
        return ok

    # 1) dados cadastrados
    try:
        base = dict(cfg)
        rv = RemoteVPS(base)
    except ErroSSH as e:
        passo("Dados da VPS", False, str(e))
        return res
    passo("Dados da VPS", True, f"{rv.user}@{rv.host}:{rv.port}")

    # 2) identidade do servidor (chave pública do SERVIDOR)
    try:
        fp, tipo = rv.capturar_fingerprint()
    except ErroSSH as e:
        passo("Identidade do servidor", False, str(e))
        return res
    registrada = (base.get("vps_fingerprint") or "").strip()
    if registrada and fp != registrada:
        passo("Identidade do servidor", False, MSG_FP_MUDOU)
        return res
    res["fingerprint"] = None if registrada else fp
    res["tipo"] = tipo
    passo("Identidade do servidor", True,
          f"{tipo} {fp}" + (" (já registrada)" if registrada else
                            " (registrada no primeiro contato)"))

    # 3) autenticação por chave (chave pública do CLIENTE)
    rv = RemoteVPS(dict(base, _key_data=base.get("_key_data") or "", _fingerprint=fp))
    r = rv.conectividade()
    if r.ok and "TMOK" in r.out:
        passo("Autenticação por chave", True, "entrou na VPS com a chave do painel")
    else:
        if r.etapa != "auth":
            passo("Autenticação por chave", False, r.err or "falha de conexão")
            return res
        # 4) instalar a chave pública, usando a senha uma única vez
        if not senha:
            passo("Autenticação por chave", False,
                  "A chave ainda não está instalada na VPS. Informe a senha SSH, "
                  "clique em CONFIRMAR SENHA e depois em TESTAR CONEXÃO.")
            return res
        ri = rv.instalar_chave_com_senha(senha, cfg.get("vps_pubkey") or "")
        if not ri.ok:
            passo("Instalar chave pública", False, ri.err or "falha ao instalar a chave")
            return res
        res["senha_aceita"] = True
        res["chave_instalada"] = True
        passo("Instalar chave pública", True, "chave gravada em authorized_keys")
        r = rv.conectividade()
        if not (r.ok and "TMOK" in r.out):
            passo("Autenticação por chave instalada", False,
                  "Falha ao autenticar usando a chave instalada: " + (r.err or "sem resposta"))
            return res
        passo("Autenticação por chave instalada", True, "entrou na VPS com a chave do painel")

    # 5) requisitos para criar contas
    rq = rv.checar_requisitos()
    if not rq.ok:
        passo("Requisitos do servidor", False,
              "Conexão estabelecida, mas o servidor não tem o necessário: " + rq.err)
        return res
    passo("Requisitos do servidor", True, "utilitários e permissões OK")

    res["ok"] = True
    return res


def gerar_credenciais_ssh(prefixo="ssh"):
    """Usuario/senha no MESMO formato do bot original (useradd exige <=32 chars).

    Charset alfanumérico: nenhum metacaracter de shell pode aparecer.
    """
    alfabeto = string.ascii_letters + string.digits
    usuario = prefixo + "".join(secrets.choice(string.digits) for _ in range(5))
    senha = "".join(secrets.choice(SENHA_CHARSET) for _ in range(10))
    return usuario, senha
