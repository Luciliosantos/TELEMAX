"""Operações SSH na VPS do cliente — comandos ADAPTADOS do BOT Vendas original.

Fonte real (botvenda-main/botvenda.sh e acompanhar_pagamento.sh):
- teste: useradd -M -N -s /bin/false <u> -e <data>; passwd; /etc/SSHPlus/senha/<u>;
         /root/usuarios.db "<u> <limite>"; expiração por at-job (aqui: central)
- compra: useradd 30 dias + chpasswd + /etc/SSHPlus/senha/<u> + usuarios.db
Adaptado para execução REMOTA (paramiko), sob demanda, com timeout, sem sessão
permanente, sem armazenar senha de root (chave dedicada + sudo de privilégio
mínimo). Os comandos de usuário NUNCA rodam no servidor central.

SEGURANÇA (endurecimento 2026-10):
- A chave pública do servidor SSH é verificada em TODA conexão (RejectPolicy).
  Primeiro uso (TOFU explícito): o método `registrar_fingerprint` captura a
  impressão digital (SHA256) e a grava PENDENTE; o dono confirma no painel
  (comparando com `ssh-keyscan` na própria VPS) e só então as operações
  conectam. Chave inesperadamente diferente → conexão interrompida + erro.
- Chave privada: RSA, ECDSA e Ed25519 (formato OpenSSH/PEM), sem senha.
- Comandos remotos: valores validados na origem (charset estrito) E
  shell-quoted; nenhum dado do usuário é concatenado cru.
- Exceções mapeadas (timeout/autenticação/desconexão/indisponibilidade) sem
  vazar chave privada ou senha em mensagens/registros.
"""
import datetime
import re
import secrets
import string

import paramiko
from flask import current_app

# ---------------- validação rígida de tudo que chega à VPS ----------------
RE_USER = re.compile(r"^[a-z_][a-z0-9_-]{0,10}$")     # useradd: <=32, minúsculas
RE_VPS_USER = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
SENHA_CHARSET = string.ascii_letters + string.digits   # sem metacaracteres
RE_DATA = re.compile(r"^\d{4}-\d{2}-\d{2}$")


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
    import base64
    import hashlib
    h = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(h).decode().rstrip("=")


# ---------------- scripts remotos FIXOS ----------------
# O corpo NUNCA contém dado de usuário: os valores chegam como argumentos
# posicionais ($1, $2...) já validados + shell-quoted, e são sempre usados
# entre aspas duplas. `set -eu` aborta no 1º erro (sem `|| true` mascarando).
# Executado via `bash -s -- args` com o script no stdin: nada a instalar na VPS.
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
    def __init__(self, ok, out="", err="", rc=0):
        self.ok, self.out, self.err, self.rc = ok, out, err, rc

    def __bool__(self):
        return self.ok


class ErroSSH(Exception):
    """Erro de conexão/protocolo com mensagem SEGURA (sem segredos)."""


class RemoteVPS:
    """Conecta por SSH sob demanda, executa e ENCERRA a conexão.

    cfg além dos campos do banco aceita:
    - _key_data: chave privada já descriptografada
    - _fingerprint: fingerprint confirmado pelo dono (SHA256:...);
      se ausente, NENHUMA operação conecta (a não ser _capturar=True).
    - _capturar: modo de cadastro inicial (primeiro uso): captura e devolve
      a chave do servidor SEM executar nada.
    """

    def __init__(self, cfg):
        self.host = (cfg.get("vps_host") or "").strip()
        bruto = cfg.get("vps_port")
        try:
            self.port = 22 if bruto in (None, "") else int(bruto)
        except (TypeError, ValueError):
            raise ErroSSH("Porta SSH inválida")
        if not (1 <= self.port <= 65535):
            raise ErroSSH("Porta SSH inválida")
        if not self.host:
            raise ErroSSH("Endereço da VPS não configurado")
        self.user = (cfg.get("vps_user") or "botvendas").strip()
        if not RE_VPS_USER.match(self.user):
            raise ErroSSH("Usuário SSH da VPS inválido (use a-z, 0-9, _ ou -)")
        self.keydata = cfg.get("_key_data") or ""
        self.fingerprint = (cfg.get("_fingerprint") or "").strip()
        self.capturar = bool(cfg.get("_capturar"))
        self.sudo = bool(cfg.get("vps_use_sudo", 1)) and self.user != "root"
        self.timeout = 15

    # ---------------- chave privada ----------------
    def _pkey(self):
        """Carrega RSA, ECDSA ou Ed25519 (OpenSSH/PEM), sem senha.

        Tenta cada classe concreta (PKey.from_private_key da base não funciona
        no paramiko 5.x). A mensagem de erro NUNCA inclui o conteúdo da chave.
        """
        if not self.keydata:
            raise ErroSSH("Chave privada ausente: gere-a no painel")
        from io import StringIO
        for cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
            try:
                return cls.from_private_key(StringIO(self.keydata))
            except (paramiko.SSHException, ValueError, TypeError):
                continue
        raise ErroSSH(
            "Chave privada inválida ou incompatível. Formatos aceitos: "
            "OpenSSH/PEM RSA, ECDSA ou Ed25519, sem senha (None).")

    # ---------------- conexão com verificação de host ----------------
    def _cliente(self):
        """Cliente com RejectPolicy: NUNCA aceita chave de servidor desconhecida."""
        key = self._pkey()
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        client.load_system_host_keys()
        try:
            client.get_host_keys().clear()      # ignora known_hosts do central
            if self.fingerprint:                 # confiança EXPLÍCITA do dono
                client.get_host_keys().add(f"[{self.host}]:{self.port}",
                                           self._tipos(key), key)
            client.connect(self.host, port=self.port, username=self.user,
                           pkey=key, timeout=self.timeout,
                           banner_timeout=self.timeout, auth_timeout=self.timeout,
                           allow_agent=False, look_for_keys=False)
            return client
        except paramiko.BadHostKeyException:
            self._fechar(client)
            raise ErroSSH(
                "A chave do servidor SSH MUDOU e não corresponde à impressão "
                "digital confirmada. Conexão interrompida por segurança — "
                "verifique a VPS e confirme a nova impressão no painel.") from None
        except paramiko.AuthenticationException:
            self._fechar(client)
            raise ErroSSH(
                "Autenticação SSH recusada: confira o usuário e se a chave "
                "pública está no authorized_keys da VPS.") from None
        except paramiko.SSHException as e:
            self._fechar(client)
            tipo = type(e).__name__
            raise ErroSSH(
                f"Servidor SSH indisponível ou handshake falhou ({tipo}). "
                "Verifique endereço, porta e se o serviço sshd está ativo.") from None
        except TimeoutError:
            self._fechar(client)
            raise ErroSSH("Tempo esgotado conectando à VPS (verifique IP/porta).") \
                from None
        except OSError as e:
            self._fechar(client)
            raise ErroSSH(
                "VPS inacessível (rede/indisponibilidade): verifique o endereço.") \
                from None

    def _tipos(self, server_key):          # pragma: no cover (helper)
        return server_key.get_name()

    def _fechar(self, client):
        try:
            client.close()
        except Exception:
            pass

    # ---------------- cadastro automático e instalação inicial ----------------
    def capturar_fingerprint(self):
        """Captura a chave do host sem enviar credenciais nem executar comandos.

        A primeira captura é TOFU (trust on first use): a identidade do servidor
        deve ser conferida por um canal confiável quando possível.
        """
        import socket
        transport = None
        sock = None
        try:
            sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
            transport = paramiko.Transport(sock)
            transport.banner_timeout = self.timeout
            transport.start_client(timeout=self.timeout)
            key = transport.get_remote_server_key()
            return _fingerprint(key), key.get_name()
        except (paramiko.SSHException, OSError, TimeoutError) as e:
            raise ErroSSH("Não foi possível capturar a chave SSH do servidor. "
                          "Confira IP, porta e serviço SSH.") from None
        finally:
            if transport:
                transport.close()
            elif sock:
                sock.close()

    def instalar_chave_com_senha(self, password, public_key):
        """Instala a chave pública após validar a fingerprint capturada.

        A senha é usada somente nesta chamada e não é gravada nem registrada.
        """
        import shlex
        if not isinstance(password, str) or not password or len(password) > 1024:
            raise ErroSSH("Informe a senha SSH inicial válida.")
        public_key = (public_key or "").strip()
        partes = public_key.split()
        if len(partes) < 2 or partes[0] not in (
                "ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256",
                "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"):
            raise ErroSSH("A chave pública gerada está inválida.")
        if not self.fingerprint:
            raise ErroSSH("Impressão digital do servidor não foi capturada.")

        expected = self.fingerprint
        class VerifyHost(paramiko.MissingHostKeyPolicy):
            def missing_host_key(_self, client, hostname, key):
                if _fingerprint(key) != expected:
                    raise paramiko.SSHException("Fingerprint SSH divergente")
                client.get_host_keys().add(hostname, key.get_name(), key)

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(VerifyHost())
        try:
            client.connect(self.host, port=self.port, username=self.user,
                           password=password, timeout=self.timeout,
                           banner_timeout=self.timeout, auth_timeout=self.timeout,
                           allow_agent=False, look_for_keys=False)
            # A chave é validada acima; agora instala apenas a chave pública.
            key_q = shlex.quote(public_key)
            command = ("set -eu; umask 077; mkdir -p ~/.ssh; chmod 700 ~/.ssh; "
                       "touch ~/.ssh/authorized_keys; chmod 600 ~/.ssh/authorized_keys; "
                       f"if ! grep -qxF -- {key_q} ~/.ssh/authorized_keys; then "
                       f"printf '%s\\n' {key_q} >> ~/.ssh/authorized_keys; fi")
            _stdin, stdout, stderr = client.exec_command(command, timeout=30)
            rc = stdout.channel.recv_exit_status()
            err = stderr.read().decode(errors="replace").strip()
            if rc != 0:
                return SSHResult(False, err=(err or "Não foi possível gravar authorized_keys")[:300], rc=rc)
            return SSHResult(True, "CHAVE_INSTALADA")
        except paramiko.AuthenticationException:
            raise ErroSSH("Autenticação SSH recusada: confira usuário e senha, e se o servidor permite login por senha.") from None
        except paramiko.SSHException as e:
            if "Fingerprint SSH divergente" in str(e):
                raise ErroSSH("A chave do servidor mudou durante a conexão. Instalação cancelada por segurança.") from None
            raise ErroSSH("Falha no protocolo SSH durante a instalação. Confira o serviço SSH.") from None
        except (OSError, TimeoutError):
            raise ErroSSH("Servidor SSH inacessível ou tempo esgotado.") from None
        finally:
            client.close()

    # ---------------- execução ----------------
    def _exec_script(self, script, args):
        """Executa um script FIXO via `bash -s -- args`, script no stdin.

        `args` já foram validados; ainda assim cada um é shell-quoted. O usuário
        sudo (quando não root) roda o bash inteiro com `sudo -n` — o sudoers
        concede apenas `/bin/bash -s -- *`? Não: ver docs/BOTVENDAS.md, que
        documenta a alternativa de comandos individuais com privilégio mínimo.
        """
        cmd = "bash -s -- " + " ".join(_shquote(a) for a in args)
        return self._run_cmd(self._p(cmd), stdin_data=script)

    def _run_cmd(self, cmd, stdin_data=None):
        try:
            client = self._cliente()
        except ErroSSH as e:
            return SSHResult(False, err=str(e))
        try:
            stdin, stdout, stderr = client.exec_command(cmd, timeout=30)
            if stdin_data is not None:
                stdin.write(stdin_data)
                stdin.flush()
                stdin.channel.shutdown_write()
            rc = stdout.channel.recv_exit_status()
            out = stdout.read().decode(errors="replace").strip()
            err = stderr.read().decode(errors="replace").strip()
            return SSHResult(rc == 0, out, err, rc)
        except paramiko.SSHException as e:
            return SSHResult(False, err=f"Desconexão SSH durante o comando "
                                        f"({type(e).__name__}).")
        except OSError:
            return SSHResult(False, err="Conexão perdida com a VPS.")
        finally:
            self._fechar(client)

    def _p(self, cmd):
        """Prefixa sudo -n quando o usuário dedicado não é root."""
        return f"sudo -n {cmd}" if self.sudo else cmd

    # ---------------- operações adaptadas do BOT Vendas ----------------
    # Todos os parâmetros: validados na origem + passados como ARGUMENTOS do
    # script remoto fixo. Nenhum valor de usuário é concatenado em comando.

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


def gerar_credenciais_ssh(prefixo="ssh"):
    """Usuario/senha no MESMO formato do bot original (useradd exige <=32 chars).

    Charset alfanumérico: nenhum metacaracter de shell pode aparecer.
    """
    alfabeto = string.ascii_letters + string.digits
    usuario = prefixo + "".join(secrets.choice(string.digits) for _ in range(5))
    senha = "".join(secrets.choice(SENHA_CHARSET) for _ in range(10))
    return usuario, senha
