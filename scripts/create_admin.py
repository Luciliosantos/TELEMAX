#!/usr/bin/env python3
"""Cria o administrador inicial do TELEMAX de forma segura.
Nunca use senha padrão: o script exige apelido, e-mail e senha forte.

Uso:
  python scripts/create_admin.py
  (ou) python scripts/create_admin.py --nickname admin --email voce@dominio.com
"""
import argparse
import getpass
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("FLASK_ENV", "production")

from telemax import create_app            # noqa: E402
from telemax.db import query, execute     # noqa: E402
from telemax.security import (hash_password, now, valid_email, valid_nickname,
                              valid_password)  # noqa: E402

def main():
    ap = argparse.ArgumentParser(description="Cria administrador do TELEMAX")
    ap.add_argument("--nickname"); ap.add_argument("--email")
    args = ap.parse_args()
    nick = args.nickname or input("Apelido do administrador: ").strip()
    email = (args.email or input("E-mail do administrador: ")).strip().lower()
    pw = getpass.getpass("Senha (mín. 8, letras e números): ")
    pw2 = getpass.getpass("Confirmar senha: ")
    if not valid_nickname(nick):
        sys.exit("Apelido inválido (3-30 caracteres, sem espaços).")
    if not valid_email(email):
        sys.exit("E-mail inválido.")
    if not valid_password(pw):
        sys.exit("Senha fraca: use ao menos 8 caracteres com letras e números.")
    if pw != pw2:
        sys.exit("As senhas não conferem.")
    app = create_app()
    with app.app_context():
        if query("SELECT id FROM users WHERE nickname = ? OR email = ?", (nick, email), one=True):
            sys.exit("Já existe usuário com este apelido ou e-mail.")
        uid = execute("INSERT INTO users(nickname, email, password_hash, role, created_at) "
                      "VALUES (?,?,?,'admin',?)", (nick, email, hash_password(pw), now()))
        print(f"Administrador criado com sucesso (id={uid}). Guarde esta senha com segurança.")

if __name__ == "__main__":
    main()
