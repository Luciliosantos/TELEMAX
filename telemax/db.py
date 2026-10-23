"""Camada de banco: SQLite com migracoes versionadas."""
import os
import sqlite3
from flask import current_app, g

MIGRATIONS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "migrations")

def get_db():
    if "db" not in g:
        os.makedirs(os.path.dirname(current_app.config["DATABASE_PATH"]), exist_ok=True)
        conn = sqlite3.connect(current_app.config["DATABASE_PATH"], timeout=20)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        g.db = conn
    return g.db

def close_db(exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def query(sql, args=(), one=False):
    cur = get_db().execute(sql, args)
    rows = cur.fetchall()
    cur.close()
    return (rows[0] if rows else None) if one else rows

def execute(sql, args=()):
    db = get_db()
    cur = db.execute(sql, args)
    db.commit()
    return cur.lastrowid

def applied_migrations(db):
    db.execute("CREATE TABLE IF NOT EXISTS schema_migrations ("
               "version TEXT PRIMARY KEY, applied_at TEXT DEFAULT CURRENT_TIMESTAMP)")
    return {r["version"] for r in db.execute("SELECT version FROM schema_migrations").fetchall()}

def run_migrations():
    """Aplica migrations pendentes em ordem alfabetica (idempotente)."""
    db = get_db()
    done = applied_migrations(db)
    files = sorted(f for f in os.listdir(MIGRATIONS_DIR) if f.endswith(".sql"))
    for f in files:
        if f in done:
            continue
        with open(os.path.join(MIGRATIONS_DIR, f), encoding="utf-8") as fh:
            sql = fh.read()
        db.executescript(sql)
        db.execute("INSERT INTO schema_migrations(version) VALUES (?)", (f,))
        db.commit()

def init_app(app):
    app.teardown_appcontext(close_db)
