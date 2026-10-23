#!/usr/bin/env python3
"""Tarefa agendada (cron/systemd timer): expira promoções e cobranças vencidas."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("FLASK_ENV", "production")
from telemax import create_app
from telemax.db import execute
from telemax.security import now

app = create_app()
with app.app_context():
    a = execute("UPDATE promotions SET is_active = 0 WHERE is_active = 1 AND ends_at <= ?", (now(),))
    b = execute("UPDATE payments SET status = 'expired' WHERE status = 'pending' AND expires_at <= ?", (now(),))
    print(f"{a or 0} promoções expiradas; {b or 0} cobranças expiradas.")
