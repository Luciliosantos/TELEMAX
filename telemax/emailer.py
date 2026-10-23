"""Envio de e-mail: console (dev) ou SMTP (producao)."""
import smtplib
from email.mime.text import MIMEText

from flask import current_app

def send_email(to, subject, body):
    cfg = current_app.config
    backend = cfg.get("EMAIL_BACKEND", "console")
    if backend == "console":
        current_app.logger.info("[EMAIL console] para=%s assunto=%s corpo=%s", to, subject, body)
        return True
    try:
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = cfg["EMAIL_FROM"]
        msg["To"] = to
        with smtplib.SMTP(cfg["SMTP_HOST"], cfg["SMTP_PORT"], timeout=15) as s:
            s.starttls()
            s.login(cfg["SMTP_USER"], cfg["SMTP_PASSWORD"])
            s.sendmail(cfg["EMAIL_FROM"], [to], msg.as_string())
        return True
    except Exception as e:
        current_app.logger.error("falha ao enviar e-mail para %s: %s", to, e)
        return False
