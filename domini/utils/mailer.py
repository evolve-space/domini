from __future__ import annotations

import hashlib
import logging
import logging.handlers
import os
import smtplib
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path

from config import Config


def send_reset_email(email: str, token: str) -> None:
    base_url = Config.APP_BASE_URL.rstrip("/")
    link = f"{base_url}/reset-password/{token}"
    mail_settings = {
        "server": os.getenv("MAIL_SERVER"),
        "port": os.getenv("MAIL_PORT"),
        "username": os.getenv("MAIL_USERNAME"),
        "password": os.getenv("MAIL_PASSWORD"),
        "from": os.getenv("MAIL_FROM"),
    }
    if not all(mail_settings.values()):
        pending_log = Path(__file__).resolve().parents[2] / "instance" / "pending_resets.log"
        pending_log.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).isoformat()
        email_prefix = hashlib.sha256(email.encode()).hexdigest()[:12]
        _reset_logger = logging.getLogger("domini.pending_resets")
        if not _reset_logger.handlers:
            _handler = logging.handlers.RotatingFileHandler(
                str(pending_log), maxBytes=1_048_576, backupCount=5, encoding="utf-8"
            )
            _reset_logger.addHandler(_handler)
            _reset_logger.setLevel(logging.INFO)
        _reset_logger.info("[%s] password reset requested for email_sha256_prefix=%s", timestamp, email_prefix)
        return

    message = EmailMessage()
    message["Subject"] = "DOMINI — Recuperación de contraseña"
    message["From"] = mail_settings["from"]
    message["To"] = email
    message.set_content(f"Abre este enlace para restablecer tu contraseña:\n\n{link}\n")
    message.add_alternative(
        f"<p>Abre este enlace para restablecer tu contraseña:</p><p><a href=\"{link}\">{link}</a></p>",
        subtype="html",
    )
    with smtplib.SMTP(mail_settings["server"], int(mail_settings["port"]), timeout=10) as smtp:
        smtp.starttls()
        smtp.login(mail_settings["username"], mail_settings["password"])
        smtp.send_message(message)
