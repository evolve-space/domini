from __future__ import annotations

import os
import smtplib
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path


def send_reset_email(email: str, token: str, base_url: str) -> None:
    link = f"{base_url.rstrip('/')}/reset-password/{token}"
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
        with pending_log.open("a", encoding="utf-8") as output:
            output.write(f"[{timestamp}] password reset requested for email={email}\n")
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
