import os
import logging
import secrets
from datetime import timedelta
from pathlib import Path

from translations import TRANSLATIONS


BASE_DIR = Path(__file__).resolve().parent
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    SECRET_KEY = secrets.token_hex(32)
    logging.getLogger(__name__).warning("SECRET_KEY is not set; using an ephemeral key and sessions will not persist across restarts.")


_database_url = os.getenv("DATABASE_URL")
if not _database_url:
    _instance_dir = BASE_DIR / "instance"
    _instance_dir.mkdir(exist_ok=True)
    _database_url = f"sqlite:///{_instance_dir / 'domini.db'}"


_WEAK_ADMIN_PASSWORDS = {"domini2024", "password", "admin", ""}


def validate_secrets() -> None:
    """Abort startup when weak credentials are detected outside dev mode."""
    dev_mode = os.getenv("FLASK_ENV", "production").lower() == "development"
    if dev_mode:
        return
    pwd = os.getenv("ADMIN_PASSWORD", "")
    errors: list[str] = []
    if pwd in _WEAK_ADMIN_PASSWORDS:
        errors.append("ADMIN_PASSWORD must not be a well-known default value.")
    if len(pwd) < 16:
        errors.append("ADMIN_PASSWORD must be at least 16 characters.")
    if errors:
        for msg in errors:
            logging.getLogger(__name__).critical("Security misconfiguration: %s", msg)
        raise SystemExit(
            "Startup aborted: insecure ADMIN_PASSWORD. Set FLASK_ENV=development to bypass (dev only)."
        )


class Config:
    SECRET_KEY = SECRET_KEY
    SQLALCHEMY_DATABASE_URI = _database_url
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_SAMESITE = "Lax"
    DEFAULT_LANG = os.getenv("DEFAULT_LANG", "es")
    ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
    ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
    DOMINUS_DIR = Path(os.getenv("DOMINUS_DIR", str(Path.home() / "dominus")))
    SENTINEL_DIR = Path(os.getenv("SENTINEL_DIR", str(Path.home() / "sentinel")))
    DOMINUS_PYTHON = os.getenv("DOMINUS_PYTHON", str(DOMINUS_DIR / ".venv" / "bin" / "python"))
    SENTINEL_PYTHON = os.getenv("SENTINEL_PYTHON", str(SENTINEL_DIR / ".venv" / "bin" / "python"))
    SCAN_OUTPUT_DIR = Path(os.getenv("SCAN_OUTPUT_DIR", str(BASE_DIR / "instance" / "scan_reports")))
    SESSION_PERMANENT = True
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)
    APP_BASE_URL = os.getenv("APP_BASE_URL", "")
    INVITE_CODE = os.getenv("INVITE_CODE", "")
    LOGIN_RATE_LIMIT_ATTEMPTS = 10
    LOGIN_RATE_LIMIT_WINDOW_SECONDS = 300
