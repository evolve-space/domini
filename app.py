import os
from datetime import datetime, timezone, timedelta
from pathlib import Path
from secrets import randbits

from OpenSSL import crypto
from flask import Flask, g, jsonify, redirect, request, session, url_for

from config import Config, TRANSLATIONS
from domini.extensions import bcrypt, db, login_manager
from domini.extensions import migrate_sqlite_user_columns
from translations import LANGUAGES


def create_self_signed_cert(cert_dir: Path) -> tuple[str, str]:
    cert_dir.mkdir(parents=True, exist_ok=True)
    cert_file = cert_dir / "domini.crt"
    key_file = cert_dir / "domini.key"

    if cert_file.exists() and key_file.exists() and certificate_is_valid(cert_file):
        return str(cert_file), str(key_file)

    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    cert = crypto.X509()
    subject = cert.get_subject()
    subject.C = "ES"
    subject.ST = "Madrid"
    subject.L = "Madrid"
    subject.O = "DOMINI"
    subject.OU = "OSINT"
    subject.CN = "localhost"
    cert.set_serial_number(randbits(128))
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(825 * 24 * 60 * 60)
    cert.set_issuer(subject)
    cert.set_pubkey(key)
    cert.add_extensions(
        [
            crypto.X509Extension(b"subjectAltName", False, b"DNS:localhost,IP:127.0.0.1"),
            crypto.X509Extension(b"basicConstraints", True, b"CA:FALSE"),
            crypto.X509Extension(b"keyUsage", True, b"digitalSignature,keyEncipherment"),
            crypto.X509Extension(b"extendedKeyUsage", False, b"serverAuth"),
        ]
    )
    cert.sign(key, "sha256")

    cert_file.write_bytes(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    key_file.write_bytes(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
    return str(cert_file), str(key_file)


def certificate_is_valid(cert_file: Path) -> bool:
    try:
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_file.read_bytes())
    except crypto.Error:
        return False

    subject = cert.get_subject()
    if subject.CN != "localhost":
        return False
    if cert.get_pubkey().bits() != 2048:
        return False

    san_values = set()
    for index in range(cert.get_extension_count()):
        extension = cert.get_extension(index)
        if extension.get_short_name() == b"subjectAltName":
            san_values.update(part.strip() for part in str(extension).split(","))
    return {"DNS:localhost", "IP Address:127.0.0.1"}.issubset(san_values)


def create_admin_user() -> None:
    from domini.models import Alert, PasswordResetToken, Scan, Target, User  # noqa: F401

    if not Config.ADMIN_USERNAME or not Config.ADMIN_PASSWORD:
        return

    admin = User.query.filter_by(username=Config.ADMIN_USERNAME).first()
    if admin:
        return

    admin = User(username=Config.ADMIN_USERNAME)
    admin.set_password(Config.ADMIN_PASSWORD)
    db.session.add(admin)
    db.session.commit()


def create_app() -> Flask:
    app = Flask(
        __name__,
        instance_relative_config=True,
        static_folder="domini/static",
        template_folder="domini/templates",
    )
    app.config.from_object(Config)

    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message = "login_required"

    from domini.auth.routes import auth_bp
    from domini.auth.routes import get_csrf_token
    from domini.dashboard.routes import dashboard_bp
    from domini.models.user import User

    @login_manager.user_loader
    def load_user(user_id: str) -> User | None:
        return db.session.get(User, int(user_id))

    _SESSION_MAX_AGE = timedelta(hours=8)

    @app.before_request
    def enforce_session_age() -> None:
        from flask_login import current_user, logout_user
        login_at_str = session.get("_login_at")
        if login_at_str and current_user.is_authenticated:
            try:
                login_at = datetime.fromisoformat(login_at_str)
                if datetime.now(timezone.utc) - login_at > _SESSION_MAX_AGE:
                    session.clear()
                    logout_user()
                    return redirect(url_for("auth.login"))
            except (ValueError, TypeError):
                session.clear()
                logout_user()
                return redirect(url_for("auth.login"))

    @app.before_request
    def set_locale() -> None:
        requested_lang = request.args.get("lang")
        if requested_lang in TRANSLATIONS:
            session["lang"] = requested_lang
        lang = session.get("lang") or Config.DEFAULT_LANG
        g.lang = lang if lang in TRANSLATIONS else Config.DEFAULT_LANG
        g.t = TRANSLATIONS[g.lang]

    @app.context_processor
    def inject_i18n() -> dict:
        return {
            "translations": TRANSLATIONS,
            "languages": LANGUAGES,
        }

    app.jinja_env.globals["csrf_token"] = get_csrf_token

    @app.after_request
    def add_security_headers(response):
        if "X-Frame-Options" not in response.headers:
            response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        if "Content-Security-Policy" not in response.headers:
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self' https://cdn.jsdelivr.net; "
                "style-src 'self' https://fonts.googleapis.com; "
                "font-src 'self' https://fonts.gstatic.com; "
                "connect-src 'self' https://cdn.jsdelivr.net; "
                "object-src 'none'; "
                "base-uri 'self'"
            )
        if not app.debug:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    @app.post("/i18n/<lang>")
    def set_language(lang: str):
        if lang not in TRANSLATIONS:
            return jsonify({"error": "unsupported_language"}), 400
        session["lang"] = lang
        return jsonify({"lang": lang, "translations": TRANSLATIONS[lang]})

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)

    with app.app_context():
        from domini.models import LoginAttempt, PasswordResetToken  # noqa: F401

        os.makedirs("/tmp/scan_reports", exist_ok=True)
        os.makedirs(str(Path(app.config.get("SCAN_OUTPUT_DIR", "/tmp/scan_reports"))), exist_ok=True)
        migrate_sqlite_user_columns(Path(__file__).resolve().parent / "instance" / "domini.db")
        db.create_all()
        create_admin_user()

    return app


app = create_app()


if __name__ == "__main__":
    cert_path, key_path = create_self_signed_cert(Path("certs"))
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8443)))
