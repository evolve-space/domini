from __future__ import annotations

import hashlib
import re
import secrets
from datetime import datetime, timedelta, timezone

from flask import Blueprint, abort, flash, g, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user

from config import Config
from domini.extensions import bcrypt, db
from domini.models.attempt import LoginAttempt
from domini.models.token import PasswordResetToken
from domini.models.user import User
from domini.utils.mailer import send_reset_email

auth_bp = Blueprint("auth", __name__)
USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,30}$")
_DUMMY_HASH: str = ""


def _get_dummy_hash() -> str:
    global _DUMMY_HASH
    if not _DUMMY_HASH:
        _DUMMY_HASH = bcrypt.generate_password_hash("x" * 32).decode()
    return _DUMMY_HASH
EMAIL_RE = re.compile(r"^[^@]+@[^@]+\.[^@]+$")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def get_csrf_token() -> str:
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def require_csrf() -> None:
    # Known limitation: rotating the token on each request invalidates tokens held by
    # other tabs opened concurrently. A parallel POST from a second tab will receive 403.
    expected = session.get("csrf_token")
    submitted = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    if not expected or not submitted or not secrets.compare_digest(submitted, expected):
        abort(403)
    new_token = secrets.token_hex(32)
    session["csrf_token"] = new_token
    g.new_csrf_token = new_token


def valid_password(password: str) -> bool:
    return (
        len(password) >= 12
        and any(c.isalpha() for c in password)
        and any(c.isdigit() for c in password)
        and any(not c.isalnum() for c in password)
    )


def remote_ip() -> str:
    return request.remote_addr or "unknown"


def _ip_hash() -> str:
    return hashlib.sha256(remote_ip().encode()).hexdigest()


def current_ip_attempts() -> int:
    ip_hash = _ip_hash()
    cutoff = utcnow() - timedelta(seconds=Config.LOGIN_RATE_LIMIT_WINDOW_SECONDS)
    LoginAttempt.query.filter(
        LoginAttempt.ip_hash == ip_hash,
        LoginAttempt.attempted_at <= cutoff,
    ).delete()
    db.session.commit()
    return LoginAttempt.query.filter_by(ip_hash=ip_hash).count()


def locked_minutes(user: User) -> int:
    locked_until = user.locked_until
    if locked_until is None:
        return 0
    if locked_until.tzinfo is None:
        locked_until = locked_until.replace(tzinfo=timezone.utc)
    seconds = max(0, int((locked_until - utcnow()).total_seconds()))
    return max(1, (seconds + 59) // 60)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        require_csrf()
        if current_ip_attempts() >= Config.LOGIN_RATE_LIMIT_ATTEMPTS:
            flash(g.t["account_locked"].format(minutes=5), "error")
            return render_template("login.html", register_enabled=bool(Config.INVITE_CODE))

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()
        if not user:
            bcrypt.check_password_hash(_get_dummy_hash(), password)
        if user and not user.is_locked() and user.check_password(password):
            user.reset_failed_attempts()
            LoginAttempt.query.filter_by(ip_hash=_ip_hash()).delete()
            db.session.commit()
            login_user(user, remember=False)
            session.permanent = True
            session["_login_at"] = utcnow().isoformat()
            session["_session_version"] = user.session_version
            return redirect(url_for("dashboard.index"))
        if user:
            user.register_failed_attempt()
        db.session.add(LoginAttempt(ip_hash=_ip_hash(), attempted_at=utcnow()))
        db.session.commit()
        flash("invalid_credentials", "error")

    return render_template("login.html", register_enabled=bool(Config.INVITE_CODE))


@auth_bp.route("/logout", methods=["POST"])
@login_required
def logout():
    require_csrf()
    session.clear()
    logout_user()
    return redirect(url_for("auth.login"))


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    invite_code_required = Config.INVITE_CODE
    if not invite_code_required:
        abort(404)

    if request.method == "POST":
        require_csrf()
        if current_ip_attempts() >= Config.LOGIN_RATE_LIMIT_ATTEMPTS:
            flash(g.t["account_locked"].format(minutes=5), "error")
            return render_template("login.html", register_mode=True)
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirmation = request.form.get("password_confirm", "")
        invite_code = request.form.get("invite_code", "").strip()
        if not secrets.compare_digest(invite_code, invite_code_required):
            flash("invalid_invite_code", "error")
        elif not USERNAME_RE.fullmatch(username):
            flash("invalid_username_format", "error")
        elif not EMAIL_RE.fullmatch(email):
            flash("invalid_email_format", "error")
        elif not valid_password(password):
            flash("weak_password", "error")
        elif password != confirmation:
            flash("passwords_dont_match", "error")
        elif User.query.filter_by(username=username).first():
            flash("username_taken", "error")
        elif User.query.filter_by(email=email).first():
            flash("email_taken", "error")
        else:
            user = User(username=username, email=email)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            login_user(user, remember=False)
            session.permanent = True
            session["_login_at"] = utcnow().isoformat()
            session["_session_version"] = user.session_version
            return redirect(url_for("dashboard.index"))

    return render_template("login.html", register_mode=True)


@auth_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        require_csrf()
        if current_ip_attempts() >= Config.LOGIN_RATE_LIMIT_ATTEMPTS:
            flash(g.t["account_locked"].format(minutes=5), "error")
            return render_template("forgot_password.html")
        email = request.form.get("email", "").strip().lower()
        user = User.query.filter_by(email=email).first()
        if user:
            PasswordResetToken.query.filter_by(user_id=user.id, used=False).update({"used": True})
            token, raw_token = PasswordResetToken.create_for_user(user.id)
            db.session.add(token)
        db.session.add(LoginAttempt(ip_hash=_ip_hash(), attempted_at=utcnow()))
        db.session.commit()
        if user:
            send_reset_email(user.email, raw_token)
        flash("reset_email_sent", "success")
    return render_template("forgot_password.html")


@auth_bp.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token: str):
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    reset_token = PasswordResetToken.query.filter_by(token_hash=token_hash).first()
    if not reset_token or not reset_token.is_valid():
        flash("reset_token_invalid", "error")
        return redirect(url_for("auth.forgot_password"))

    if request.method == "POST":
        require_csrf()
        password = request.form.get("password", "")
        confirmation = request.form.get("password_confirm", "")
        if not valid_password(password):
            flash("weak_password", "error")
        elif password != confirmation:
            flash("passwords_dont_match", "error")
        else:
            reset_token.user.set_password(password)
            reset_token.user.reset_failed_attempts()
            reset_token.user.session_version = (reset_token.user.session_version or 0) + 1
            reset_token.used = True
            db.session.commit()
            flash("password_reset_success", "success")
            return redirect(url_for("auth.login"))
    return render_template("reset_password.html", token=token)
