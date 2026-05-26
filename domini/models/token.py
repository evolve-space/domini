from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from secrets import token_urlsafe

from domini.extensions import db


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class PasswordResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    token_hash = db.Column(db.String(128), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)
    used = db.Column(db.Boolean, default=False, nullable=False)

    user = db.relationship("User", backref="reset_tokens")

    @staticmethod
    def create_for_user(user_id: int) -> tuple["PasswordResetToken", str]:
        """Create a secure password reset token and return it with its raw value."""
        raw = token_urlsafe(32)
        hashed = hashlib.sha256(raw.encode()).hexdigest()
        token = PasswordResetToken(
            user_id=user_id,
            token_hash=hashed,
            expires_at=utcnow() + timedelta(hours=1),
        )
        return token, raw

    def is_valid(self) -> bool:
        expires_at = self.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        return not self.used and expires_at > utcnow()
