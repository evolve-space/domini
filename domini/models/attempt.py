from __future__ import annotations

from datetime import datetime

from domini.extensions import db


class LoginAttempt(db.Model):
    __tablename__ = "login_attempt"
    id = db.Column(db.Integer, primary_key=True)
    ip_hash = db.Column(db.String(64), nullable=False, index=True)
    attempted_at = db.Column(db.DateTime(timezone=True), nullable=False)
