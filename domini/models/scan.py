from datetime import datetime, timezone

from domini.extensions import db


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Target(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False, index=True)
    type = db.Column(db.String(16), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)

    user = db.relationship("User", backref=db.backref("targets", lazy=True))
    scans = db.relationship("Scan", back_populates="target", cascade="all, delete-orphan")
    alerts = db.relationship("Alert", back_populates="target", cascade="all, delete-orphan")


class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target_id = db.Column(db.Integer, db.ForeignKey("target.id"), nullable=False, index=True)
    started_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    finished_at = db.Column(db.DateTime(timezone=True))
    status = db.Column(db.String(32), default="queued", nullable=False, index=True)
    risk_score = db.Column(db.Integer)
    raw_json = db.Column(db.Text)

    target = db.relationship("Target", back_populates="scans")
    alerts = db.relationship("Alert", back_populates="scan", cascade="all, delete-orphan")


class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target_id = db.Column(db.Integer, db.ForeignKey("target.id"), nullable=False, index=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scan.id"), nullable=False, index=True)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    severity = db.Column(db.String(24), nullable=False)
    message = db.Column(db.String(500), nullable=False)
    read = db.Column(db.Boolean, default=False, nullable=False)

    target = db.relationship("Target", back_populates="alerts")
    scan = db.relationship("Scan", back_populates="alerts")
