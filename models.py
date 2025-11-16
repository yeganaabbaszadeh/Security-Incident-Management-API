import uuid
from datetime import datetime

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())

    def set_password(self, password: str) -> None:
        """
        Store a salted hash instead of the raw password.
        """
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        """
        Verify that the provided password matches the stored hash.
        """
        return check_password_hash(self.password_hash, password)


class AuthToken(db.Model):
    """
    DB-backed bearer token.

    In production you might prefer stateless JWT tokens instead,
    but this is convenient for controlled lab testing and revocation.
    """
    __tablename__ = "auth_tokens"

    token = db.Column(db.String(64), primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)

    user = db.relationship("User", backref="tokens")

    def is_expired(self) -> bool:
        """
        Compare expires_at (timezone-aware) with current UTC time (also aware).
        """
        if self.expires_at is None:
            return True
        return self.expires_at < datetime.now(timezone.utc)


class Incident(db.Model):
    """
    Security incident record.

    In a real system, some fields (like description / source_ip) might be
    encrypted at rest using DB features (pgcrypto) or application-level crypto.
    """
    __tablename__ = "incidents"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=True)

    severity = db.Column(db.String(10), nullable=False)  # low/medium/high/critical
    status = db.Column(db.String(20), nullable=False, default="open")

    source_ip = db.Column(db.String(45), nullable=True)  # IPv4/IPv6 as string

    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())
    updated_at = db.Column(
        db.DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now()
    )
