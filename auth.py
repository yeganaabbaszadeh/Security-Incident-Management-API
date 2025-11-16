import uuid
from datetime import datetime, timedelta, timezone

from flask import request, current_app
from flask_restful import abort

from models import db, User, AuthToken


def generate_token(user: User) -> str:
    """
    Create a new bearer token for the given user and store it in the DB.
    """
    hours = current_app.config.get("TOKEN_EXPIRES_HOURS", 8)
    token_value = uuid.uuid4().hex  # 32-char hex string

    token = AuthToken(
        token=token_value,
        user_id=user.id,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=hours),
    )
    db.session.add(token)
    db.session.commit()
    return token_value


def get_authorization_header() -> str:
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        abort(401, message="Missing or invalid Authorization header.")
    return auth_header.split(" ", 1)[1].strip()


def require_auth() -> User:
    """
    Validate the Authorization header and return the authenticated User.
    Used by protected endpoints.
    """
    token_value = get_authorization_header()

    token_obj = AuthToken.query.filter_by(token=token_value).first()
    if not token_obj:
        abort(401, message="Invalid or expired token.")

    if token_obj.is_expired():
        db.session.delete(token_obj)
        db.session.commit()
        abort(401, message="Token expired.")

    return token_obj.user
