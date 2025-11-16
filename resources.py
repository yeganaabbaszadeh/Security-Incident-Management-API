import re
from flask import jsonify, request
from flask_restful import Resource, abort

from models import db, User, Incident
from auth import generate_token, require_auth


# ----------------- Helpers ----------------- #

def require_json():
    if not request.is_json:
        abort(400, message="Content-Type must be application/json.")
    try:
        data = request.get_json()
    except Exception:
        abort(400, message="Invalid JSON.")
    if data is None:
        abort(400, message="JSON body is required.")
    return data


def validate_password_strength(password: str):
    """
    Enforce a basic strong password policy:
    - At least 12 characters
    - At least one lowercase letter
    - At least one uppercase letter
    - At least one digit
    - At least one special character
    """
    if not isinstance(password, str):
        abort(400, message="'password' must be a string.")

    if len(password) < 12:
        abort(400, message="Password must be at least 12 characters long.")

    if not re.search(r"[a-z]", password):
        abort(400, message="Password must include at least one lowercase letter.")

    if not re.search(r"[A-Z]", password):
        abort(400, message="Password must include at least one uppercase letter.")

    if not re.search(r"[0-9]", password):
        abort(400, message="Password must include at least one digit.")

    if not re.search(r"[^A-Za-z0-9]", password):
        abort(400, message="Password must include at least one special character.")


def validate_incident_payload(data):
    """
    Validate incident creation/update payload.
    """
    if not isinstance(data, dict):
        abort(400, message="Invalid JSON structure.")

    title = data.get("title")
    description = data.get("description", "")
    severity = data.get("severity")
    source_ip = data.get("source_ip")

    if not title or not isinstance(title, str):
        abort(400, message="'title' is required and must be a string.")
    if len(title) > 150:
        abort(400, message="'title' is too long (max 150 chars).")

    if not isinstance(description, str):
        abort(400, message="'description' must be a string.")

    if severity not in ("low", "medium", "high", "critical"):
        abort(400, message="'severity' must be one of: low, medium, high, critical.")

    if source_ip and not isinstance(source_ip, str):
        abort(400, message="'source_ip' must be a string if provided.")

    return {
        "title": title,
        "description": description,
        "severity": severity,
        "source_ip": source_ip,
    }


def validate_status_payload(data):
    new_status = data.get("status")
    allowed_statuses = ("open", "in_progress", "contained", "resolved", "false_positive")
    if new_status not in allowed_statuses:
        abort(400, message=f"'status' must be one of: {', '.join(allowed_statuses)}.")
    return new_status


def incident_to_dict(incident: Incident):
    return {
        "id": incident.id,
        "title": incident.title,
        "description": incident.description,
        "severity": incident.severity,
        "status": incident.status,
        "source_ip": incident.source_ip,
        "created_at": incident.created_at.isoformat() if incident.created_at else None,
        "updated_at": incident.updated_at.isoformat() if incident.updated_at else None,
    }


# ----------------- Resources ----------------- #

class AuthRegister(Resource):
    """
    POST /auth/register

    Public endpoint to create a new user account.

    Body:
        {
          "username": "newuser",
          "password": "VeryStrong!Pass123",
          "password_confirm": "VeryStrong!Pass123"
        }
    """

    def post(self):
        data = require_json()

        username = data.get("username")
        password = data.get("password")
        password_confirm = data.get("password_confirm")

        # Basic presence checks
        if not username or not isinstance(username, str):
            abort(400, message="'username' is required and must be a string.")
        if not password or not isinstance(password, str):
            abort(400, message="'password' is required and must be a string.")
        if password_confirm is None:
            abort(400, message="'password_confirm' is required.")

        # Username policy: 3–50 chars, letters/digits/underscore only
        if not re.fullmatch(r"[A-Za-z0-9_]{3,50}", username):
            abort(
                400,
                message=(
                    "Username must be 3–50 characters long and contain only "
                    "letters, digits, or underscore."
                ),
            )

        # Prevent duplicate usernames
        if User.query.filter_by(username=username).first():
            abort(409, message="Username is already taken.")

        # Password strength checks
        validate_password_strength(password)

        # Password confirmation
        if password != password_confirm:
            abort(400, message="'password' and 'password_confirm' do not match.")

        # Create and store the user
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        # Optionally auto-login them
        token_value = generate_token(user)

        return {
            "message": "User registered successfully.",
            "access_token": token_value,
            "token_type": "Bearer",
        }, 201


class AuthLogin(Resource):
    """
    POST /auth/login
    Input:
        { "username": "secadmin", "password": "S0C*M4n4g3r" }

    Returns:
        { "access_token": "...", "token_type": "Bearer" }
    """

    def post(self):
        data = require_json()

        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            # Prevent username enumeration
            abort(401, message="Invalid credentials.")

        user = User.query.filter_by(username=username).first()
        if not user or not user.check_password(password):
            abort(401, message="Invalid credentials.")

        token_value = generate_token(user)
        return {"access_token": token_value, "token_type": "Bearer"}, 200


class IncidentList(Resource):
    """
    GET /incidents
    POST /incidents
    """

    def get(self):
        user = require_auth()  # noqa: F841 (not used further, but enforces auth)

        status_filter = request.args.get("status")
        severity_filter = request.args.get("severity")

        query = Incident.query

        if status_filter:
            query = query.filter(Incident.status == status_filter)
        if severity_filter:
            query = query.filter(Incident.severity == severity_filter)

        incidents = query.order_by(Incident.created_at.desc()).all()
        return jsonify({"incidents": [incident_to_dict(i) for i in incidents]})

    def post(self):
        user = require_auth()  # noqa: F841
        payload = require_json()
        data = validate_incident_payload(payload)

        incident = Incident(
            title=data["title"],
            description=data["description"],
            severity=data["severity"],
            source_ip=data["source_ip"],
            status="open",
        )
        db.session.add(incident)
        db.session.commit()

        return incident_to_dict(incident), 201


class IncidentDetail(Resource):
    """
    GET /incidents/<incident_id>
    """

    def get(self, incident_id):
        user = require_auth()  # noqa: F841
        incident = Incident.query.filter_by(id=incident_id).first()
        if not incident:
            abort(404, message="Incident not found.")
        return incident_to_dict(incident), 200


class IncidentStatus(Resource):
    """
    PATCH /incidents/<incident_id>/status
    """

    def patch(self, incident_id):
        user = require_auth()  # noqa: F841
        incident = Incident.query.filter_by(id=incident_id).first()
        if not incident:
            abort(404, message="Incident not found.")

        payload = require_json()
        new_status = validate_status_payload(payload)

        incident.status = new_status
        db.session.commit()

        return incident_to_dict(incident), 200
