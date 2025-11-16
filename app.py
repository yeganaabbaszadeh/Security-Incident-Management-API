import os

from dotenv import load_dotenv  # Load .env before anything else
load_dotenv(override=True)

from flask import Flask
from flask_restful import Api

from config import Config
from models import db, User
from resources import (
    AuthLogin,
    AuthRegister,
    IncidentList,
    IncidentDetail,
    IncidentStatus,
)


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialize extensions
    db.init_app(app)
    api = Api(app)

    # Register resources / endpoints
    api.add_resource(AuthLogin, "/auth/login")
    api.add_resource(AuthRegister, "/auth/register")
    api.add_resource(IncidentList, "/incidents")
    api.add_resource(IncidentDetail, "/incidents/<string:incident_id>")
    api.add_resource(IncidentStatus, "/incidents/<string:incident_id>/status")

    # Request hardening: limit request size
    @app.before_request
    def limit_content_length():
        from flask import request
        from flask_restful import abort

        max_bytes = app.config.get("MAX_CONTENT_LENGTH_BYTES", 1 * 1024 * 1024)
        if request.content_length is not None and request.content_length > max_bytes:
            abort(413, message="Request body too large.")

    # CLI command to init DB and create an initial user
    @app.cli.command("init-db")
    def init_db_command():
        """
        Initialize tables in the existing database and create an initial user
        based on environment variables.

        Usage:
            flask --app app.py init-db

        Required env vars for initial user:
            INITIAL_ADMIN_USERNAME
            INITIAL_ADMIN_PASSWORD
        """
        with app.app_context():
            # 1) Create tables inside the existing database
            db.create_all()

            # 2) Bootstrap initial user from environment
            initial_username = os.getenv("INITIAL_ADMIN_USERNAME")
            initial_password = os.getenv("INITIAL_ADMIN_PASSWORD")

            if not initial_username or not initial_password:
                print(
                    "INITIAL_ADMIN_USERNAME or INITIAL_ADMIN_PASSWORD not set. "
                    "Skipping initial user creation."
                )
            else:
                existing = User.query.filter_by(username=initial_username).first()
                if existing:
                    print(f"User '{initial_username}' already exists.")
                else:
                    user = User(username=initial_username)
                    user.set_password(initial_password)
                    db.session.add(user)
                    db.session.commit()
                    print(f"Created initial user: {initial_username}")

            print("Tables initialized.")

    return app


app = create_app()

if __name__ == "__main__":
    # For dev purposes only – in real deployments:
    # - serve via gunicorn/uwsgi
    # - put Nginx/other reverse proxy with HTTPS in front
    app.run(host="0.0.0.0", port=5000, debug=app.config.get("DEBUG", False))
