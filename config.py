import os


class Config:
    """
    Central configuration object.

    In production:
      - All sensitive values (SECRET_KEY, DATABASE_URL) MUST come from environment
        variables or a secret manager.
      - This file only defines how they are read, not the values themselves.
    """

    # Flask secret key (used for signing session cookies, tokens, etc.)
    SECRET_KEY = os.getenv("SECRET_KEY")
    if not SECRET_KEY:
        raise RuntimeError(
            "SECRET_KEY environment variable is not set. "
            "Never hardcode it in code; set it in your environment or secret manager."
        )

    # PostgreSQL connection string, e.g.:
    # postgresql://user:password@host:5432/incidents_db
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL")
    if not SQLALCHEMY_DATABASE_URI:
        raise RuntimeError(
            "DATABASE_URL environment variable is not set. "
            "Example: postgresql://user:password@localhost:5432/incidents_db"
        )

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Token lifetime (hours) – safe to default, but can be overridden.
    TOKEN_EXPIRES_HOURS = int(os.getenv("TOKEN_EXPIRES_HOURS", "8"))

    # Simple max content length (1 MB by default)
    MAX_CONTENT_LENGTH_BYTES = int(
        os.getenv("MAX_CONTENT_LENGTH_BYTES", str(1 * 1024 * 1024))
    )

    # Flask debug flag – should be FALSE in production.
    DEBUG = os.getenv("FLASK_DEBUG", "0") == "1"
