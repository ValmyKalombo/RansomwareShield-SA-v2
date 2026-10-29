import os
from datetime import timedelta
from pathlib import Path

from dotenv import load_dotenv


# ---------------------------------------------------------
# PROJECT PATHS
# ---------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent

INSTANCE_DIR = BASE_DIR / "instance"

# Make sure the instance folder always exists
INSTANCE_DIR.mkdir(parents=True, exist_ok=True)

# Load local environment variables
load_dotenv(BASE_DIR / ".env")


# ---------------------------------------------------------
# DATABASE
# ---------------------------------------------------------

default_database = INSTANCE_DIR / "ransomwareshield.db"

database_url = os.getenv(
    "DATABASE_URL",
    f"sqlite:///{default_database.as_posix()}"
)

# Some hosted PostgreSQL providers may supply postgres://
# SQLAlchemy expects postgresql://
if database_url.startswith("postgres://"):
    database_url = (
        "postgresql://"
        + database_url[len("postgres://"):]
    )


# ---------------------------------------------------------
# APPLICATION CONFIGURATION
# ---------------------------------------------------------

class Config:

    # Application secret
    SECRET_KEY = os.getenv(
        "SECRET_KEY",
        "development-key-change-before-production"
    )

    # Database
    SQLALCHEMY_DATABASE_URI = database_url

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # CSRF
    WTF_CSRF_TIME_LIMIT = 3600

    # Session security
    SESSION_COOKIE_HTTPONLY = True

    SESSION_COOKIE_SAMESITE = "Lax"

    REMEMBER_COOKIE_HTTPONLY = True

    REMEMBER_COOKIE_SAMESITE = "Lax"

    # Secure cookies are enabled on the hosted HTTPS version
    SESSION_COOKIE_SECURE = (
        os.getenv("FLASK_ENV") == "production"
    )

    REMEMBER_COOKIE_SECURE = (
        os.getenv("FLASK_ENV") == "production"
    )

    # Session timeout
    PERMANENT_SESSION_LIFETIME = timedelta(
        minutes=int(
            os.getenv(
                "SESSION_MINUTES",
                "30"
            )
        )
    )

    # Limit request size
    MAX_CONTENT_LENGTH = 1024 * 1024