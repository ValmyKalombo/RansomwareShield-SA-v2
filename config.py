import os
from datetime import timedelta
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
(BASE_DIR / "instance").mkdir(exist_ok=True)
load_dotenv(BASE_DIR / ".env")

_db = os.getenv("DATABASE_URL", f"sqlite:///{(BASE_DIR / 'instance' / 'ransomwareshield.db').as_posix()}")
if _db.startswith("postgres://"):
    _db = "postgresql+psycopg://" + _db[len("postgres://"):]
elif _db.startswith("postgresql://"):
    _db = "postgresql+psycopg://" + _db[len("postgresql://"):]

PRODUCTION = os.getenv("FLASK_ENV") == "production"


class Config:
    APP_VERSION = "3.3.0"
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-key-change-me")
    SQLALCHEMY_DATABASE_URI = _db
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True, "pool_recycle": 280}
    WTF_CSRF_TIME_LIMIT = 3600
    SESSION_COOKIE_NAME = "rs_session"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = PRODUCTION
    REMEMBER_COOKIE_NAME = "rs_remember"
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = "Lax"
    REMEMBER_COOKIE_SECURE = PRODUCTION
    REMEMBER_COOKIE_DURATION = timedelta(hours=12)
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=int(os.getenv("SESSION_MINUTES", "30")))
    MAX_CONTENT_LENGTH = 1024 * 1024
    PRODUCTION = PRODUCTION

    SUPERADMIN_EMAIL = os.getenv("SUPERADMIN_EMAIL", "").strip().lower()
    PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "http://127.0.0.1:5000").rstrip("/")

    # Microsoft Graph (optional) - invitation and reset-code emails
    GRAPH_TENANT_ID = os.getenv("GRAPH_TENANT_ID", "")
    GRAPH_CLIENT_ID = os.getenv("GRAPH_CLIENT_ID", "")
    GRAPH_CLIENT_SECRET = os.getenv("GRAPH_CLIENT_SECRET", "")
    GRAPH_SENDER = os.getenv("GRAPH_SENDER", "")

    # Threat intelligence (optional)
    HIBP_API_KEY = os.getenv("HIBP_API_KEY", "")
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

    # ShieldAI generative model (optional). Either Azure OpenAI or any OpenAI-compatible API.
    AZURE_OPENAI_ENDPOINT = os.getenv("AZURE_OPENAI_ENDPOINT", "")
    AZURE_OPENAI_KEY = os.getenv("AZURE_OPENAI_KEY", "")
    AZURE_OPENAI_DEPLOYMENT = os.getenv("AZURE_OPENAI_DEPLOYMENT", "")
    AI_API_BASE = os.getenv("AI_API_BASE", "")
    AI_API_KEY = os.getenv("AI_API_KEY", "")
    AI_MODEL = os.getenv("AI_MODEL", "")
