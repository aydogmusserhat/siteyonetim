import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

class Config:
    """Uygulama genel ayarları."""

    # PROD için: mutlaka environment'tan gelsin
    # Development'ta kolaylık için yoksa random üretir (restart olunca değişir)
    SECRET_KEY = os.environ.get("Ser990701022") or secrets.token_hex(32)

    # SQLite veritabanı yolu
    DB_PATH = BASE_DIR / "instance" / "apartman.db"
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL") or f"sqlite:///{DB_PATH}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Debug modu: default kapalı (prod güvenliği)
    DEBUG = os.environ.get("FLASK_DEBUG", "0") == "1"

    # Session cookie güvenliği
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    # HTTPS kullanıyorsan True yap (Render / nginx / cloudflare genelde HTTPS)
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "1") == "1"

    # Log dosyası
    LOG_DIR = BASE_DIR / "logs"
    LOG_FILE = LOG_DIR / "app.log"
