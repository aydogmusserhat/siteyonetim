import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

class Config:
    """Uygulama genel ayarları."""
    # Güvenlik anahtarı (.env içinden okunabilir)
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me")

    # SQLite veritabanı yolu
    DB_PATH = BASE_DIR / "instance" / "apartman.db"
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL") or f"sqlite:///{DB_PATH}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Debug modu (geliştirme için)
    DEBUG = os.environ.get("FLASK_DEBUG", "1") == "1"

    # Log dosyası
    LOG_DIR = BASE_DIR / "logs"
    LOG_FILE = LOG_DIR / "app.log"
