import logging
from logging.handlers import RotatingFileHandler
import os

from flask import Flask, redirect, url_for, session, g, request
from waitress import serve

from config import Config
from models import db
from models.user_model import User


# ============================
#  BLUEPRINT IMPORT (fallback)
# ============================
# Sunucudaki yapına göre blueprints bazen routes/ içinde, bazen kökte olabiliyor.
# Bu fallback sistemi "ModuleNotFoundError" riskini sıfırlar.

try:
    from routes.auth_routes import auth_bp  # type: ignore
except Exception:
   pass

try:
    from routes.admin_routes import admin_bp  # type: ignore
except Exception:
    pass

try:
    from routes.resident_routes import resident_bp  # type: ignore
except Exception:
    pass


# ==========================================
#  SQLITE MINI MIGRATION + SUPERADMIN SEED
# ==========================================
def _ensure_sqlite_columns(app: Flask) -> None:
    """
    SQLite mini-migration:
      - users.is_deleted
      - payments.description
    """
    try:
        conn = db.engine.raw_connection()
        cur = conn.cursor()

        # users.is_deleted
        try:
            cur.execute("PRAGMA table_info(users)")
            cols = [r[1] for r in cur.fetchall()]
            if "is_deleted" not in cols:
                cur.execute("ALTER TABLE users ADD COLUMN is_deleted BOOLEAN NOT NULL DEFAULT 0")
                conn.commit()
                app.logger.info("users.is_deleted kolonu eklendi.")
        except Exception as e:
            app.logger.exception("users.is_deleted migration hatası: %s", e)
            try:
                conn.rollback()
            except Exception:
                pass

        # payments.description
        try:
            cur.execute("PRAGMA table_info(payments)")
            cols = [r[1] for r in cur.fetchall()]
            if "description" not in cols:
                cur.execute("ALTER TABLE payments ADD COLUMN description VARCHAR(255)")
                conn.commit()
                app.logger.info("payments.description kolonu eklendi.")
        except Exception as e:
            app.logger.exception("payments.description migration hatası: %s", e)
            try:
                conn.rollback()
            except Exception:
                pass

    except Exception as e:
        app.logger.exception("SQLite migration genel hata: %s", e)
    finally:
        try:
            cur.close()
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass


def _seed_superadmin(app: Flask) -> None:
    """
    Super admin yoksa oluşturur.
    Prod için environment ile yönet:
      SUPERADMIN_EMAIL
      SUPERADMIN_PASSWORD
      DISABLE_AUTO_SUPERADMIN=1  -> tamamen kapatmak için
    """
    if str(os.getenv("DISABLE_AUTO_SUPERADMIN") or "0").lower() in ("1", "true", "yes"):
        app.logger.info("AUTO superadmin seed devre dışı (DISABLE_AUTO_SUPERADMIN=1).")
        return

    email = (os.getenv("SUPERADMIN_EMAIL") or "superadmin@example.com").strip().lower()
    password = os.getenv("SUPERADMIN_PASSWORD") or "superadmin123"

    try:
        existing_super = User.query.filter_by(role="super_admin").first()
        if existing_super:
            return

        u = User(
            name="Sistem Süper Yöneticisi",
            email=email,
            phone="",
            role="super_admin",
            is_active=True,
        )
        u.set_password(password)
        db.session.add(u)
        db.session.commit()

        if password == "superadmin123":
            app.logger.warning(
                "Superadmin oluşturuldu ama DEFAULT şifre kullanıldı! "
                "Prod'da SUPERADMIN_PASSWORD set et."
            )

        app.logger.info("İlk super_admin oluşturuldu: %s", email)

    except Exception as e:
        db.session.rollback()
        app.logger.exception("Super admin seed hatası: %s", e)


# ============================
#  APP FACTORY
# ============================
def create_app(config_class=Config) -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(config_class)

    # instance/ klasörü
    try:
        os.makedirs(app.instance_path, exist_ok=True)
    except OSError:
        pass

    # logs/ klasörü
    try:
        os.makedirs(app.config.get("LOG_DIR", "logs"), exist_ok=True)
    except OSError:
        pass

    # DB init
    db.init_app(app)

    # Logging
    configure_logging(app)

    # Blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(resident_bp)

    # ✅ DB init + migration + seed (DOĞRU YER)
    with app.app_context():
        db.create_all()
        _ensure_sqlite_columns(app)
        _seed_superadmin(app)

    # current_user
    @app.before_request
    def load_current_user():
        user_id = session.get("user_id")
        if user_id is None:
            g.current_user = None
        else:
            try:
                g.current_user = db.session.get(User, int(user_id))
            except Exception:
                g.current_user = None

    # root redirect
    @app.route("/")
    def index():
        if not session.get("user_id"):
            return redirect(url_for("auth.login"))

        role = session.get("user_role")

        if role == "super_admin":
            return redirect(url_for("admin.manage_sites"))
        if role == "admin":
            return redirect(url_for("admin.dashboard"))
        if role == "resident":
            return redirect(url_for("resident.dashboard"))

        # beklenmeyen role -> güvenli fallback
        return redirect(url_for("auth.login"))

    @app.get("/set-lang/<lang>")
    def set_lang(lang):
        if lang not in ("tr", "en", "me", "ru"):
            lang = "tr"
        session["lang"] = lang
        next_url = request.args.get("next")
        return redirect(next_url or url_for("index"))

    return app


def configure_logging(app: Flask) -> None:
    log_file = app.config.get("LOG_FILE") or os.path.join(app.config.get("LOG_DIR", "logs"), "app.log")
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    handler = RotatingFileHandler(log_file, maxBytes=1_000_000, backupCount=5, encoding="utf-8")
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    handler.setFormatter(formatter)
    handler.setLevel(logging.INFO)

    # handler tekrar eklenmesin
    if not any(isinstance(h, RotatingFileHandler) for h in app.logger.handlers):
        app.logger.addHandler(handler)

    app.logger.setLevel(logging.INFO)
    logging.getLogger("werkzeug").addHandler(handler)


# WSGI entry
app = create_app()

if __name__ == "__main__":
    serve(app, host="0.0.0.0", port=5000)
