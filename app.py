import logging
from logging.handlers import RotatingFileHandler
import os

from flask import Flask, render_template, redirect, url_for, session, g

from config import Config
from models import db
from models.user_model import User
from routes.auth_routes import auth_bp
from routes.admin_routes import admin_bp
from routes.resident_routes import resident_bp

import webbrowser
import threading

def create_app(config_class=Config) -> Flask:
    """Flask uygulamasını oluşturan factory fonksiyon."""
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(config_class)

    # instance/ klasörünün var olduğundan emin ol
    try:
        os.makedirs(app.instance_path, exist_ok=True)
    except OSError:
        pass

    # logs/ klasörünü oluştur
    try:
        os.makedirs(app.config["LOG_DIR"], exist_ok=True)
    except OSError:
        pass

    # Veritabanını başlat
    db.init_app(app)

    # Logging yapılandırması
    configure_logging(app)

    # Blueprint kayıtları
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(resident_bp)

    # Request öncesi current_user bilgisini ayarla
    @app.before_request
    def load_current_user():
        """Her request öncesi aktif kullanıcıyı global 'g' içine koyar."""
        user_id = session.get("user_id")
        if user_id is None:
            g.current_user = None
        else:
            # 🔄 SQLAlchemy 2.0 uyumlu yöntem
            g.current_user = db.session.get(User, user_id)

    # Basit ana sayfa: login durumuna göre yönlendirme / dashboard placeholder
    @app.route("/")
    def index():
        """
        Kök URL:
        - Giriş yoksa /login
        - Admin ise /admin/dashboard
        - Resident ise /resident/dashboard
        """
        if not session.get("user_id"):
            return redirect(url_for("auth.login"))

        role = session.get("user_role")
        if role == "admin":
            return redirect(url_for("admin.dashboard"))
        elif role == "resident":
            return redirect(url_for("resident.dashboard"))

        # Rol tanımsızsa (beklenmeyen durum) base layout aç
        return render_template("base.html")

    # Uygulama context'inde tabloları oluştur ve ilk admini hazırla
    with app.app_context():
        from sqlalchemy.exc import SQLAlchemyError

        db.create_all()

        # İlk çalıştırmada örnek admin kullanıcı oluştur (yoksa)
        try:
            existing_admin = User.query.filter_by(role="admin").first()
            if existing_admin is None:
                default_admin = User(
                    name="Sistem Yöneticisi",
                    email="admin@example.com",
                    phone="",
                    role="admin",
                    is_active=True,
                )
                default_admin.set_password("admin123")
                db.session.add(default_admin)
                db.session.commit()
                app.logger.info(
                    "İlk admin kullanıcısı oluşturuldu: admin@example.com / admin123"
                )
        except SQLAlchemyError as exc:
            db.session.rollback()
            app.logger.exception("İlk admin oluşturulurken hata: %s", exc)

    return app


def configure_logging(app: Flask) -> None:
    """Uygulama için dosya tabanlı logging kurar."""
    log_file = app.config["LOG_FILE"]

    handler = RotatingFileHandler(
        log_file, maxBytes=1_000_000, backupCount=5, encoding="utf-8"
    )
    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )
    handler.setFormatter(formatter)
    handler.setLevel(logging.INFO)

    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)

    # Werkzeug loglarını da aynı dosyaya al
    logging.getLogger("werkzeug").addHandler(handler)


# Flask CLI / flask run için
app = create_app()

# İstersen direkt `python app.py` ile de çalıştırabil diye:
if __name__ == "__main__":
    def open_browser():
        webbrowser.open("http://127.0.0.1:5000")

    try:
        # 🔴 Sadece reloader'ın "asıl" process'inde tarayıcı aç
        if os.environ.get("WERKZEUG_RUN_MAIN") == "true":
            threading.Timer(1, open_browser).start()

        app.run(debug=True)
    except Exception as e:
        app.logger.error("Uygulama başlatılırken hata oluştu: %s", e)

