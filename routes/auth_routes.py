from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    current_app,
)
from sqlalchemy.exc import SQLAlchemyError

from models.user_model import User
from models import db

auth_bp = Blueprint("auth", __name__, url_prefix="")

# Basit login/logout akışı; ileride register vs. eklenebilir.


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """Kullanıcı giriş ekranı ve post işlemi."""
    if request.method == "GET":
        # Eğer zaten giriş yapmışsa, rolüne göre paneline yönlendir
        if session.get("user_id"):
            role = session.get("user_role")
            if role == "admin":
                return redirect(url_for("admin.dashboard"))
            elif role == "resident":
                return redirect(url_for("resident.dashboard"))
            return redirect(url_for("index"))
        return render_template("login.html")

    # POST
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    if not email or not password:
        flash("E-posta ve şifre boş bırakılamaz.", "error")
        return render_template("login.html", email=email)

    try:
        user = User.query.filter_by(email=email).first()
    except SQLAlchemyError as exc:
        current_app.logger.exception("Login sırasında veritabanı hatası: %s", exc)
        flash("Beklenmeyen bir hata oluştu. Lütfen tekrar deneyin.", "error")
        return render_template("login.html", email=email)

    if not user or not user.check_password(password):
        flash("E-posta veya şifre hatalı.", "error")
        return render_template("login.html", email=email)

    if not user.is_active:
        flash("Hesabınız pasif durumda. Yönetici ile iletişime geçin.", "error")
        return render_template("login.html", email=email)

    # Başarılı login -> session'a yaz
    session["user_id"] = user.id
    session["user_name"] = user.name
    session["user_role"] = user.role

    flash("Başarıyla giriş yaptınız.", "success")

    # Rol bazlı yönlendirme
    if user.is_admin:
        return redirect(url_for("admin.dashboard"))
    elif user.is_resident:
        return redirect(url_for("resident.dashboard"))

    # Her ihtimale karşı
    return redirect(url_for("index"))


@auth_bp.route("/logout")
def logout():
    """Kullanıcı çıkışı."""
    session.clear()
    flash("Oturumunuz sonlandırıldı.", "info")
    return redirect(url_for("auth.login"))
