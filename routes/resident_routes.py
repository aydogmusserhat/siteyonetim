from functools import wraps
from datetime import datetime, date
from decimal import Decimal

from flask import (
    Blueprint,
    render_template,
    session,
    redirect,
    url_for,
    flash,
    current_app,
    request,
)
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import func

from models import db
from models.user_model import User
from models.apartment_model import Apartment
from models.bill_model import Bill
from models.payment_model import Payment
from models.announcement_model import Announcement
from models.ticket_model import Ticket


resident_bp = Blueprint("resident", __name__, url_prefix="/resident")


def resident_required(view_func):
    """
    Sadece 'resident' rolündeki kullanıcıların erişmesini sağlayan decorator.
    Giriş yoksa /login, rol yanlışsa index'e yönlendirir.
    """

    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        user_id = session.get("user_id")
        role = session.get("user_role")

        if not user_id:
            flash("Devam etmek için lütfen giriş yapın.", "info")
            return redirect(url_for("auth.login"))

        if role != "resident":
            flash("Bu alana sadece sakin kullanıcılar erişebilir.", "error")
            return redirect(url_for("index"))

        return view_func(*args, **kwargs)

    return wrapped_view


def _get_current_resident():
    """Session'daki sakin kullanıcının User ve Apartment bilgilerini döner."""
    user_id = session.get("user_id")
    if not user_id:
        return None, None

    try:
        user = User.query.get(user_id)
        if not user:
            return None, None
        apartment = None
        if user.apartment_id:
            apartment = Apartment.query.get(user.apartment_id)
        return user, apartment
    except SQLAlchemyError as exc:
        current_app.logger.exception("Sakin bilgisi alınamadı: %s", exc)
        return None, None


def _compute_debt_stats_for_apartment(apartment_id: int) -> dict:
    """
    Verilen daire için borç/ödeme özetini hesaplar.
    - total_bills          : faturaların adedi
    - open_bills / partial_bills / paid_bills : duruma göre adetler
    - total_bills_amount   : tüm faturaların toplam tutarı
    - total_paid_amount    : Payment tablosuna göre yapılan gerçek ödeme toplamı
    - total_open_amount    : net kalan borç (faturalar - ödemeler)
    """
    stats = {
        "total_bills": 0,
        "open_bills": 0,
        "partial_bills": 0,
        "paid_bills": 0,
        "total_bills_amount": Decimal("0.00"),
        "total_paid_amount": Decimal("0.00"),
        "total_open_amount": Decimal("0.00"),
    }

    # 1) Fatura adetleri (status bazında)
    try:
        status_counts = (
            db.session.query(Bill.status, func.count(Bill.id))
            .filter(Bill.apartment_id == apartment_id)
            .group_by(Bill.status)
            .all()
        )

        total_bills = 0
        for status, count in status_counts:
            total_bills += count or 0
            if status == "open":
                stats["open_bills"] = count
            elif status == "partial":
                stats["partial_bills"] = count
            elif status == "paid":
                stats["paid_bills"] = count

        stats["total_bills"] = total_bills

    except SQLAlchemyError as exc:
        current_app.logger.exception(
            "Sakin istatistikleri hesaplanırken (adet) hata: %s", exc
        )

    # 2) Tutarlar (toplam fatura ve toplam ödeme)
    try:
        # Tüm faturaların toplamı
        total_bills_amount = (
            db.session.query(func.coalesce(func.sum(Bill.amount), 0))
            .filter(Bill.apartment_id == apartment_id)
            .scalar()
        )

        # O daireye ait yapılan tüm ödemeler
        total_paid_amount = (
            db.session.query(func.coalesce(func.sum(Payment.amount), 0))
            .filter(Payment.apartment_id == apartment_id)
            .scalar()
        )

        # Decimal'e çevir
        if total_bills_amount is None:
            total_bills_amount = Decimal("0.00")
        else:
            total_bills_amount = Decimal(str(total_bills_amount))

        if total_paid_amount is None:
            total_paid_amount = Decimal("0.00")
        else:
            total_paid_amount = Decimal(str(total_paid_amount))

        stats["total_bills_amount"] = total_bills_amount
        stats["total_paid_amount"] = total_paid_amount

        # Net kalan borç (eksiye düşmesini engelle)
        remaining = total_bills_amount - total_paid_amount
        if remaining < Decimal("0.00"):
            remaining = Decimal("0.00")

        stats["total_open_amount"] = remaining

    except SQLAlchemyError as exc:
        current_app.logger.exception(
            "Sakin istatistikleri hesaplanırken (tutar) hata: %s", exc
        )

    return stats


# ======================
#  DASHBOARD
# ======================


@resident_bp.route("/dashboard")
@resident_required
def dashboard():
    """Sakinin kendi borç, ödeme, talep ve duyuru özetlerini gösterir."""
    user, apartment = _get_current_resident()
    if not user:
        flash("Kullanıcı bulunamadı. Lütfen tekrar giriş yapın.", "error")
        return redirect(url_for("auth.logout"))

    # Varsayılan boş istatistik
    stats = {
        "total_bills": 0,
        "open_bills": 0,
        "partial_bills": 0,
        "paid_bills": 0,
        "total_bills_amount": Decimal("0.00"),
        "total_open_amount": Decimal("0.00"),
        "total_paid_amount": Decimal("0.00"),
    }

    bills = []
    payments = []
    tickets = []
    announcements = []

    # Borç / aidat özeti
    if apartment:
        # İstatistikleri Payment tablosuna göre NET hesapla
        stats = _compute_debt_stats_for_apartment(apartment.id)

        # Fatura listesi
        try:
            bills = (
                Bill.query.filter(Bill.apartment_id == apartment.id)
                .order_by(Bill.due_date.desc().nullslast(), Bill.created_at.desc())
                .all()
            )
        except SQLAlchemyError as exc:
            current_app.logger.exception("Sakin borç bilgileri alınamadı: %s", exc)
            flash("Borç bilgileriniz alınırken bir hata oluştu.", "error")

        # Ödemeler
        try:
            payments = (
                Payment.query.filter(Payment.apartment_id == apartment.id)
                .order_by(Payment.payment_date.desc())
                .limit(5)
                .all()
            )
        except SQLAlchemyError as exc:
            current_app.logger.exception("Sakin ödeme listesi alınamadı: %s", exc)
            flash("Ödeme bilgileriniz alınırken bir hata oluştu.", "error")

    # Talepler
    try:
        tickets = (
            Ticket.query.filter(Ticket.user_id == user.id)
            .order_by(Ticket.created_at.desc())
            .limit(5)
            .all()
        )
    except SQLAlchemyError as exc:
        current_app.logger.exception("Sakin talep listesi alınamadı: %s", exc)
        flash("Talep listeniz alınırken bir hata oluştu.", "error")

    # Duyurular (tüm sakinlere açık olanlar)
    try:
        announcements = (
            Announcement.query.filter(
                Announcement.target.in_(["all", "residents"])
            )
            .order_by(Announcement.created_at.desc())
            .limit(5)
            .all()
        )
    except SQLAlchemyError as exc:
        current_app.logger.exception("Sakin duyuru listesi alınamadı: %s", exc)
        flash("Duyurular alınırken bir hata oluştu.", "error")

    today = date.today()  # 🔹 bugünün tarihi

    return render_template(
        "resident/dashboard.html",
        user=user,
        apartment=apartment,
        stats=stats,
        bills=bills,
        payments=payments,
        tickets=tickets,
        announcements=announcements,
        today=today,  # 🔹 template’e gönder
    )


# ======================
#  BORÇLARIM
# ======================


@resident_bp.route("/borclarim")
@resident_required
def borclarim():
    """Sakinin dairesine ait borç / aidat listesini gösterir."""
    user, apartment = _get_current_resident()
    if not user:
        flash("Kullanıcı bulunamadı. Lütfen tekrar giriş yapın.", "error")
        return redirect(url_for("auth.logout"))

    bills = []
    stats = {
        "total_bills": 0,
        "open_bills": 0,
        "partial_bills": 0,
        "paid_bills": 0,
        "total_bills_amount": Decimal("0.00"),
        "total_open_amount": Decimal("0.00"),
        "total_paid_amount": Decimal("0.00"),
    }

    if not apartment:
        flash(
            "Herhangi bir daire ile eşleştirilmemişsiniz. Lütfen yönetici ile iletişime geçin.",
            "info",
        )
        return render_template(
            "resident/borclarim.html",
            user=user,
            apartment=None,
            bills=bills,
            stats=stats,
        )

    try:
        bills = (
            Bill.query.filter(Bill.apartment_id == apartment.id)
            .order_by(Bill.due_date.asc().nullslast(), Bill.created_at.desc())
            .all()
        )
    except SQLAlchemyError as exc:
        current_app.logger.exception("Sakin borç listesi alınamadı: %s", exc)
        flash("Borçlarınız listelenirken bir hata oluştu.", "error")

    # Aynı helper ile NET istatistik
    stats = _compute_debt_stats_for_apartment(apartment.id)

    return render_template(
        "resident/borclarim.html",
        user=user,
        apartment=apartment,
        bills=bills,
        stats=stats,
    )


# ======================
#  ÖDEMELERİM
# ======================


@resident_bp.route("/odemelerim")
@resident_required
def odemelerim():
    """Sakinin kendi dairesi için yapılan ödemeleri gösterir."""
    user, apartment = _get_current_resident()
    if not user:
        flash("Kullanıcı bulunamadı. Lütfen tekrar giriş yapın.", "error")
        return redirect(url_for("auth.logout"))

    payments = []

    if not apartment:
        flash(
            "Herhangi bir daire ile eşleştirilmemişsiniz. Lütfen yönetici ile iletişime geçin.",
            "info",
        )
        return render_template("resident/odemelerim.html", user=user, payments=payments)

    try:
        payments = (
            db.session.query(Payment, Bill)
            .outerjoin(Bill, Payment.bill_id == Bill.id)
            .filter(Payment.apartment_id == apartment.id)
            .order_by(Payment.payment_date.desc())
            .all()
        )
    except SQLAlchemyError as exc:
        current_app.logger.exception("Sakin ödeme listesi alınamadı: %s", exc)
        flash("Ödemeleriniz listelenirken bir hata oluştu.", "error")

    return render_template(
        "resident/odemelerim.html",
        user=user,
        apartment=apartment,
        payments=payments,
    )


# ======================
#  TALEPLERİM
# ======================


@resident_bp.route("/taleplerim", methods=["GET", "POST"])
@resident_required
def taleplerim():
    """Sakinin kendi taleplerini görüntülemesi ve yeni talep açması."""
    user, apartment = _get_current_resident()
    if not user:
        flash("Kullanıcı bulunamadı. Lütfen tekrar giriş yapın.", "error")
        return redirect(url_for("auth.logout"))

    if request.method == "POST":
        title = (request.form.get("title") or "").strip()
        description = (request.form.get("description") or "").strip()
        priority = (request.form.get("priority") or "normal").strip()

        if not title or not description:
            flash("Talep başlığı ve açıklaması zorunludur.", "error")
        else:
            try:
                ticket = Ticket(
                    apartment_id=apartment.id if apartment else None,
                    user_id=user.id,
                    title=title,
                    description=description,
                    priority=priority or "normal",
                    status="open",
                    created_at=datetime.utcnow(),
                )
                db.session.add(ticket)
                db.session.commit()
                flash("Talebiniz başarıyla oluşturuldu.", "success")
            except SQLAlchemyError as exc:
                db.session.rollback()
                current_app.logger.exception("Talep eklenemedi: %s", exc)
                flash("Talep kaydedilirken bir hata oluştu.", "error")

    tickets = []
    try:
        tickets = (
            Ticket.query.filter(Ticket.user_id == user.id)
            .order_by(Ticket.created_at.desc())
            .all()
        )
    except SQLAlchemyError as exc:
        current_app.logger.exception("Talep listesi alınamadı: %s", exc)
        flash("Talep listeniz alınırken bir hata oluştu.", "error")

    return render_template(
        "resident/taleplerim.html",
        user=user,
        apartment=apartment,
        tickets=tickets,
    )


# ======================
#  PROFİL
# ======================


@resident_bp.route("/profil", methods=["GET", "POST"])
@resident_required
def profil():
    """Sakinin kendi iletişim bilgilerini güncellemesi için basit profil ekranı."""
    user, apartment = _get_current_resident()
    if not user:
        flash("Kullanıcı bulunamadı. Lütfen tekrar giriş yapın.", "error")
        return redirect(url_for("auth.logout"))

    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        phone = (request.form.get("phone") or "").strip()
        password = request.form.get("password") or ""
        password_confirm = request.form.get("password_confirm") or ""

        if not name:
            flash("Ad soyad alanı boş bırakılamaz.", "error")
        else:
            try:
                user.name = name
                user.phone = phone

                if password or password_confirm:
                    if password != password_confirm:
                        flash("Şifre ve şifre tekrarı eşleşmiyor.", "error")
                    elif len(password) < 6:
                        flash("Şifre en az 6 karakter olmalıdır.", "error")
                    else:
                        user.set_password(password)
                        flash("Şifreniz güncellendi.", "success")

                db.session.commit()
                flash("Profil bilgileriniz güncellendi.", "success")
            except SQLAlchemyError as exc:
                db.session.rollback()
                current_app.logger.exception("Profil güncellenemedi: %s", exc)
                flash("Profil güncellenirken bir hata oluştu.", "error")

    return render_template(
        "resident/profil.html",
        user=user,
        apartment=apartment,
    )
