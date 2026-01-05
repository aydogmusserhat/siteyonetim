from functools import wraps
from datetime import datetime, date
from decimal import Decimal
from collections import defaultdict
from models.settings_model import SystemSetting

from flask import (
    Blueprint,
    render_template,
    session,
    redirect,
    url_for,
    flash,
    current_app,
    request,
    jsonify,
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


admin_bp = Blueprint("admin", __name__, url_prefix="/admin")

# ==================================================
#  AYLIK AİDAT İÇİN VARSAYILAN TUTAR (DEĞİŞTİREBİLİRSİN)
# ==================================================


# ======================
#  YETKİ KONTROL
# ======================

def admin_required(view_func):
    """
    Sadece 'admin' rolündeki kullanıcıların erişmesini sağlayan decorator.
    Giriş yoksa /login, rol yanlışsa index'e yönlendirir.
    """

    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        user_id = session.get("user_id")
        role = session.get("user_role")

        if not user_id:
            flash("Devam etmek için lütfen giriş yapın.", "info")
            return redirect(url_for("auth.login"))

        if role != "admin":
            flash("Bu alana sadece yönetici kullanıcılar erişebilir.", "error")
            return redirect(url_for("index"))

        return view_func(*args, **kwargs)

    return wrapped_view


def _get_current_admin():
    """Session'daki admin kullanıcının User nesnesini döner."""
    user_id = session.get("user_id")
    if not user_id:
        return None
    try:
        return User.query.get(user_id)
    except SQLAlchemyError as exc:
        current_app.logger.exception("Admin bilgisi alınamadı: %s", exc)
        return None

# ======================
#  SETTINGS
# ======================


def get_default_monthly_dues_amount() -> Decimal:
    """
    Varsayılan aylık aidat tutarını ayarlar tablosundan (SystemSetting)
    okur. Herhangi bir hata ya da kayıt bulunamazsa 1000.00 TL döner.
    Böylece tek bir doğruluk kaynağı kullanılmış olur.
    """
    fallback = Decimal("500.00")
    try:
        settings = SystemSetting.get_singleton()
        if settings and settings.default_monthly_dues_amount is not None:
            return Decimal(settings.default_monthly_dues_amount)
    except SQLAlchemyError as exc:
        current_app.logger.exception("Varsayılan aidat tutarı okunamadı: %s", exc)

    return fallback


# ======================== Tarih formatlarını anlama ==========================
def _parse_date_flex(value: str):
    """
    Girilen tarihi esnek formatlarla çözmeye çalışır.
    Örnek: 04.01.2026, 4/1/2026, 2026-01-04
    """
    if not value:
        return None
    value = value.strip()

    # Ayraçları normalize et
    norm = value.replace("/", ".").replace("-", ".")
    parts = [p for p in norm.split(".") if p]

    from datetime import datetime, date

    if len(parts) == 3:
        try:
            # 2026.01.04 veya 2026.1.4
            if len(parts[0]) == 4:
                year, month, day = parts
            else:
                # 04.01.2026 veya 4.1.2026
                day, month, year = parts
            return date(int(year), int(month), int(day))
        except ValueError:
            pass

    # Yine de anlamazsa klasik formatları dene
    for fmt in ("%Y-%m-%d", "%d.%m.%Y", "%d/%m/%Y"):
        try:
            return datetime.strptime(value, fmt).date()
        except ValueError:
            continue

    raise ValueError("Geçersiz tarih formatı")


# ==============================================================================
# ======================
#  DASHBOARD
# ======================
@admin_bp.route("/dashboard")
@admin_required
def dashboard():
    """Genel yönetim paneli özeti + son 12 ay aylık özet."""

    admin_user = _get_current_admin()

    stats = {
        "total_apartments": 0,
        "total_users": 0,
        "resident_users": 0,
        "admin_users": 0,
        "total_bills": 0,
        # 👉 Bu kartta gösterilecek: bu ay beklenen gelir - bu ay ödenen
        "total_open_amount": Decimal("0.00"),
        # 👉 Bu kartta artık sadece bu aya ait ödemeler var
        "total_paid_amount": Decimal("0.00"),
        # 👉 Bu ay oluşturulan borçların toplamı
        "expected_income_this_month": Decimal("0.00"),
        "open_tickets": 0,
    }

    today = date.today()

    # =========================
    #  GENEL SAYILAR
    # =========================
    try:
        stats["total_apartments"] = Apartment.query.count()
        stats["total_users"] = User.query.count()
        stats["resident_users"] = User.query.filter_by(role="resident").count()
        stats["admin_users"] = User.query.filter_by(role="admin").count()
    except SQLAlchemyError as exc:
        current_app.logger.exception("Dashboard kullanıcı istatistikleri alınamadı: %s", exc)

    # =========================
    #  BORÇ / ÖDEME ÖZETLERİ
    # =========================
    try:
        stats["total_bills"] = Bill.query.count()

        # Bu ayın başlangıcı ve bir sonraki ayın başlangıcı
        month_start = date(today.year, today.month, 1)
        if today.month == 12:
            month_end = date(today.year + 1, 1, 1)
        else:
            month_end = date(today.year, today.month + 1, 1)

        # Bu ay oluşturulan borçların toplamı (beklenen gelir)
        month_bills_sum = (
            db.session.query(func.coalesce(func.sum(Bill.amount), 0))
            .filter(
                Bill.created_at >= month_start,
                Bill.created_at < month_end,
            )
            .scalar()
        )
        billed_dec = Decimal(month_bills_sum or 0)

        # Bu ay yapılan ödemelerin toplamı
        month_payments_sum = (
            db.session.query(func.coalesce(func.sum(Payment.amount), 0))
            .filter(
                Payment.payment_date >= month_start,
                Payment.payment_date < month_end,
            )
            .scalar()
        )
        paid_dec = Decimal(month_payments_sum or 0)

        # Kartlar:
        # "Bu Ay Beklenen Toplam Gelir"
        stats["expected_income_this_month"] = billed_dec
        # "Toplam Ödenmiş" kartı → bu aya ait ödemeler
        stats["total_paid_amount"] = paid_dec
        # "Açık / Kısmi Borç" kartı → bu ayın farkı
        diff = billed_dec - paid_dec
        if diff < 0:
            diff = Decimal("0.00")
        stats["total_open_amount"] = diff

    except SQLAlchemyError as exc:
        current_app.logger.exception("Dashboard borç istatistikleri alınamadı: %s", exc)

    # =========================
    #  AÇIK TALEP SAYISI
    # =========================
    try:
        stats["open_tickets"] = Ticket.query.filter(
            Ticket.status.in_(["open", "in_progress"])
        ).count()
    except SQLAlchemyError as exc:
        current_app.logger.exception("Dashboard talep istatistikleri alınamadı: %s", exc)

    # =========================
    #  SON KAYITLAR
    # =========================
    recent_bills = []
    recent_payments = []
    recent_tickets = []
    recent_announcements = []

    # Son borçlar
    try:
        recent_bills = (
            db.session.query(Bill, Apartment)
            .outerjoin(Apartment, Bill.apartment_id == Apartment.id)
            .order_by(Bill.created_at.desc())
            .limit(5)
            .all()
        )
    except SQLAlchemyError:
        pass

    # Son ödemeler
    try:
        recent_payments = (
            db.session.query(Payment, Apartment, User)
            .outerjoin(Apartment, Payment.apartment_id == Apartment.id)
            .outerjoin(User, Payment.user_id == User.id)
            .order_by(Payment.payment_date.desc())
            .limit(5)
            .all()
        )
    except SQLAlchemyError:
        pass

    # Son talepler
    try:
        recent_tickets = (
            db.session.query(Ticket, Apartment, User)
            .outerjoin(Apartment, Ticket.apartment_id == Apartment.id)
            .outerjoin(User, Ticket.user_id == User.id)
            .order_by(Ticket.created_at.desc())
            .limit(5)
            .all()
        )
    except SQLAlchemyError:
        pass

    # Son duyurular
    try:
        recent_announcements = (
            db.session.query(Announcement, User)
            .outerjoin(User, Announcement.created_by == User.id)
            .order_by(Announcement.created_at.desc())
            .limit(5)
            .all()
        )
    except SQLAlchemyError:
        pass

    # =========================
    #  SON 12 AYLIK ÖZET
    # =========================
      # =========================
    #  SON 12 AYLIK ÖZET
    # =========================
    monthly_overview = []
    try:
        MONTH_LABELS_TR = {
            1: "Ocak",
            2: "Şubat",
            3: "Mart",
            4: "Nisan",
            5: "Mayıs",
            6: "Haziran",
            7: "Temmuz",
            8: "Ağustos",
            9: "Eylül",
            10: "Ekim",
            11: "Kasım",
            12: "Aralık",
        }

        # Bugünün yılı / ayı
        cur_y = today.year
        cur_m = today.month

        from dateutil.relativedelta import relativedelta

        # 12 ay geriye kadar verileri gruplayacağız
        start_date = date(cur_y, cur_m, 1) - relativedelta(months=11)
        end_date = date(cur_y, cur_m, 1) + relativedelta(months=1)

        bills_in_range = (
            Bill.query
            .filter(
                Bill.created_at >= start_date,
                Bill.created_at < end_date,
            )
            .all()
        )

        payments_in_range = (
            Payment.query
            .filter(
                Payment.payment_date >= start_date,
                Payment.payment_date < end_date,
            )
            .all()
        )

        bill_totals = defaultdict(Decimal)
        pay_totals = defaultdict(Decimal)

        # Borçlar → aya göre grupla
        for b in bills_in_range:
            if not b.created_at:
                continue
            d = b.created_at.date()
            bill_totals[(d.year, d.month)] += Decimal(b.amount or 0)

        # Ödemeler → aya göre grupla
        for p in payments_in_range:
            if not p.payment_date:
                continue
            d = p.payment_date.date()
            pay_totals[(d.year, d.month)] += Decimal(p.amount or 0)

        # 🔥 EN ÖNEMLİ KISIM:
        # Liste güncel aydan geriye doğru gelecek
        y = cur_y
        m = cur_m

        for _ in range(12):
            key = (y, m)
            total_billed = bill_totals.get(key, Decimal("0"))
            total_paid = pay_totals.get(key, Decimal("0"))

            monthly_overview.append({
                "year": y,
                "month": m,
                "label": f"{MONTH_LABELS_TR[m]} {y}",
                "total_billed": total_billed,
                "total_paid": total_paid,
                "delta": total_paid - total_billed
            })

            # bir önceki aya git
            if m == 1:
                m = 12
                y -= 1
            else:
                m -= 1

    except Exception as exc:
        current_app.logger.exception("Aylık özet hesaplanamadı: %s", exc)
        monthly_overview = []


    return render_template(
        "admin/dashboard.html",
        admin_user=admin_user,
        stats=stats,
        recent_bills=recent_bills,
        recent_payments=recent_payments,
        recent_tickets=recent_tickets,
        recent_announcements=recent_announcements,
        today=today,
        monthly_overview=monthly_overview,
    )


# ======================
#  DAİRELER
# ======================
@admin_bp.route("/apartments", methods=["GET", "POST"])
@admin_required
def manage_apartments():
    """Daire listesi ve yeni daire ekleme."""
    if request.method == "POST":
        block = (request.form.get("block") or "").strip()
        floor = (request.form.get("floor") or "").strip()
        number = (request.form.get("number") or "").strip()
        area_m2 = (request.form.get("area_m2") or "").strip()
        owner_name = (request.form.get("owner_name") or "").strip()
        owner_phone = (request.form.get("owner_phone") or "").strip()
        notes = (request.form.get("notes") or "").strip()

        if not block or not floor or not number:
            flash("Blok, kat ve daire numarası zorunludur.", "error")
        else:
            try:
                # 🔴 DUPLICATE KONTROLÜ: Aynı blok+kat+no var mı?
                existing_apt = (
                    Apartment.query
                    .filter_by(block=block, floor=floor, number=number)
                    .first()
                )
                if existing_apt:
                    flash(
                        f"{block} blok, {floor}. kat, {number} no için zaten bir daire kaydı mevcut.",
                        "error",
                    )
                else:
                    apt = Apartment(
                        block=block,
                        floor=floor,
                        number=number,
                        owner_name=owner_name or None,
                        owner_phone=owner_phone or None,
                        notes=notes or None,
                    )
                    if area_m2:
                        try:
                            apt.area_m2 = float(area_m2.replace(",", "."))
                        except ValueError:
                            flash("Metrekare bilgisi sayısal olmalıdır.", "error")

                    db.session.add(apt)
                    db.session.commit()
                    flash("Daire başarıyla eklendi.", "success")

            except SQLAlchemyError as exc:
                db.session.rollback()
                current_app.logger.exception("Daire eklenemedi: %s", exc)
                flash("Daire kaydedilirken bir hata oluştu.", "error")

    apartments = []
    try:
        apartments = Apartment.query.order_by(
            Apartment.block.asc(),
            Apartment.floor.asc(),
            Apartment.number.asc(),
        ).all()
    except SQLAlchemyError as exc:
        current_app.logger.exception("Daire listesi alınamadı: %s", exc)
        flash("Daire listesi alınırken bir hata oluştu.", "error")

    return render_template("admin/daireler.html", apartments=apartments)


@admin_bp.route("/apartments/<int:apartment_id>/update", methods=["POST"])
@admin_required
def update_apartment(apartment_id: int):
    """Tek bir dairenin bilgilerini günceller (satır içi düzenleme)."""
    try:
        apt = Apartment.query.get(apartment_id)
        if not apt:
            flash("Daire bulunamadı.", "error")
            return redirect(url_for("admin.manage_apartments"))

        block = (request.form.get("block") or "").strip()
        floor = (request.form.get("floor") or "").strip()
        number = (request.form.get("number") or "").strip()
        area_m2 = (request.form.get("area_m2") or "").strip()
        owner_name = (request.form.get("owner_name") or "").strip()
        owner_phone = (request.form.get("owner_phone") or "").strip()
        notes = (request.form.get("notes") or "").strip()

        if not block or not floor or not number:
            flash("Blok, kat ve daire numarası zorunludur.", "error")
            return redirect(url_for("admin.manage_apartments"))

        # 🔴 DUPLICATE KONTROLÜ: Bu id dışındaki kayıtlar içinde aynı blok+kat+no var mı?
        duplicate_apt = (
            Apartment.query
            .filter(
                Apartment.id != apartment_id,
                Apartment.block == block,
                Apartment.floor == floor,
                Apartment.number == number,
            )
            .first()
        )
        if duplicate_apt:
            flash(
                f"{block} blok, {floor}. kat, {number} no başka bir daireye zaten atanmış.",
                "error",
            )
            return redirect(url_for("admin.manage_apartments"))

        # 🔵 Buraya geldiysek: çakışma yok, güvenle güncelleyebiliriz
        apt.block = block
        apt.floor = floor
        apt.number = number
        apt.owner_name = owner_name or None
        apt.owner_phone = owner_phone or None
        apt.notes = notes or None

        if area_m2:
            try:
                apt.area_m2 = float(area_m2.replace(",", "."))
            except ValueError:
                flash("Metrekare bilgisi sayısal olmalıdır.", "error")

        db.session.commit()
        flash("Daire bilgileri güncellendi.", "success")

    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Daire güncellenemedi: %s", exc)
        flash("Daire güncellenirken bir hata oluştu.", "error")

    return redirect(url_for("admin.manage_apartments"))

@admin_bp.route("/apartments/<int:apartment_id>/delete", methods=["POST"])
@admin_required
def delete_apartment(apartment_id: int):
    """
    Daireyi siler.
    Eğer daireye ait ÖDENMEMİŞ borç (bill) varsa silmeye izin vermez.
    Koşul: Her bill için sum(Payment.amount) >= Bill.amount olmalı.
    """
    try:
        apt = Apartment.query.get(apartment_id)
        if not apt:
            flash("Daire bulunamadı.", "error")
            return redirect(url_for("admin.manage_apartments"))

        # 🔍 Bu daireye ait ödenmemiş borç var mı?
        # bill.amount > ödenen toplamı olan en az 1 kayıt varsa silme.
        unpaid_bill = (
            db.session.query(Bill.id)
            .outerjoin(Payment, Payment.bill_id == Bill.id)
            .filter(Bill.apartment_id == apartment_id)
            .group_by(Bill.id, Bill.amount)
            .having(func.coalesce(func.sum(Payment.amount), 0) < Bill.amount)
            .first()
        )

        if unpaid_bill:
            # ✅ İstediğin uyarı metni:
            flash("Bu dairenin silinebilmesi için TÜM borçlarının tamamen ödenmiş olması gerekir.", "error")
            return redirect(url_for("admin.manage_apartments"))

        # Buraya geldiysek: hiç borcu kalmamış → silinebilir
        db.session.delete(apt)
        db.session.commit()
        flash("Daire kaydı silindi.", "success")

    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Daire silinemedi: %s", exc)
        flash("Daire silinirken bir hata oluştu.", "error")

    return redirect(url_for("admin.manage_apartments"))


# ======================
#  KULLANICILAR
# ======================

@admin_bp.route("/users", methods=["GET", "POST"])
@admin_required
def manage_users():
    """Kullanıcı listesi ve yeni kullanıcı ekleme."""
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        phone = (request.form.get("phone") or "").strip()
        role = (request.form.get("role") or "resident").strip()
        apartment_id = request.form.get("apartment_id") or None
        password = request.form.get("password") or ""

        if not name or not email or not password:
            flash("Ad, e-posta ve şifre alanları zorunludur.", "error")
        else:
            try:
                existing = User.query.filter_by(email=email).first()
                if existing:
                    flash("Bu e-posta ile kayıtlı bir kullanıcı zaten var.", "error")
                else:
                    user = User(
                        name=name,
                        email=email,
                        phone=phone or None,
                        role=role if role in ("admin", "resident") else "resident",
                        is_active=True,
                    )
                    if apartment_id:
                        try:
                            user.apartment_id = int(apartment_id)
                        except ValueError:
                            pass
                    user.set_password(password)
                    db.session.add(user)
                    db.session.commit()
                    flash("Kullanıcı başarıyla oluşturuldu.", "success")
            except SQLAlchemyError as exc:
                db.session.rollback()
                current_app.logger.exception("Kullanıcı eklenemedi: %s", exc)
                flash("Kullanıcı kaydedilirken bir hata oluştu.", "error")

    users = []
    apartments = []
    try:
        users = User.query.order_by(User.role.desc(), User.name.asc()).all()
        apartments = Apartment.query.order_by(
            Apartment.block.asc(),
            Apartment.floor.asc(),
            Apartment.number.asc(),
        ).all()
    except SQLAlchemyError as exc:
        current_app.logger.exception("Kullanıcı listesi alınamadı: %s", exc)
        flash("Kullanıcı listesi alınırken bir hata oluştu.", "error")

    return render_template(
        "admin/kullanicilar.html",
        users=users,
        apartments=apartments,
    )


@admin_bp.route("/users/<int:user_id>/toggle-active", methods=["POST"])
@admin_required
def toggle_user_active(user_id: int):
    """Kullanıcının aktif/pasif durumunu değiştirir."""
    try:
        user = User.query.get(user_id)
        if not user:
            flash("Kullanıcı bulunamadı.", "error")
            return redirect(url_for("admin.manage_users"))

        user.is_active = not bool(user.is_active)
        db.session.commit()
        flash(
            f"Kullanıcı durumu güncellendi: {'Aktif' if user.is_active else 'Pasif'}",
            "success",
        )
    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Kullanıcı durumu değiştirilemedi: %s", exc)
        flash("Kullanıcı durumu güncellenirken bir hata oluştu.", "error")

    return redirect(url_for("admin.manage_users"))


# ======================
#  AİDATLAR / BORÇLAR
# ======================
# ======================
#  AİDATLAR / BORÇLAR
# ======================
@admin_bp.route("/bills", methods=["GET", "POST"])
@admin_required
def manage_bills():
    """Aidat / borç kayıtlarını yönetir."""
    apartments = []
    bills = []
    apartment_summaries = []

    # --- Listeleme parametreleri (filtre / sıralama / sayfalama) ---
    page = request.args.get("page", 1, type=int) or 1
    if page < 1:
        page = 1

    per_page = 20  # ✅ max 20 satır
    sort = (request.args.get("sort") or "created_at").strip()
    direction = (request.args.get("dir") or "desc").strip().lower()
    if direction not in ("asc", "desc"):
        direction = "desc"

    filter_status = (request.args.get("status") or "").strip()
    filter_type = (request.args.get("bill_type") or "").strip()

    # ======================
    #  YENİ BORÇ / AİDAT EKLEME
    # ======================
    if request.method == "POST":
        apartment_id = (request.form.get("apartment_id") or "").strip()
        description = (request.form.get("description") or "").strip()
        amount_str = (request.form.get("amount") or "").strip()
        due_date_str = (request.form.get("due_date") or "").strip()
        bill_type = (request.form.get("type") or "").strip() or None
        for_all = request.form.get("for_all") == "1"

        # Daire (veya tüm daireler), açıklama ve tutar zorunlu
        if (not apartment_id and not for_all) or not description or not amount_str:
            flash("Daire (veya tüm daireler), açıklama ve tutar zorunludur.", "error")
        else:
            try:
                # Hangi dairelere borç yazılacak?
                if for_all:
                    target_apartments = (
                        Apartment.query
                        .order_by(
                            Apartment.block.asc(),
                            Apartment.floor.asc(),
                            Apartment.number.asc(),
                        )
                        .all()
                    )
                else:
                    apt = Apartment.query.get(int(apartment_id))
                    target_apartments = [apt] if apt else []

                if not target_apartments:
                    flash("Borç eklenecek daire bulunamadı.", "error")
                else:
                    amount = Decimal(amount_str.replace(",", "."))
                    due_date = None
                    if due_date_str:
                        try:
                            # Esnek tarih çözümü: 04.01.2026, 4/1/2026, 2026-01-04 vs.
                            due_date = _parse_date_flex(due_date_str)
                        except ValueError:
                            flash("Vade tarihi anlaşılamadı. Örnek: 04.01.2026", "error")
                            return redirect(url_for("admin.manage_bills"))


                    created_count = 0
                    for apt in target_apartments:
                        if not apt:
                            continue
                        bill = Bill(
                            apartment_id=apt.id,
                            description=description,
                            status="open",
                            type=bill_type,
                        )
                        bill.amount = amount
                        if due_date:
                            bill.due_date = due_date
                        db.session.add(bill)
                        created_count += 1

                    db.session.commit()
                    if created_count == 1:
                        flash("Borç kaydı oluşturuldu.", "success")
                    else:
                        flash(
                            f"Borç / aidat kaydı {created_count} daire için oluşturuldu.",
                            "success",
                        )

            except (ValueError, SQLAlchemyError) as exc:
                db.session.rollback()
                current_app.logger.exception("Borç kaydı eklenemedi: %s", exc)
                flash("Borç kaydedilirken bir hata oluştu.", "error")

    # ======================
    #  LİSTELER + DAİRE ÖZETLERİ
    # ======================
    try:
        # Daire listesi (soldaki form için)
        apartments = (
            Apartment.query
            .order_by(
                Apartment.block.asc(),
                Apartment.floor.asc(),
                Apartment.number.asc(),
            )
            .all()
        )

        # ---- Detay borç listesi (filtre + sıralama + sayfalama) ----
        base_query = (
            db.session.query(Bill, Apartment)
            .outerjoin(Apartment, Bill.apartment_id == Apartment.id)
        )

        # Filtre: durum
        if filter_status in ("open", "partial", "paid"):
            base_query = base_query.filter(Bill.status == filter_status)

        # Filtre: tür
        if filter_type:
            base_query = base_query.filter(Bill.type == filter_type)

        # Sıralama alanları
        allowed_sorts = {
            "apartment": "apartment",
            "description": Bill.description,
            "type": Bill.type,
            "amount": Bill.amount,
            "due_date": Bill.due_date,
            "status": Bill.status,
            "created_at": Bill.created_at,
        }
        if sort not in allowed_sorts:
            sort = "created_at"

        order_columns = []
        asc = direction == "asc"

        if sort == "apartment":
            # blok / kat / daire sırası
            if asc:
                order_columns = [
                    Apartment.block.asc(),
                    Apartment.floor.asc(),
                    Apartment.number.asc(),
                ]
            else:
                order_columns = [
                    Apartment.block.desc(),
                    Apartment.floor.desc(),
                    Apartment.number.desc(),
                ]
        else:
            col = allowed_sorts[sort]
            order_columns = [col.asc() if asc else col.desc()]

        if order_columns:
            base_query = base_query.order_by(*order_columns)

        # Toplam kayıt sayısı
        total_bills = base_query.count()

        # Sayfalama
        offset = (page - 1) * per_page
        bills = (
            base_query
            .offset(offset)
            .limit(per_page)
            .all()
        )

        pages = (total_bills + per_page - 1) // per_page if total_bills > 0 else 1

        # 🔹 DAİRE + TÜR BAZINDA TOPLAMLAR (borç / ödenen)
        rows = (
            db.session.query(
                Apartment,
                Bill.type.label("bill_type"),
                func.coalesce(func.sum(Bill.amount), 0).label("total_debt"),
                func.coalesce(func.sum(Payment.amount), 0).label("total_paid"),
            )
            .outerjoin(Bill, Bill.apartment_id == Apartment.id)
            .outerjoin(Payment, Payment.bill_id == Bill.id)
            .group_by(Apartment.id, Bill.type)
            .order_by(
                Apartment.block.asc(),
                Apartment.floor.asc(),
                Apartment.number.asc(),
                Bill.type.asc(),
            )
            .all()
        )

        summary_map = {}

        for apt, bill_type, total_debt, total_paid in rows:
            if apt is None:
                continue

            entry = summary_map.get(apt.id)
            if not entry:
                entry = {
                    "apartment": apt,
                    "total_debt": Decimal("0.00"),
                    "total_paid": Decimal("0.00"),
                    "type_totals": {},  # tür bazlı borç tutarları
                }
                summary_map[apt.id] = entry

            debt_dec = Decimal(total_debt or 0)
            paid_dec = Decimal(total_paid or 0)

            entry["total_debt"] += debt_dec
            entry["total_paid"] += paid_dec

            t = bill_type or "genel"
            entry["type_totals"][t] = entry["type_totals"].get(t, Decimal("0.00")) + debt_dec

        apartment_summaries = []

        for _, entry in summary_map.items():
            remaining = entry["total_debt"] - entry["total_paid"]
            if remaining < 0:
                remaining = Decimal("0.00")

            apartment_summaries.append({
                "apartment": entry["apartment"],
                "type_totals": entry["type_totals"],
                "total_debt": entry["total_debt"],
                "total_paid": entry["total_paid"],
                "remaining": remaining,
            })

        # Blok / kat / daireye göre sırala
        apartment_summaries.sort(
            key=lambda r: (
                r["apartment"].block,
                r["apartment"].floor,
                r["apartment"].number,
            )
        )

    except SQLAlchemyError as exc:
        current_app.logger.exception("Borç listesi / özetleri alınamadı: %s", exc)
        flash("Borç listesi alınırken bir hata oluştu.", "error")
        apartments = apartments or []
        bills = bills or []
        apartment_summaries = apartment_summaries or []
        total_bills = 0
        pages = 1

    # ✅ HER DURUMDA BİR RESPONSE DÖNÜYOR
    return render_template(
        "admin/aidatlar.html",
        apartments=apartments,
        bills=bills,
        apartment_summaries=apartment_summaries,
        # sayfa bilgileri
        page=page,
        pages=pages,
        per_page=per_page,
        total_bills=total_bills,
        current_sort=sort,
        current_dir=direction,
        filter_status=filter_status,
        filter_type=filter_type,
    )

# ==================================== borç silme ========================
@admin_bp.route("/bills/<int:bill_id>/delete", methods=["POST"])
@admin_required
def delete_bill(bill_id: int):
    """Seçilen borç kaydını siler."""
    try:
        bill = Bill.query.get(bill_id)
        if not bill:
            flash("Silinecek borç kaydı bulunamadı.", "error")
        else:
            db.session.delete(bill)
            db.session.commit()
            flash("Borç kaydı silindi.", "success")
    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Borç kaydı silinemedi: %s", exc)
        flash("Borç silinirken bir hata oluştu.", "error")

    return redirect(url_for("admin.manage_bills"))

@admin_bp.route("/bills/<int:bill_id>/update", methods=["POST"])
@admin_required
def update_bill(bill_id: int):
    """
    Borç kaydını günceller.
    - Durum (status) burada değiştirilmez (open/partial/paid dokunmuyoruz).
    - Tarih formatı esnek: YYYY-AA-GG, GG.AA.YYYY, GG/AA/YYYY, GG-AA-YYYY gibi.
    """
    description = (request.form.get("description") or "").strip()
    amount_str = (request.form.get("amount") or "").strip()
    due_date_str = (request.form.get("due_date") or "").strip()
    bill_type = (request.form.get("type") or "").strip() or None

    try:
        bill = Bill.query.get(bill_id)
        if not bill:
            flash("Güncellenecek borç kaydı bulunamadı.", "error")
            return redirect(url_for("admin.manage_bills"))

        # Açıklama
        if description:
            bill.description = description

        # Tutar
        if amount_str:
            bill.amount = Decimal(amount_str.replace(",", "."))

        # Vade tarihi (esnek format)
# Vade tarihi (esnek format)
        if due_date_str:
            try:
                bill.due_date = _parse_date_flex(due_date_str)
            except ValueError:
                # Eski davranışı koruyalım: sadece uyarı, eski tarih kalsın
                flash("Tarih formatı anlaşılamadı, mevcut tarih korunuyor. Örnek: 04.01.2026", "warning")


        # Tür
        # (Tür listesi HTML tarafında sabit; burada sadece gelen değeri yazıyoruz)
        bill.type = bill_type

        db.session.commit()
        flash("Borç kaydı güncellendi.", "success")

    except (ValueError, SQLAlchemyError) as exc:
        db.session.rollback()
        current_app.logger.exception("Borç kaydı güncellenemedi: %s", exc)
        flash("Borç güncellenirken bir hata oluştu.", "error")

    return redirect(url_for("admin.manage_bills"))


# ========================================================================



# ===== AİDAT DURUMU (YILLIK ÖZET TABLOSU + OTOMATİK AYLIK BORÇ) =====

@admin_bp.route("/dues-summary", methods=["GET"])
@admin_required
def dues_summary():
    """
    Her DAİRE için, seçilen yılda Ocak–Aralık aidat durumlarını özetleyen tablo.

    - Satır = Apartment (daire)
    - Varsa o daireye atanmış ilk aktif resident kullanıcı "sakin" sütununda gösterilir.
    - Özet durumu (paid / partial / open), (apartment_id, ay) bazında hesaplanır.

    Ek olarak:
    - İçinde bulunulan yılda ve AY'da:
      Tüm daireler için, eğer o ay için borç kaydı yoksa
      otomatik bir 'aidat' Bill kaydı açılır (status='open').
    """

    now = datetime.utcnow()
    current_year = now.year
    current_month = now.month

    # Yıl seçimi (query string: ?year=2026 gibi)
    year = request.args.get("year", type=int) or current_year

    # 1..12 ay listesi (etiketler Türkçe)
    months = [
        (1, "Ocak"),
        (2, "Şubat"),
        (3, "Mart"),
        (4, "Nisan"),
        (5, "Mayıs"),
        (6, "Haziran"),
        (7, "Temmuz"),
        (8, "Ağustos"),
        (9, "Eylül"),
        (10, "Ekim"),
        (11, "Kasım"),
        (12, "Aralık"),
    ]
    month_labels = dict(months)

    # 1) Tüm daireleri çek (satır bazımız bu olacak)
    apartments = []
    try:
        apartments = (
            Apartment.query
            .order_by(
                Apartment.block.asc(),
                Apartment.floor.asc(),
                Apartment.number.asc(),
            )
            .all()
        )
    except SQLAlchemyError as exc:
        current_app.logger.exception("Aidat durumu için daire listesi alınamadı: %s", exc)
        flash("Daire listesi alınırken bir hata oluştu.", "error")
        apartments = []

    # 2) Eğer seçilen yıl, içinde bulunduğumuz yıl ise:
    #    - Tüm daireler için, mevcut ayda (current_month)
    #      borç kaydı yoksa otomatik 'aidat' Bill oluştur.
    if year == current_year and apartments:
        try:
            active_apartment_ids = {apt.id for apt in apartments if apt.id is not None}

            month_start = date(year, current_month, 1)
            if current_month == 12:
                month_end = date(year + 1, 1, 1)
            else:
                month_end = date(year, current_month + 1, 1)

            existing_bills = (
                Bill.query.filter(
                    Bill.apartment_id.in_(active_apartment_ids),
                    Bill.due_date >= month_start,
                    Bill.due_date < month_end,
                )
                .all()
            )

            apartments_with_bill = {
                b.apartment_id for b in existing_bills if b.apartment_id is not None
            }

            for apt_id in active_apartment_ids:
                if apt_id in apartments_with_bill:
                    continue

                desc = f"{year} {month_labels.get(current_month, str(current_month))} aidatı"
                auto_bill = Bill(
                    apartment_id=apt_id,
                    description=desc,
                    amount=get_default_monthly_dues_amount(),  # ✅ artık ayarlardan
                    status="open",
                    type="aidat",
                    due_date=month_start,
                    created_at=datetime.utcnow(),
                )
                db.session.add(auto_bill)

            db.session.commit()

        except SQLAlchemyError as exc:
            db.session.rollback()
            current_app.logger.exception("Otomatik aylık aidat oluşturulamadı: %s", exc)
            flash("Otomatik aidat oluşturulurken bir hata oluştu.", "error")

    # 3) Seçilen yıl için tüm Bill kayıtlarını çek (due_date'e göre)
    start_date = date(year, 1, 1)
    end_date = date(year + 1, 1, 1)

    bills = []
    payments = []
    bill_totals = defaultdict(Decimal)
    bill_key_by_id = {}

    try:
        bills = (
            Bill.query
            .filter(
                Bill.due_date >= start_date,
                Bill.due_date < end_date,
            )
            .all()
        )

        # Bill -> (apt_id, month) map'i ve toplam borçlar
        for b in bills:
            if not b.apartment_id or not b.due_date:
                continue
            key = (b.apartment_id, b.due_date.month)
            bill_totals[key] += Decimal(b.amount or 0)
            bill_key_by_id[b.id] = key

        # Bu Bill'lere bağlı tüm ödemeleri çek
        if bill_key_by_id:
            payments = (
                Payment.query
                .filter(Payment.bill_id.in_(bill_key_by_id.keys()))
                .all()
            )
        else:
            payments = []

        # Ödenen toplamlar
        paid_totals = defaultdict(Decimal)   # key: (apartment_id, month) -> toplam ödeme
        for p in payments:
            if not p.bill_id:
                continue
            key = bill_key_by_id.get(p.bill_id)
            if not key:
                continue
            paid_totals[key] += Decimal(p.amount or 0)

        # Final durum map'i: key -> "paid" / "partial" / "open"
        status_map = {}
        for key, total_bill in bill_totals.items():
            total_paid = paid_totals.get(key, Decimal("0"))
            if total_bill <= 0:
                continue

            if total_paid >= total_bill:
                status_map[key] = "paid"
            elif total_paid > 0:
                status_map[key] = "partial"
            else:
                status_map[key] = "open"

    except SQLAlchemyError as exc:
        current_app.logger.exception("Aidat durumu hesaplanamadı: %s", exc)
        flash("Aidat durumu hesaplanırken bir hata oluştu.", "error")
        status_map = {}
        bill_totals = {}

    # 4) Dairelere atanmış ilk aktif sakinleri tek sorguda çek
    resident_by_apartment = {}
    try:
        residents = (
            User.query
            .filter(
                User.role == "resident",
                User.is_active == True,  # noqa: E712
                User.apartment_id.isnot(None),
            )
            .order_by(User.name.asc())
            .all()
        )
        for u in residents:
            # Her daire için ilk bulduğumuz aktif sakini baz alıyoruz
            if u.apartment_id not in resident_by_apartment:
                resident_by_apartment[u.apartment_id] = u
    except SQLAlchemyError as exc:
        current_app.logger.exception("Sakin listesi alınamadı: %s", exc)
        flash("Sakin listesi alınırken bir hata oluştu.", "error")
        resident_by_apartment = {}

    # 5) Template'e veri hazırlama: her daire için ay -> durum
    #    rows: [{apartment, resident, monthly: {month: "paid"/"partial"/"open"/None}}]
    rows = []
    for apt in apartments:
        monthly_status = {}
        for m_num, _m_label in months:
            key = (apt.id, m_num)
            if key in status_map:
                monthly_status[m_num] = status_map[key]
            else:
                monthly_status[m_num] = None  # O ay için borç yok → gri "-"

        resident = resident_by_apartment.get(apt.id)
        rows.append(
            {
                "apartment": apt,
                "resident": resident,
                "monthly": monthly_status,
            }
        )

    return render_template(
        "admin/aidat_durumu.html",
        year=year,
        current_year=current_year,
        months=months,
        rows=rows,
    )

# ========================= Borç status’ünü yeniden hesaplayan helper =========================

def _recalc_bill_status(bill: Bill):
    """Verilen borcun ödemelerine göre status alanını günceller."""
    total_paid_for_bill = (
        db.session.query(func.coalesce(func.sum(Payment.amount), 0))
        .filter(Payment.bill_id == bill.id)
        .scalar()
    )
    total_paid_for_bill = Decimal(total_paid_for_bill or 0)
    amount = Decimal(bill.amount or 0)

    if amount <= 0:
        bill.status = "open"
    elif total_paid_for_bill >= amount:
        bill.status = "paid"
    elif total_paid_for_bill > 0:
        bill.status = "partial"
    else:
        bill.status = "open"

# ======================
#  ÖDEMELER
# ======================
@admin_bp.route("/payments", methods=["GET", "POST"])
@admin_required
def manage_payments():
    """Ödeme kayıtlarını yönetir."""
    if request.method == "POST":
        apartment_id = request.form.get("apartment_id")
        bill_id = request.form.get("bill_id") or None   # override için hala var
        user_id = request.form.get("user_id") or None
        amount = (request.form.get("amount") or "").strip()
        payment_date_str = request.form.get("payment_date") or ""
        method = (request.form.get("method") or "").strip() or None
        bill_type = (request.form.get("bill_type") or "").strip() or None  # ✅ borç türü

        if not apartment_id or not amount:
            flash("Daire ve tutar zorunludur.", "error")
        else:
            try:
                # Temel ödeme objesini oluştur
                payment = Payment(
                    apartment_id=int(apartment_id),
                    method=method,
                )

                # Kullanıcı seçilmişse bağla
                if user_id:
                    payment.user_id = int(user_id)

                # ✅ Tutar her durumda set edilmeli
                try:
                    payment.amount = Decimal(amount.replace(",", "."))
                except (ValueError, ArithmeticError):
                    flash("Tutar sayısal olmalıdır.", "error")
                    return redirect(url_for("admin.manage_payments"))

                # ✅ Tarih her durumda set edilmeli
                if payment_date_str:
                    try:
                        payment.payment_date = _parse_date_flex(payment_date_str)
                    except ValueError:
                        flash("Ödeme tarihi anlaşılamadı. Örnek: 04.01.2026", "error")
                        return redirect(url_for("admin.manage_payments"))
                else:
                    # Tarih girilmediyse bugünün tarihi
                    payment.payment_date = datetime.utcnow().date()

                # ✅ Otomatik eşleştirme: tür + daire + ay
                if not bill_id and bill_type:
                    try:
                        apt_id_int = int(apartment_id)
                    except ValueError:
                        apt_id_int = None

                    if apt_id_int:
                        pay_date = payment.payment_date or datetime.utcnow().date()
                        month_start = date(pay_date.year, pay_date.month, 1)
                        if pay_date.month == 12:
                            month_end = date(pay_date.year + 1, 1, 1)
                        else:
                            month_end = date(pay_date.year, pay_date.month + 1, 1)

                        candidate_q = (
                            Bill.query.filter(
                                Bill.apartment_id == apt_id_int,
                                Bill.type == bill_type,
                                Bill.due_date >= month_start,
                                Bill.due_date < month_end,
                                Bill.status.in_(["open", "partial"]),
                            )
                            .order_by(Bill.due_date.asc())
                        )

                        candidate = candidate_q.first()
                        if candidate:
                            # Bu borç için daha önce ödenen toplam
                            already_paid = (
                                db.session.query(func.coalesce(func.sum(Payment.amount), 0))
                                .filter(Payment.bill_id == candidate.id)
                                .scalar()
                            )
                            already_paid = Decimal(already_paid or 0)
                            remaining = Decimal(candidate.amount or 0) - already_paid

                            if remaining > 0:
                                payment.bill_id = candidate.id
                                bill_id = str(candidate.id)

                # Eğer override veya otomatik bir bill_id bulunduysa
                if bill_id:
                    payment.bill_id = int(bill_id)

                db.session.add(payment)

                # İlgili borcun durumunu güncelle
                if bill_id:
                    bill = Bill.query.get(int(bill_id))
                    if bill:
                        total_paid_for_bill = (
                            db.session.query(func.coalesce(func.sum(Payment.amount), 0))
                            .filter(Payment.bill_id == bill.id)
                            .scalar()
                        )
                        total_paid_for_bill = Decimal(total_paid_for_bill or 0)

                        if total_paid_for_bill >= bill.amount:
                            bill.status = "paid"
                        elif total_paid_for_bill > 0:
                            bill.status = "partial"
                        else:
                            bill.status = "open"

                db.session.commit()
                flash("Ödeme kaydı oluşturuldu.", "success")

            except (ValueError, SQLAlchemyError) as exc:
                db.session.rollback()
                current_app.logger.exception("Ödeme kaydı eklenemedi: %s", exc)
                flash("Ödeme kaydedilirken bir hata oluştu.", "error")

    apartments = []
    bills = []
    users = []
    payments = []

    try:
        apartments = Apartment.query.order_by(
            Apartment.block.asc(),
            Apartment.floor.asc(),
            Apartment.number.asc(),
        ).all()
        bills = Bill.query.order_by(Bill.created_at.desc()).limit(200).all()
        users = User.query.order_by(User.name.asc()).all()

        payments = (
            db.session.query(Payment, Apartment, User, Bill)
            .outerjoin(Apartment, Payment.apartment_id == Apartment.id)
            .outerjoin(User, Payment.user_id == User.id)
            .outerjoin(Bill, Payment.bill_id == Bill.id)
            .order_by(Payment.payment_date.desc())
            .limit(200)
            .all()
        )

    except SQLAlchemyError as exc:
        current_app.logger.exception("Ödeme listesi alınamadı: %s", exc)
        flash("Ödeme listesi alınırken bir hata oluştu.", "error")

    return render_template(
        "admin/odemeler.html",
        apartments=apartments,
        bills=bills,
        users=users,
        payments=payments,
    )


@admin_bp.route("/payments/<int:payment_id>/update", methods=["POST"])
@admin_required
def update_payment(payment_id: int):
    """Tek bir ödeme kaydını satır içi (inline) düzenlemek için."""
    try:
        payment = Payment.query.get(payment_id)
        if not payment:
            return jsonify({"ok": False, "error": "Ödeme kaydı bulunamadı."}), 404

        amount_str = (request.form.get("amount") or "").strip()
        method = (request.form.get("method") or "").strip() or None
        date_str = (request.form.get("payment_date") or "").strip()

        if not amount_str:
            return jsonify({"ok": False, "error": "Tutar boş olamaz."}), 400

        try:
            payment.amount = Decimal(amount_str.replace(",", "."))
        except (ValueError, ArithmeticError):
            return jsonify({"ok": False, "error": "Tutar sayısal olmalıdır."}), 400

        if date_str:
            try:
                payment.payment_date = _parse_date_flex(date_str)
            except ValueError:
                return jsonify(
                    {
                        "ok": False,
                        "error": "Tarih formatı anlaşılamadı. Örnek: 04.01.2026",
                    }
                ), 400
        else:
            payment.payment_date = None

        payment.method = method

        # İlgili borcun durumunu güncelle
        if payment.bill_id:
            bill = Bill.query.get(payment.bill_id)
            if bill:
                _recalc_bill_status(bill)

        db.session.commit()

        # Formatlanmış stringler (frontend'e geri dönecek)
        amount_display = f"₺ {payment.amount:.2f}"
        date_display = (
            payment.payment_date.strftime("%d.%m.%Y")
            if payment.payment_date
            else ""
        )

        return jsonify(
            {
                "ok": True,
                "amount": amount_display,
                "payment_date": date_display,
            }
        )

    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Ödeme kaydı güncellenemedi: %s", exc)
        return jsonify(
            {"ok": False, "error": "Ödeme güncellenirken bir hata oluştu."}
        ), 500

@admin_bp.route("/payments/<int:payment_id>/delete", methods=["POST"])
@admin_required
def delete_payment(payment_id: int):
    """Tek bir ödeme kaydını silmek için."""
    try:
        payment = Payment.query.get(payment_id)
        if not payment:
            return jsonify({"ok": False, "error": "Ödeme kaydı bulunamadı."}), 404

        bill_id = payment.bill_id

        db.session.delete(payment)

        if bill_id:
            bill = Bill.query.get(bill_id)
            if bill:
                _recalc_bill_status(bill)

        db.session.commit()
        return jsonify({"ok": True})

    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Ödeme kaydı silinemedi: %s", exc)
        return jsonify(
            {"ok": False, "error": "Ödeme silinirken bir hata oluştu."}
        ), 500

# ======================
#  DUYURULAR
# ======================

@admin_bp.route("/announcements", methods=["GET", "POST"])
@admin_required
def manage_announcements():
    """Duyuru oluşturma ve listeleme."""
    admin_user = _get_current_admin()

    if request.method == "POST":
        title = (request.form.get("title") or "").strip()
        content = (request.form.get("content") or "").strip()
        target = (request.form.get("target") or "all").strip()

        if not title or not content:
            flash("Başlık ve içerik zorunludur.", "error")
        else:
            try:
                ann = Announcement(
                    title=title,
                    content=content,
                    target=target if target in ("all", "admins", "residents") else "all",
                    created_at=datetime.utcnow(),
                    created_by=admin_user.id if admin_user else None,
                )
                db.session.add(ann)
                db.session.commit()
                flash("Duyuru başarıyla yayınlandı.", "success")
            except SQLAlchemyError as exc:
                db.session.rollback()
                current_app.logger.exception("Duyuru eklenemedi: %s", exc)
                flash("Duyuru kaydedilirken bir hata oluştu.", "error")

    announcements = []
    try:
        announcements = (
            db.session.query(Announcement, User)
            .outerjoin(User, Announcement.created_by == User.id)
            .order_by(Announcement.created_at.desc())
            .limit(100)
            .all()
        )
    except SQLAlchemyError as exc:
        current_app.logger.exception("Duyuru listesi alınamadı: %s", exc)
        flash("Duyuru listesi alınırken bir hata oluştu.", "error")

    today = date.today()  # 🔹 bugünün tarihi

    return render_template(
        "admin/duyurular.html",
        announcements=announcements,
        today=today,  # 🔹 template’e gönder
    )


# ======================
#  TALEPLER (SAKİN TALEPLERİ)
# ======================

@admin_bp.route("/tickets", methods=["GET"])
@admin_required
def manage_tickets():
    """
    Sakinlerin açtığı tüm talepleri admin tarafında listeler.
    ?status=open / in_progress / closed / all
    """
    status_filter = (request.args.get("status") or "all").strip()

    tickets = []
    try:
        q = (
            db.session.query(Ticket, Apartment, User)
            .outerjoin(Apartment, Ticket.apartment_id == Apartment.id)
            .outerjoin(User, Ticket.user_id == User.id)
        )

        if status_filter in ("open", "in_progress", "closed"):
            q = q.filter(Ticket.status == status_filter)

        tickets = q.order_by(Ticket.created_at.desc()).all()

    except SQLAlchemyError as exc:
        current_app.logger.exception("Talep listesi alınamadı: %s", exc)
        flash("Talep listesi alınırken bir hata oluştu.", "error")

    return render_template(
        "admin/talepler.html",
        tickets=tickets,
        status_filter=status_filter,
    )


@admin_bp.route("/tickets/<int:ticket_id>/status", methods=["POST"])
@admin_required
def update_ticket_status(ticket_id: int):
    """Bir talebin durumunu değiştirir."""
    new_status = (request.form.get("status") or "").strip()

    if new_status not in ("open", "in_progress", "closed"):
        flash("Geçersiz talep durumu.", "error")
        return redirect(url_for("admin.manage_tickets"))

    try:
        ticket = Ticket.query.get(ticket_id)
        if not ticket:
            flash("Talep bulunamadı.", "error")
            return redirect(url_for("admin.manage_tickets"))

        ticket.status = new_status
        if new_status == "closed":
            ticket.closed_at = datetime.utcnow()
        else:
            ticket.closed_at = None

        ticket.updated_at = datetime.utcnow()
        db.session.commit()
        flash("Talep durumu güncellendi.", "success")

    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Talep durumu güncellenemedi: %s", exc)
        flash("Talep durumu güncellenirken bir hata oluştu.", "error")

    status_filter = request.args.get("status") or "all"
    return redirect(url_for("admin.manage_tickets", status=status_filter))


# ======================
#  AYARLAR (DEMO)
# ======================

class _SettingsDemo:
    """Gerçek DB ayar tablosu yok; şimdilik demo olarak kullanıyoruz."""

    def __init__(self):
        self.site_name = "Örnek Apartman Sitesi"
        self.address = "Adres bilgisi henüz tanımlanmadı."
        self.manager_name = "Site Yöneticisi"
        self.manager_phone = "+90 555 000 00 00"
        self.manager_email = "yonetici@example.com"


@admin_bp.route("/settings", methods=["GET", "POST"])
@admin_required
def settings():
    """Sistem ayarları (varsayılan aidat tutarı vb.)."""

    try:
        settings_obj = SystemSetting.get_singleton()
    except SQLAlchemyError as exc:
        current_app.logger.exception("Ayarlar alınamadı: %s", exc)
        flash("Ayarlar okunurken bir hata oluştu.", "error")
        settings_obj = None

    if request.method == "POST":
        default_dues = (request.form.get("default_monthly_dues_amount") or "").strip()

        try:
            if settings_obj is None:
                settings_obj = SystemSetting.get_singleton()

            if default_dues:
                settings_obj.default_monthly_dues_amount = Decimal(
                    default_dues.replace(",", ".")
                )

            db.session.commit()
            flash("Ayarlar başarıyla kaydedildi.", "success")

        except (ValueError, SQLAlchemyError) as exc:
            db.session.rollback()
            current_app.logger.exception("Ayarlar kaydedilemedi: %s", exc)
            flash("Ayarlar kaydedilirken bir hata oluştu.", "error")

    return render_template("admin/ayarlar.html", settings=settings_obj)

