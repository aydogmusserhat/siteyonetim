from functools import wraps
from datetime import datetime, date
from decimal import Decimal
from collections import defaultdict
from models.settings_model import SystemSetting
import io
import os
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
    send_file,
)
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import func, or_, and_
from models import db
from models.user_model import User
from models.apartment_model import Apartment
from models.bill_model import Bill
from models.payment_model import Payment
from models.announcement_model import Announcement
from models.ticket_model import Ticket
from models.site_model import Site  # 🔸 site modeli
from audit_logging import log_action
from typing import Optional

from models.need_item_model import NeedItem

import json
from audit_logging import AuditLog  # audit_logging.py içindeki model


admin_bp = Blueprint("admin", __name__, url_prefix="/admin")



# ==================================================
#  YETKİ KONTROL
# ==================================================


def admin_required(view_func):
    """
    Sadece 'admin' veya 'super_admin' rolündeki kullanıcıların erişmesini sağlayan decorator.
    Giriş yoksa /login, rol yanlışsa index'e yönlendirir.
    """

    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        user_id = session.get("user_id")
        role = session.get("user_role")

        if not user_id:
            flash("Devam etmek için lütfen giriş yapın.", "info")
            return redirect(url_for("auth.login"))

        # Admin paneline super_admin da girebilsin:
        if role not in ("admin", "super_admin"):
            flash("Bu alana sadece yönetici kullanıcılar erişebilir.", "error")
            return redirect(url_for("index"))

        return view_func(*args, **kwargs)

    return wrapped_view

# ==================================================superadmin log ekranı ===============================
def _require_super_admin():
    """Sadece super_admin erişebilsin. Değilse 403/redirect."""
    admin_user = _get_current_admin()
    if not admin_user or admin_user.role != "super_admin":
        return False
    return True

@admin_bp.route("/audit-logs", methods=["GET"])
@admin_required
def audit_logs():
    """Denetim izleri ekranı (sadece super_admin)."""

    if not _require_super_admin():
        flash("Bu sayfayı sadece Süper Admin görüntüleyebilir.", "error")
        return redirect(url_for("admin.dashboard"))

    # Filtre parametreleri
    page = request.args.get("page", 1, type=int) or 1
    if page < 1:
        page = 1

    per_page = 50

    action = (request.args.get("action") or "").strip()
    entity_type = (request.args.get("entity_type") or "").strip()
    status = (request.args.get("status") or "").strip()
    site_id = request.args.get("site_id", type=int)
    user_id = request.args.get("user_id", type=int)
    q = (request.args.get("q") or "").strip()  # description / ip / entity_id araması

    try:
        query = AuditLog.query

        if action:
            query = query.filter(AuditLog.action == action)
        if entity_type:
            query = query.filter(AuditLog.entity_type == entity_type)
        if status:
            query = query.filter(AuditLog.status == status)
        if site_id:
            query = query.filter(AuditLog.site_id == site_id)
        if user_id:
            query = query.filter(AuditLog.user_id == user_id)

        if q:
            # Basit arama: description/ip/entity_id
            like = f"%{q}%"
            # entity_id integer olduğu için cast etmek yerine stringle karşılaştırma yaklaşımı:
            # SQLite uyumu için func.cast kullanılabilir; basit tutuyoruz:
            query = query.filter(
                (AuditLog.description.ilike(like)) |
                (AuditLog.ip_address.ilike(like)) |
                (AuditLog.entity_type.ilike(like))
            )

        total = query.count()
        logs = (
            query
            .order_by(AuditLog.created_at.desc())
            .offset((page - 1) * per_page)
            .limit(per_page)
            .all()
        )

        pages = (total + per_page - 1) // per_page if total > 0 else 1

        # Dropdown seçenekleri
        distinct_pairs = db.session.query(AuditLog.entity_type, AuditLog.action).distinct().all()
        all_entity_types = sorted({et for et, act in distinct_pairs if et})
        all_actions = sorted({act for et, act in distinct_pairs if act})

        all_sites = Site.query.order_by(Site.name.asc()).all()
        all_users = User.query.order_by(User.name.asc()).all()

        return render_template(
            "admin/audit_logs.html",
            logs=logs,
            page=page,
            pages=pages,
            total=total,
            filters={
                "action": action,
                "entity_type": entity_type,
                "status": status,
                "site_id": site_id,
                "user_id": user_id,
                "q": q,
            },
            all_actions=all_actions,
            all_entity_types=all_entity_types,
            all_sites=all_sites,
            all_users=all_users,
        )

    except SQLAlchemyError as exc:
        current_app.logger.exception("Audit log listesi alınamadı: %s", exc)
        flash("Audit log listesi alınırken hata oluştu.", "error")
        return redirect(url_for("admin.dashboard"))

@admin_bp.route("/audit-logs/<int:log_id>", methods=["GET"])
@admin_required
def audit_log_detail(log_id: int):
    """Audit log detay ekranı (sadece super_admin)."""

    if not _require_super_admin():
        flash("Bu sayfayı sadece Süper Admin görüntüleyebilir.", "error")
        return redirect(url_for("admin.dashboard"))

    try:
        log = AuditLog.query.get(log_id)
        if not log:
            flash("Audit kaydı bulunamadı.", "error")
            return redirect(url_for("admin.audit_logs"))

        # JSON alanlarını template tarafında rahat göstermek için parse et
        old_data = None
        new_data = None
        try:
            old_data = json.loads(log.old_values) if log.old_values else None
        except Exception:
            old_data = {"_raw": log.old_values}

        try:
            new_data = json.loads(log.new_values) if log.new_values else None
        except Exception:
            new_data = {"_raw": log.new_values}

        # İlgili kullanıcı / site isimlerini göstermek için (relationship varsa zaten geliyor)
        return render_template(
            "admin/audit_log_detail.html",
            log=log,
            old_data=old_data,
            new_data=new_data,
        )

    except SQLAlchemyError as exc:
        current_app.logger.exception("Audit log detayı alınamadı: %s", exc)
        flash("Audit log detayı alınırken hata oluştu.", "error")
        return redirect(url_for("admin.audit_logs"))


def super_admin_required(view_func):
    """
    Sadece 'super_admin' rolündeki kullanıcılar için decorator.
    (Site yönetimi ekranı gibi özel alanlar için)
    """

    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        user_id = session.get("user_id")
        role = session.get("user_role")

        if not user_id:
            flash("Devam etmek için lütfen giriş yapın.", "info")
            return redirect(url_for("auth.login"))

        if role != "super_admin":
            flash("Bu alana sadece süper yönetici erişebilir.", "error")
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
#  SETTINGS / SITE NAME
# ======================


def get_default_monthly_dues_amount(site_id: Optional[int] = None) -> Decimal:
    """
    Site bazlı aylık aidat tutarını Site tablosundan okur.
    site_id yoksa 500.00 döner.
    """
    fallback = Decimal("500.00")

    if not site_id:
        return fallback

    try:
        site = Site.query.get(site_id)
        val = getattr(site, "monthly_dues_amount", None) if site else None
        if val is not None:
            return Decimal(str(val))

    except SQLAlchemyError as exc:
        current_app.logger.exception("Site aidat tutarı okunamadı (site_id=%s): %s", site_id, exc)

    return fallback




#
# NOTE:
# A context processor named `inject_site_name` is defined later in this file.  The
# original code contained two separate definitions of the same function on the
# same blueprint, which caused the first one to be silently overridden by the
# second.  Maintaining a single context processor avoids confusion and makes
# the behaviour explicit.  The first definition has been removed; see below
# for the remaining implementation.


# ======================
#  SUPER ADMIN: SITE PANELİ
# ======================


@admin_bp.route("/sites", methods=["GET", "POST"])
@super_admin_required
def manage_sites():
    """
    Super admin paneli:
    - Site oluşturma (POST /admin/sites)
    - Sayfada:
        * Oluşturulan siteler listesi
        * Her sitenin atanmış adminleri
    Admin oluşturma POST'u ayrı route'tan alınır (create_site_admin).
    """
    # Yeni site oluşturma
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        description = (request.form.get("description") or "").strip()

        if not name:
            flash("Site adı boş bırakılamaz.", "error")
        else:
            try:
                existing = Site.query.filter_by(name=name).first()
                if existing:
                    flash("Bu isimde bir site zaten mevcut.", "error")
                else:
                    site = Site(name=name, description=description or None)
                    db.session.add(site)
                    db.session.commit()
                    flash("Site başarıyla oluşturuldu.", "success")
            except SQLAlchemyError as exc:
                db.session.rollback()
                current_app.logger.exception("Site oluşturulamadı: %s", exc)
                flash("Site kaydedilirken bir hata oluştu.", "error")

    # Listeleme
    sites = []
    site_admins_map = defaultdict(list)

    try:
        sites = Site.query.order_by(Site.name.asc()).all()

        if sites:
            admins = (
                User.query.filter_by(role="admin")
                .order_by(User.name.asc())
                .all()
            )
            for admin in admins:
                if admin.site_id:
                    site_admins_map[admin.site_id].append(admin)
    except SQLAlchemyError as exc:
        current_app.logger.exception("Site listesi alınamadı: %s", exc)
        flash("Site listesi alınırken bir hata oluştu.", "error")

    return render_template(
        "admin/sites.html",
        sites=sites,
        site_admins_map=site_admins_map,
    )

@admin_bp.route("/sites/<int:site_id>/switch", methods=["GET"])
@super_admin_required
def switch_active_site(site_id: int):
    """
    Super admin için: aktif siteyi değiştirir ve o sitenin dashboard'una gider.
    """
    from models.site_model import Site  # döngüyü önlemek için lokal import

    try:
        site = Site.query.get(site_id)
        if not site:
            flash("Site bulunamadı.", "error")
            return redirect(url_for("admin.manage_sites"))

        # 🔹 Aktif siteyi session'a yaz
        session["active_site_id"] = site.id
        session["active_site_name"] = site.name
        # Context processor'un kullandığı isim
        session["site_name"] = site.name

        flash(f"'{site.name}' sitesi için yönetim paneli açıldı.", "success")
        return redirect(url_for("admin.dashboard"))

    except SQLAlchemyError as exc:
        current_app.logger.exception("Aktif site değiştirilemedi: %s", exc)
        flash("Aktif site değiştirilirken bir hata oluştu.", "error")
        return redirect(url_for("admin.manage_sites"))


@admin_bp.route("/sites/create-admin", methods=["POST"])
@super_admin_required
def create_site_admin():
    """
    Super admin panelinden yeni bir admin kullanıcı oluşturur
    ve seçilen siteye bağlar.
    """
    name = (request.form.get("admin_name") or "").strip()
    email = (request.form.get("admin_email") or "").strip().lower()
    phone = (request.form.get("admin_phone") or "").strip()
    password = request.form.get("admin_password") or ""
    site_id = request.form.get("admin_site_id")

    if not name or not email or not password or not site_id:
        flash("İsim, e-posta, şifre ve site seçimi zorunludur.", "error")
        return redirect(url_for("admin.manage_sites"))

    try:
        # E-posta daha önce kullanılmış mı?
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Bu e-posta ile kayıtlı bir kullanıcı zaten var.", "error")
            return redirect(url_for("admin.manage_sites"))

        site = Site.query.get(int(site_id))
        if not site:
            flash("Seçilen site bulunamadı.", "error")
            return redirect(url_for("admin.manage_sites"))

        new_admin = User(
            name=name,
            email=email,
            phone=phone,
            role="admin",
            site_id=site.id,
            is_active=True,
        )
        new_admin.set_password(password)

        db.session.add(new_admin)
        db.session.commit()

        flash(f"{name} kullanıcısı {site.name} için admin olarak oluşturuldu.", "success")

    except (ValueError, SQLAlchemyError) as exc:
        db.session.rollback()
        current_app.logger.exception("Yeni admin oluşturulamadı: %s", exc)
        flash("Admin oluşturulurken bir hata oluştu.", "error")

    return redirect(url_for("admin.manage_sites"))

@admin_bp.route("/sites/admins/<int:admin_id>/delete", methods=["POST"])
@super_admin_required
def delete_site_admin(admin_id: int):
    """
    Super admin tarafından oluşturulan admin kullanıcısını
    sistemden tamamen siler.
    """

    try:
        admin_user = User.query.get(admin_id)

        if not admin_user:
            flash("Silinecek kullanıcı bulunamadı.", "error")
            return redirect(url_for("admin.manage_sites"))

        # Sadece admin rolündekiler silinsin
        if admin_user.role != "admin":
            flash("Sadece admin kullanıcılar silinebilir.", "error")
            return redirect(url_for("admin.manage_sites"))

        # Kendi hesabını silmesin
        if session.get("user_id") == admin_user.id:
            flash("Kendi hesabınızı silemezsiniz.", "error")
            return redirect(url_for("admin.manage_sites"))

        # Eğer site eşleşme alanı varsa temizle
        # örn: admin_user.site_id
        admin_user.site_id = None

        # TAMAMEN SİL
        db.session.delete(admin_user)
        db.session.commit()

        flash("Admin kullanıcı sistemden tamamen silindi.", "success")

    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Admin silinemedi: %s", exc)
        flash("Admin silinirken hata oluştu.", "error")

    return redirect(url_for("admin.manage_sites"))


@admin_bp.route("/sites/<int:site_id>/assign-admin", methods=["POST"])
@super_admin_required
def assign_site_admin(site_id: int):
    """
    Bir kullanıcıyı belirli bir site için admin yapar.
    - Kullanıcının rolünü 'admin' yapar
    - Kullanıcının site_id alanını günceller
    """
    user_id = request.form.get("user_id")
    if not user_id:
        flash("Bir kullanıcı seçmelisiniz.", "error")
        return redirect(url_for("admin.manage_sites"))

    try:
        site = Site.query.get(site_id)
        if not site:
            flash("Site bulunamadı.", "error")
            return redirect(url_for("admin.manage_sites"))

        user = User.query.get(int(user_id))
        if not user:
            flash("Kullanıcı bulunamadı.", "error")
            return redirect(url_for("admin.manage_sites"))

        if user.role == "super_admin":
            flash("Süper admin için site ataması yapmaya gerek yok.", "info")
            return redirect(url_for("admin.manage_sites"))

        user.role = "admin"
        user.site_id = site.id
        db.session.commit()
        flash(f"{user.name} artık '{site.name}' sitesinin yöneticisi.", "success")

    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Site admin atanamadı: %s", exc)
        flash("Admin ataması yapılırken bir hata oluştu.", "error")

    return redirect(url_for("admin.manage_sites"))


@admin_bp.route("/sites/<int:site_id>/delete", methods=["POST"])
@super_admin_required
def delete_site(site_id: int):
    """
    Basit silme: Sadece o siteye bağlı admin yoksa siler.
    (İleride apartman/bill/payment site_id ile bağlandığında ekstra kontroller ekleriz.)
    """
    try:
        site = Site.query.get(site_id)
        if not site:
            flash("Site bulunamadı.", "error")
            return redirect(url_for("admin.manage_sites"))

        # Bu siteye bağlı admin var mı?
        linked_admins = User.query.filter_by(site_id=site.id, role="admin").count()
        if linked_admins > 0:
            flash("Bu siteye atanmış adminler varken silemezsiniz.", "error")
            return redirect(url_for("admin.manage_sites"))

        db.session.delete(site)
        db.session.commit()
        flash("Site başarıyla silindi.", "success")

    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Site silinemedi: %s", exc)
        flash("Site silinirken bir hata oluştu.", "error")

    return redirect(url_for("admin.manage_sites"))

# ======================
#  SETTINGS / SITE NAME
# ======================

def get_site_display_name() -> str:
    """
    Sistem ayarlarından (SystemSetting) site / apartman adını okur.
    Bulamazsa güvenli bir varsayılan değer döner.
    """
    default_name = "Site / Apartman"
    try:
        settings = SystemSetting.get_singleton()
        if settings and getattr(settings, "site_name", None):
            name = (settings.site_name or "").strip()
            if name:
                return name
    except SQLAlchemyError as exc:
        current_app.logger.exception("Site adı okunamadı: %s", exc)

    return default_name

@admin_bp.app_context_processor
def inject_site_name():
    """
    Tüm admin template'lerine current_site_name verir.
    Önce session'dan okur, yoksa DB'den çeker ve session'a yazar.
    """
    name = session.get("site_name")

    if not name:
        name = get_site_display_name()  # DB'den oku (SystemSetting)
        session["site_name"] = name

    return {"current_site_name": name}


def get_current_site():
    """
    Session'dan aktif siteyi döner.
    Eğer session'da yoksa, admin kullanıcının site_id bilgisini kullanır.
    """
    from models.site_model import Site  # local import, döngüyü önlemek için

    site_id = session.get("active_site_id")
    if site_id:
        return Site.query.get(site_id)

    admin_user = _get_current_admin()
    if admin_user and admin_user.site_id:
        site = Site.query.get(admin_user.site_id)
        if site:
            session["active_site_id"] = site.id
            session["active_site_name"] = site.name
        return site

    return None

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
# ==============================================================================
# ======================
#  DASHBOARD
# ======================
@admin_bp.route("/dashboard")
@admin_required
def dashboard():
    """Genel yönetim paneli özeti + son 12 ay aylık özet.

    - Normal admin: sadece bağlı olduğu / seçtiği site
    - Süper admin:
        * Aktif site seçmişse -> o site
        * Seçmemişse         -> tüm siteler (global özet)
    """

    admin_user = _get_current_admin()
    if not admin_user:
        flash("Kullanıcı bulunamadı. Lütfen tekrar giriş yapın.", "error")
        return redirect(url_for("auth.logout"))

    from models.site_model import Site  # döngü olmasın diye lokal import

    # Session'dan veya kullanıcının site_id'sinden oku
    site_id = session.get("active_site_id") or (admin_user.site_id if admin_user.site_id else None)

    is_super = (admin_user.role == "super_admin")
    # Süper admin ve hiçbir site seçili değilse -> GLOBAL MOD
    global_mode = is_super and not site_id

    # Global modda üstte görünen isim için yardımcı label
    if global_mode:
        session["active_site_name"] = "Tüm Siteler (Genel)"
    else:
        # Site bazlı moddaysak, aktif site adını garantiye al
        if site_id:
            try:
                site = Site.query.get(site_id)
                if site:
                    session["active_site_id"] = site.id
                    session["active_site_name"] = site.name
            except SQLAlchemyError:
                pass
        else:
            # Normal admin ve site yoksa engelle
            flash("Bu paneli kullanabilmek için bir siteye atanmış olmanız gerekiyor.", "error")
            return redirect(url_for("index"))

    stats = {
        "total_apartments": 0,
        "total_users": 0,
        "resident_users": 0,
        "admin_users": 0,
        "total_bills": 0,
        # Bu ay beklenen gelir - bu ay ödenen
        "total_open_amount": Decimal("0.00"),
        # Bu ay yapılan ödemelerin toplamı
        "total_paid_amount": Decimal("0.00"),
        # Bu ay oluşturulan borçların toplamı
        "expected_income_this_month": Decimal("0.00"),
        "open_tickets": 0,
        "carryover_amount": Decimal("0.00"),  # önceki aylardan devir eden (kalan) tutar
    }

    today = date.today()

    # =========================
    #  GENEL SAYILAR
    # =========================
    try:
        # Daireler
        q_apts = Apartment.query
        if not global_mode:
            q_apts = q_apts.filter_by(site_id=site_id)
        stats["total_apartments"] = q_apts.count()

        # Kullanıcılar
        q_users = User.query
        if not global_mode:
            q_users = q_users.filter_by(site_id=site_id)
        stats["total_users"] = q_users.count()

        q_res = q_users.filter_by(role="resident") if global_mode else User.query.filter_by(site_id=site_id, role="resident")
        q_admins = q_users.filter_by(role="admin") if global_mode else User.query.filter_by(site_id=site_id, role="admin")
        stats["resident_users"] = q_res.count()
        stats["admin_users"] = q_admins.count()
    except SQLAlchemyError as exc:
        current_app.logger.exception("Dashboard kullanıcı istatistikleri alınamadı: %s", exc)

    # =========================
    #  BORÇ / ÖDEME ÖZETLERİ (bu ay)
    # =========================
    try:
        q_bills_all = Bill.query
        if not global_mode:
            q_bills_all = q_bills_all.filter(Bill.site_id == site_id)
        stats["total_bills"] = q_bills_all.count()

        # Bu ayın başlangıcı ve bir sonraki ayın başlangıcı
        month_start = date(today.year, today.month, 1)
        if today.month == 12:
            month_end = date(today.year + 1, 1, 1)
        else:
            month_end = date(today.year, today.month + 1, 1)

        # ===== SUBQUERY: HER BILL İÇİN TOPLAM ÖDENEN =====
        pay_sum_subq = (
            db.session.query(
                Payment.bill_id.label("bill_id"),
                func.coalesce(func.sum(Payment.amount), 0).label("paid_sum"),
            )
            .group_by(Payment.bill_id)
            .subquery()
        )

        # ==========================================================
        # DEVİR EDEN TUTAR (önceki aylardan kalan NET bakiye)
        # - due_date varsa due_date < month_start
        # - due_date yoksa created_at < month_start
        # - (Bill.amount - bill'e bağlı ödemeler) toplamı
        # ==========================================================
        from sqlalchemy import and_, or_

        q_carry = (
            db.session.query(
                func.coalesce(
                    func.sum(
                        Bill.amount - func.coalesce(pay_sum_subq.c.paid_sum, 0)
                    ),
                    0,
                )
            )
            .outerjoin(pay_sum_subq, pay_sum_subq.c.bill_id == Bill.id)
            .filter(Bill.status.in_(["open", "partial"]))
        )

        if not global_mode:
            q_carry = q_carry.filter(Bill.site_id == site_id)

        q_carry = q_carry.filter(
            or_(
                and_(Bill.due_date.isnot(None), Bill.due_date < month_start),
                and_(Bill.due_date.is_(None), Bill.created_at < month_start),
            )
        )

        carry_sum = q_carry.scalar() or 0
        stats["carryover_amount"] = Decimal(str(carry_sum))

        # ==========================================================
        # Bu ay beklenen gelir (Vade ayına göre)
        # - due_date varsa due_date ayı
        # - due_date yoksa created_at ayı
        # ==========================================================
        q_billed = db.session.query(func.coalesce(func.sum(Bill.amount), 0))
        if not global_mode:
            q_billed = q_billed.filter(Bill.site_id == site_id)

        q_billed = q_billed.filter(
            or_(
                and_(Bill.due_date.isnot(None), Bill.due_date >= month_start, Bill.due_date < month_end),
                and_(Bill.due_date.is_(None), Bill.created_at >= month_start, Bill.created_at < month_end),
            )
        )
        billed_sum = q_billed.scalar() or 0
        stats["expected_income_this_month"] = Decimal(str(billed_sum))

        # Bu ay yapılan ödemeler (nakit akışı: ödeme tarihi bu ay olanlar)
        q_paid = db.session.query(func.coalesce(func.sum(Payment.amount), 0))
        if not global_mode:
            q_paid = q_paid.filter(Payment.site_id == site_id)
        q_paid = q_paid.filter(
            Payment.payment_date >= month_start,
            Payment.payment_date < month_end,
        )
        paid_sum = q_paid.scalar() or 0
        stats["total_paid_amount"] = Decimal(str(paid_sum))

        # ==========================================================
        # AÇıK / kısmı borç (NET) 
        # = Her borçun (Bill.amount - o borca ait ödemeler) toplamı
        # Pozitif: borç, Negatif: fazla ödeme (kredit)
        # ==========================================================
        q_open_net = (
            db.session.query(
                func.coalesce(
                    func.sum(
                        Bill.amount - func.coalesce(pay_sum_subq.c.paid_sum, 0)
                    ),
                    0,
                )
            )
            .outerjoin(pay_sum_subq, pay_sum_subq.c.bill_id == Bill.id)
            .filter(Bill.status.in_(["open", "partial"]))
        )

        if not global_mode:
            q_open_net = q_open_net.filter(Bill.site_id == site_id)

        open_net_sum = q_open_net.scalar() or 0
        stats["total_open_amount"] = Decimal(str(open_net_sum))

    except SQLAlchemyError as exc:
        current_app.logger.exception("Dashboard borç/ödeme istatistikleri alınamadı: %s", exc)

    # =========================
    #  TALEP SAYISI
    # =========================
    try:
        q_tickets = Ticket.query
        if not global_mode:
            q_tickets = q_tickets.filter(Ticket.site_id == site_id)
        q_tickets = q_tickets.filter(Ticket.status.in_(["open", "in_progress"]))
        stats["open_tickets"] = q_tickets.count()
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
        q_rb = db.session.query(Bill, Apartment).outerjoin(
            Apartment, Bill.apartment_id == Apartment.id
        )
        if not global_mode:
            q_rb = q_rb.filter(Bill.site_id == site_id)
        recent_bills = (
            q_rb.order_by(Bill.created_at.desc()).limit(5).all()
        )
    except SQLAlchemyError:
        pass

    # Son ödemeler
    try:
        q_rp = (
            db.session.query(Payment, Apartment, User)
            .outerjoin(Apartment, Payment.apartment_id == Apartment.id)
            .outerjoin(User, Payment.user_id == User.id)
        )
        if not global_mode:
            q_rp = q_rp.filter(Payment.site_id == site_id)
        recent_payments = (
            q_rp.order_by(Payment.payment_date.desc()).limit(5).all()
        )
    except SQLAlchemyError:
        pass

    # Son talepler
    try:
        q_rt = (
            db.session.query(Ticket, Apartment, User)
            .outerjoin(Apartment, Ticket.apartment_id == Apartment.id)
            .outerjoin(User, Ticket.user_id == User.id)
        )
        if not global_mode:
            q_rt = q_rt.filter(Ticket.site_id == site_id)
        recent_tickets = (
            q_rt.order_by(Ticket.created_at.desc()).limit(5).all()
        )
    except SQLAlchemyError:
        pass

    # Son duyurular
    try:
        q_ra = db.session.query(Announcement, User).outerjoin(
            User, Announcement.created_by == User.id
        )
        if not global_mode:
            q_ra = q_ra.filter(Announcement.site_id == site_id)
        recent_announcements = (
            q_ra.order_by(Announcement.created_at.desc()).limit(5).all()
        )
    except SQLAlchemyError:
        pass

    # =========================
    #  SON 12 AYLIK ÖZET
    # =========================
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

    def _shift_month(year: int, month: int, delta: int):
        """year-month değerini delta ay kadar geri/ileri kaydırır."""
        total = year * 12 + (month - 1) + delta
        new_year = total // 12
        new_month = total % 12 + 1
        return new_year, new_month

    monthly_overview = []
    try:
        cur_y = today.year
        cur_m = today.month

        for back in range(11, -1, -1):
            y, m = _shift_month(cur_y, cur_m, -back)
            month_start = date(y, m, 1)
            if m == 12:
                month_end = date(y + 1, 1, 1)
            else:
                month_end = date(y, m + 1, 1)

            # Faturalar (Vade tarihine göre; due_date NULL ise created_at fallback)
            q_mb = db.session.query(func.coalesce(func.sum(Bill.amount), 0))
            if not global_mode:
                q_mb = q_mb.filter(Bill.site_id == site_id)

            q_mb = q_mb.filter(
                or_(
                    and_(Bill.due_date.isnot(None), Bill.due_date >= month_start, Bill.due_date < month_end),
                    and_(Bill.due_date.is_(None), Bill.created_at >= month_start, Bill.created_at < month_end),
                )
            )
            month_bills_sum = q_mb.scalar()

            # Ödemeler (Muhasebe doğru olsun: ödeme, bağlı olduğu borcun vade ayına yazılsın)
            q_mp = (
                db.session.query(func.coalesce(func.sum(Payment.amount), 0))
                .join(Bill, Payment.bill_id == Bill.id)  # sadece bir borca bağlı ödemeler
            )

            if not global_mode:
                # burada Bill.site_id yeterli (istersen Payment.site_id filtresi de ekleyebilirsin)
                q_mp = q_mp.filter(Bill.site_id == site_id)

            q_mp = q_mp.filter(
                or_(
                    and_(Bill.due_date.isnot(None), Bill.due_date >= month_start, Bill.due_date < month_end),
                    and_(Bill.due_date.is_(None), Bill.created_at >= month_start, Bill.created_at < month_end),
                )
            )

            month_payments_sum = q_mp.scalar()


            billed = Decimal(month_bills_sum or 0)
            paid = Decimal(month_payments_sum or 0)
            delta = paid - billed

            monthly_overview.append(
                {
                    "year": y,
                    "month": m,
                    "label": f"{MONTH_LABELS_TR[m]} {y}",
                    "total_billed": billed,
                    "total_paid": paid,
                    "total_open": billed - paid if billed - paid > 0 else Decimal("0.00"),
                    "delta": delta,
                }
            )
    except SQLAlchemyError as exc:
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
        monthly_overview=monthly_overview,
        today=today,
        global_mode=global_mode,
    )

# ======================
#  DAİRELER
# ======================
@admin_bp.route("/apartments", methods=["GET", "POST"])
@admin_required
def manage_apartments():
    """Daire listesi ve yeni daire ekleme (site bazlı)."""

    admin_user = _get_current_admin()
    site_id = session.get("active_site_id") or (admin_user.site_id if admin_user else None)
    if not site_id:
        flash("Bu sayfayı kullanabilmek için bir siteye atanmış olmanız gerekiyor.", "error")
        return redirect(url_for("index"))

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
                # Aynı blok+kat+no sadece AYNI SİTE içinde kontrol ediliyor
                existing_apt = (
                    Apartment.query
                    .filter_by(site_id=site_id, block=block, floor=floor, number=number)
                    .first()
                )
                if existing_apt:
                    flash(
                        f"{block} blok, {floor}. kat, {number} no için bu sitede zaten bir daire kaydı var.",
                        "error",
                    )
                else:
                    apt = Apartment(
                        site_id=site_id,
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
        apartments = (
            Apartment.query
            .filter_by(site_id=site_id)
            .order_by(
                Apartment.block.asc(),
                Apartment.floor.asc(),
                Apartment.number.asc(),
            )
            .all()
        )
    except SQLAlchemyError as exc:
        current_app.logger.exception("Daire listesi alınamadı: %s", exc)
        flash("Daire listesi alınırken bir hata oluştu.", "error")

    return render_template("admin/daireler.html", apartments=apartments)


@admin_bp.route("/apartments/<int:apartment_id>/update", methods=["POST"])
@admin_required
def update_apartment(apartment_id: int):
    """Tek bir dairenin bilgilerini günceller (site bazlı)."""

    admin_user = _get_current_admin()
    site_id = session.get("active_site_id") or (admin_user.site_id if admin_user else None)
    if not site_id:
        flash("Bu işlemi yapabilmek için bir siteye atanmış olmanız gerekiyor.", "error")
        return redirect(url_for("admin.manage_apartments"))

    try:
        apt = Apartment.query.get(apartment_id)
        if not apt:
            flash("Daire bulunamadı.", "error")
            return redirect(url_for("admin.manage_apartments"))

        if apt.site_id != site_id:
            flash("Bu daire, yetkili olduğunuz siteye ait değil.", "error")
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
    """Bir daireyi siler (sadece kendi sitesi ve ilişkisi yoksa)."""

    admin_user = _get_current_admin()
    site_id = session.get("active_site_id") or (admin_user.site_id if admin_user else None)
    if not site_id:
        flash("Bu işlemi yapabilmek için bir siteye atanmış olmanız gerekiyor.", "error")
        return redirect(url_for("admin.manage_apartments"))

    try:
        apt = Apartment.query.get(apartment_id)
        if not apt:
            flash("Daire bulunamadı.", "error")
            return redirect(url_for("admin.manage_apartments"))

        if apt.site_id != site_id:
            flash("Bu daire, yetkili olduğunuz siteye ait değil.", "error")
            return redirect(url_for("admin.manage_apartments"))

        # İlişkili kullanıcı, borç veya ödeme varsa silme
        has_users = User.query.filter_by(apartment_id=apt.id).count() > 0
        has_bills = Bill.query.filter_by(apartment_id=apt.id).count() > 0
        has_payments = Payment.query.filter_by(apartment_id=apt.id).count() > 0

        if has_users or has_bills or has_payments:
            flash(
                "Bu daireyle ilişkili kullanıcı, borç veya ödeme kaydı olduğu için silinemez.",
                "error",
            )
            return redirect(url_for("admin.manage_apartments"))

        db.session.delete(apt)
        db.session.commit()
        flash("Daire başarıyla silindi.", "success")

    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Daire silinemedi: %s", exc)
        flash("Daire silinirken bir hata oluştu.", "error")

    return redirect(url_for("admin.manage_apartments"))



# ======================
#  KULLANICILAR
# ======================
@admin_bp.route("/users", methods=["GET", "POST"], endpoint="kullanicilar")
@admin_required
def manage_users():

    """Kullanıcı listesi ve yeni kullanıcı ekleme (site bazlı)."""

    admin_user = _get_current_admin()
    site_id = session.get("active_site_id") or (admin_user.site_id if admin_user else None)
    if not site_id:
        flash("Bu sayfayı kullanabilmek için bir siteye atanmış olmanız gerekiyor.", "error")
        return redirect(url_for("index"))

    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        phone = (request.form.get("phone") or "").strip()
        role = (request.form.get("role") or "resident").strip()
        apartment_id = request.form.get("apartment_id") or None
        password = request.form.get("password") or ""

        if not name or not email or not password:
            flash("Ad, e-posta ve şifre alanları zorunludur.", "error")

        elif role == "resident" and not apartment_id:
            flash("Sakin rolü için bağlı daire seçimi zorunludur.", "error")

        else:
            try:

                existing = User.query.filter_by(email=email).first()
                if existing:
                    flash("Bu e-posta adresi ile zaten bir kullanıcı mevcut.", "error")
                else:
                    apt_obj = None
                    if apartment_id:
                        apt_obj = Apartment.query.get(int(apartment_id))
                        if not apt_obj or apt_obj.site_id != site_id:
                            flash("Seçilen daire bu siteye ait değil.", "error")
                            apt_obj = None

                    user = User(
                        site_id=site_id,
                        name=name,
                        email=email,
                        phone=phone or None,
                        role=role,
                        apartment_id=apt_obj.id if apt_obj else None,
                        is_active=True,
                    )
                    user.set_password(password)

                    db.session.add(user)
                    db.session.commit()
                    flash("Kullanıcı başarıyla eklendi.", "success")

            except SQLAlchemyError as exc:
                db.session.rollback()
                current_app.logger.exception("Kullanıcı eklenemedi: %s", exc)
                flash("Kullanıcı kaydedilirken bir hata oluştu.", "error")

    users = []
    apartments = []

    try:
        users = (
            User.query
            .filter_by(site_id=site_id)
            .filter(User.is_deleted.is_(False))
            .order_by(User.role.desc(), User.name.asc())
            .all()
        )


        apartments = (
            Apartment.query
            .filter_by(site_id=site_id)
            .order_by(
                Apartment.block.asc(),
                Apartment.floor.asc(),
                Apartment.number.asc(),
            )
            .all()
        )

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
    """Kullanıcıyı aktif / pasif yapar (sadece kendi sitesinde)."""

    admin_user = _get_current_admin()
    site_id = session.get("active_site_id") or (admin_user.site_id if admin_user else None)
    if not site_id:
        flash("Bu işlemi yapabilmek için bir siteye atanmış olmanız gerekiyor.", "error")
        return redirect(url_for("admin.manage_users"))

    try:
        user = User.query.get(user_id)
        if not user:
            flash("Kullanıcı bulunamadı.", "error")
            return redirect(url_for("admin.manage_users"))

        if user.site_id != site_id:
            flash("Bu kullanıcı, yetkili olduğunuz siteye ait değil.", "error")
            return redirect(url_for("admin.manage_users"))

        user.is_active = not bool(user.is_active)
        db.session.commit()
        flash("Kullanıcı durumu güncellendi.", "success")

    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Kullanıcı durumu güncellenemedi: %s", exc)
        flash("Kullanıcı durumu güncellenirken bir hata oluştu.", "error")

    return redirect(url_for("admin.manage_users"))


# ======================
#  AİDATLAR / BORÇLAR
# ======================
@admin_bp.route("/bills", methods=["GET", "POST"])
@admin_required
def manage_bills():
    """Aidat / borç kayıtlarını yönetir (site bazlı)."""
    apartments = []
    bills = []
    apartment_summaries = []

    # --- Aktif site kontrolü ---
    admin_user = _get_current_admin()
    site_id = session.get("active_site_id") or (admin_user.site_id if admin_user else None)
    if not site_id:
        flash("Bu sayfayı kullanabilmek için bir siteye atanmış olmanız gerekiyor.", "error")
        return redirect(url_for("index"))

    # --- Listeleme parametreleri (filtre / sıralama / sayfalama) ---
    page = request.args.get("page", 1, type=int) or 1
    if page < 1:
        page = 1

    per_page = 20  # max 20 satır
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
                    # SADECE BU SİTENİN DAİRELERİ
                    target_apartments = (
                        Apartment.query
                        .filter_by(site_id=site_id)
                        .order_by(
                            Apartment.block.asc(),
                            Apartment.floor.asc(),
                            Apartment.number.asc(),
                        )
                        .all()
                    )
                else:
                    apt = Apartment.query.get(int(apartment_id))
                    # daire var mı ve bu siteye mi ait?
                    if not apt or apt.site_id != site_id:
                        target_apartments = []
                    else:
                        target_apartments = [apt]

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
                            site_id=site_id,          # 🔴 BU SİTEYE AİT
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
        # Daire listesi (soldaki form için) — sadece bu sitenin daireleri
        apartments = (
            Apartment.query
            .filter_by(site_id=site_id)
            .order_by(
                Apartment.block.asc(),
                Apartment.floor.asc(),
                Apartment.number.asc(),
            )
            .all()
        )

        # Detay borç listesi (filtre + sıralama + sayfalama)
        base_query = (
            db.session.query(Bill, Apartment)
            .outerjoin(Apartment, Bill.apartment_id == Apartment.id)
            .filter(Bill.site_id == site_id)   # 🔴 SADECE BU SİTENİN BORÇLARI
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


        # ------------------------------------------------------------
        # ✅ Sayfadaki her borç için "Ödenen" ve "Kalan" hesapla (tabloya yazdırmak için)
        # Not: Bill.status güncel olsa bile, liste tablosunda ödenen/kalanı anlık göstermek istiyoruz.
        # ------------------------------------------------------------
        bill_ids = [b.id for (b, _a) in bills if b and getattr(b, "id", None)]
        paid_map_by_bill = {}
        if bill_ids:
            paid_rows = (
                db.session.query(
                    Payment.bill_id,
                    func.coalesce(func.sum(Payment.amount), 0).label("paid_sum"),
                )
                .filter(Payment.site_id == site_id)
                .filter(Payment.bill_id.in_(bill_ids))
                .group_by(Payment.bill_id)
                .all()
            )
            for bill_id, paid_sum in paid_rows:
                paid_map_by_bill[int(bill_id)] = Decimal(str(paid_sum or 0))

        for b, _a in bills:
            if not b:
                continue
            paid_amt = paid_map_by_bill.get(int(b.id), Decimal("0.00"))
            bill_amt = Decimal(str(getattr(b, "amount", 0) or 0))
            rem_amt = bill_amt - paid_amt
            if rem_amt < 0:
                rem_amt = Decimal("0.00")
            # Template tarafında kolay kullanım için
            setattr(b, "_paid", paid_amt)
            setattr(b, "_remaining", rem_amt)
        # DAİRE + TÜR BAZINDA TOPLAMLAR (borç / ödenen)
        rows = (
            db.session.query(
                Apartment,
                Bill.type.label("bill_type"),
                func.coalesce(func.sum(Bill.amount), 0).label("total_debt"),
                func.coalesce(func.sum(Payment.amount), 0).label("total_paid"),
            )
            .outerjoin(Bill, Bill.apartment_id == Apartment.id)
            .outerjoin(Payment, Payment.bill_id == Bill.id)
            .filter(Apartment.site_id == site_id)   # 🔴 SADECE BU SİTENİN DAİRELERİ
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

    # HER DURUMDA BİR RESPONSE DÖNÜYOR
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


# ============================== Kullanıcı silme ==============================

from audit_logging import log_action
from models import db
from models.user_model import User

from flask import session, redirect, url_for, flash, request, abort

from sqlalchemy import or_

@admin_bp.post("/users/<int:user_id>/delete")
@admin_required
def delete_user(user_id: int):
    actor_id = session.get("user_id")
    if not actor_id:
        abort(401)

    actor = User.query.get(actor_id)
    target = User.query.get_or_404(user_id)

    # ❌ kendini silemez
    if actor.id == target.id:
        flash("Kendi hesabınızı silemezsiniz.", "error")
        return redirect(url_for("admin.manage_users"))

    # ❌ super_admin silinemez
    if target.role == "super_admin":
        flash("Süper yönetici silinemez.", "error")
        return redirect(url_for("admin.manage_users"))

    # ❌ admin sadece kendi sitesindekini işaretleyebilir
    if actor.role == "admin" and actor.site_id != target.site_id:
        abort(403)

    old_values = {
        "id": target.id,
        "name": target.name,
        "email": target.email,
        "role": target.role,
        "site_id": target.site_id,
        "apartment_id": target.apartment_id,
        "is_active": target.is_active,
        "is_deleted": getattr(target, "is_deleted", False),
    }

    # ✅ SOFT DELETE: pasifleştir + ekranda görünmesin
    target.is_active = False
    target.is_deleted = True

    db.session.commit()

    log_action(
        actor_id=actor.id,
        site_id=actor.site_id,
        action="DELETE",
        entity="User",
        entity_id=target.id,
        old_data=old_values,
        new_data={"is_active": target.is_active, "is_deleted": target.is_deleted},
    )

    flash("Kullanıcı silindi (pasifleştirildi).", "success")
    return redirect(url_for("admin.manage_users"))


# ==================================== borç silme için yardımcı========================
def _bill_audit_dict(bill: Bill) -> dict:
    """Borç (Bill) kaydını audit log için JSON-dostu sözlüğe çevir."""
    if not bill:
        return {}

    return {
        "id": getattr(bill, "id", None),
        "site_id": getattr(bill, "site_id", None),
        "apartment_id": getattr(bill, "apartment_id", None),
        "type": getattr(bill, "type", None),
        "amount": str(getattr(bill, "amount", "") or ""),
        "due_date": (
            getattr(bill, "due_date", None).strftime("%Y-%m-%d")
            if getattr(bill, "due_date", None)
            else None
        ),
        "status": getattr(bill, "status", None),
        "description": (
            getattr(bill, "description", None)
            if getattr(bill, "description", None)
            else getattr(bill, "desc", None)
        ),
        "created_at": (
            getattr(bill, "created_at", None).strftime("%Y-%m-%d %H:%M:%S")
            if getattr(bill, "created_at", None)
            else None
        ),
    }

# ==================================== borç silme ========================
@admin_bp.route("/bills/<int:bill_id>/delete", methods=["POST"])
@admin_required
def delete_bill(bill_id: int):
    """Tek bir borç kaydını silmek için (Audit Log dahil)."""

    # --- Aktif site kontrolü ---
    admin_user = _get_current_admin()
    site_id = session.get("active_site_id") or (admin_user.site_id if admin_user else None)
    if not site_id:
        return jsonify({"ok": False, "error": "Herhangi bir siteye atanmış değilsiniz."}), 403

    try:
        bill = Bill.query.get(bill_id)
        if not bill:
            return jsonify({"ok": False, "error": "Borç kaydı bulunamadı."}), 404

        # 🔴 Başka sitenin borcuysa iptal
        if bill.site_id != site_id:
            return jsonify({"ok": False, "error": "Bu borç için yetkiniz yok."}), 403

        # ✅ Audit için eski değer snapshot (silmeden önce)
        old_snapshot = _bill_audit_dict(bill)

        # Bu borca bağlı ödeme var mı? (varsa silmeyi engelle)
        payments_count = (
            db.session.query(func.count(Payment.id))
            .filter(Payment.bill_id == bill.id)
            .scalar()
        ) or 0

        if payments_count > 0:
            # ✅ Audit Log (FAILURE - DELETE Bill)
            try:
                log_action(
                    action="DELETE",
                    entity_type="Bill",
                    entity_id=bill_id,
                    old_values=old_snapshot,
                    new_values={"blocked_reason": "Bu borca bağlı ödeme var", "payments_count": int(payments_count)},
                    description="Borç silme engellendi (bağlı ödeme bulundu).",
                    site_id=site_id,
                    status="failure",
                    error_message=f"Bill({bill_id}) için {payments_count} adet ödeme var. Silme engellendi.",
                )
            except Exception:
                current_app.logger.exception("Audit log yazılamadı (FAILURE DELETE Bill - payments exist)")

            return jsonify({
                "ok": False,
                "error": "Bu borca bağlı ödeme(ler) var. Önce ödemeleri silmeden borç silinemez."
            }), 400

        # Sil
        db.session.delete(bill)
        db.session.commit()

        # ✅ Audit Log (DELETE Bill)
        try:
            log_action(
                action="DELETE",
                entity_type="Bill",
                entity_id=bill_id,
                old_values=old_snapshot,
                new_values=None,
                description=f"Borç silindi (id={bill_id})",
                site_id=site_id,
                status="success",
            )
        except Exception:
            current_app.logger.exception("Audit log yazılamadı (DELETE Bill)")

        return jsonify({"ok": True})

    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Borç kaydı silinemedi: %s", exc)

        # ✅ Audit Log (FAILURE - DELETE Bill)
        try:
            # Bill bulunabildiyse snapshot vardı; yoksa None kalır.
            log_action(
                action="DELETE",
                entity_type="Bill",
                entity_id=bill_id,
                old_values=old_snapshot if "old_snapshot" in locals() else None,
                new_values=None,
                description="Borç silme başarısız",
                site_id=site_id,
                status="failure",
                error_message=str(exc),
            )
        except Exception:
            current_app.logger.exception("Audit log yazılamadı (FAILURE DELETE Bill)")

        return jsonify({"ok": False, "error": "Borç silinirken bir hata oluştu."}), 500



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

    # --- Aktif site kontrolü ---
    admin_user = _get_current_admin()
    site_id = session.get("active_site_id") or (admin_user.site_id if admin_user else None)
    if not site_id:
        flash("Bu işlemi yapabilmek için bir siteye atanmış olmanız gerekiyor.", "error")
        return redirect(url_for("admin.manage_bills"))

    try:
        bill = Bill.query.get(bill_id)
        if not bill:
            flash("Güncellenecek borç kaydı bulunamadı.", "error")
            return redirect(url_for("admin.manage_bills"))

        # 🔴 Sadece kendi sitesine ait borcu güncelleyebilsin
        if bill.site_id != site_id:
            flash("Bu borç kaydı, yetkili olduğunuz siteye ait değil.", "error")
            return redirect(url_for("admin.manage_bills"))

        # Açıklama
        if description:
            bill.description = description

        # Tutar
        if amount_str:
            bill.amount = Decimal(amount_str.replace(",", "."))

        # Vade tarihi (esnek format)
        if due_date_str:
            try:
                bill.due_date = _parse_date_flex(due_date_str)
            except ValueError:
                # Eski davranışı koruyalım: sadece uyarı, eski tarih kalsın
                flash("Tarih formatı anlaşılamadı, mevcut tarih korunuyor. Örnek: 04.01.2026", "warning")

        # Tür
        bill.type = bill_type

        db.session.commit()
        flash("Borç kaydı güncellendi.", "success")

    except (ValueError, SQLAlchemyError) as exc:
        db.session.rollback()
        current_app.logger.exception("Borç kaydı güncellenemedi: %s", exc)
        flash("Borç güncellenirken bir hata oluştu.", "error")

    return redirect(url_for("admin.manage_bills"))



# ===== AİDAT DURUMU (YILLIK ÖZET TABLOSU + OTOMATİK AYLIK BORÇ) =====
# admin_routes.py dosyasında aşağıdaki yerin tamamını değiştir:
# Satır başlangıcı: @admin_bp.route("/dues-summary", methods=["GET"])
# Satır bitişi: return render_template(...) ile bitişini bulup tümünü değiştir

@admin_bp.route("/dues-summary", methods=["GET"])
@admin_required
def dues_summary():
    """
    Her DAİRE için, seçilen yılda Ocak–Aralık aidat durumlarını özetleyen tablo.
    + HER DAİRE İÇİN AYLAR BAZINDA TOPLAM ÖDENEN / KALAN BORÇ satırları
    """
    # --- Aktif site kontrolü ---
    admin_user = _get_current_admin()
    site_id = session.get("active_site_id") or (admin_user.site_id if admin_user else None)
    if not site_id:
        flash("Bu sayfayı kullanabilmek için bir siteye atanmış olmanız gerekiyor.", "error")
        return redirect(url_for("index"))

    now = datetime.utcnow()
    current_year = now.year
    current_month = now.month

    # Yıl seçimi
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

    # 1) Aktif siteye ait daireleri çek
    apartments = []
    try:
        apartments = (
            Apartment.query
            .filter(Apartment.site_id == site_id)  # ✅ SİTE FİLTRESİ
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

    # 2) İçinde bulunulan yıl ve ay için otomatik aidat oluştur (lazy)
    if year == current_year and apartments:
        try:
            active_apartment_ids = {apt.id for apt in apartments if apt.id is not None}

            month_start = date(year, current_month, 1)
            if current_month == 12:
                month_end = date(year + 1, 1, 1)
            else:
                month_end = date(year, current_month + 1, 1)

            existing_aidat_bills = (
                Bill.query.filter(
                    Bill.site_id == site_id,                       # ✅ SİTE FİLTRESİ
                    Bill.type == "aidat",                           # ✅ SADECE AİDAT
                    Bill.apartment_id.in_(active_apartment_ids),
                    Bill.due_date >= month_start,
                    Bill.due_date < month_end,
                )
                .all()
            )

            apartments_with_aidat = {
                b.apartment_id for b in existing_aidat_bills if b.apartment_id is not None
            }

            for apt_id in active_apartment_ids:
                if apt_id in apartments_with_aidat:
                    continue

                desc = f"{year} {month_labels.get(current_month, str(current_month))} aidatı"

                auto_bill = Bill(
                    site_id=site_id,  # ✅ KRİTİK: BU YOKSA ÇOKLU SİTEDE KAYIT KAYBOLUR
                    apartment_id=apt_id,
                    description=desc,
                    amount=get_default_monthly_dues_amount(site_id),
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

    # 3) Seçilen yıl için tüm AİDAT Bill kayıtlarını çek (site bazlı)
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
                Bill.site_id == site_id,          # ✅ SİTE FİLTRESİ
                Bill.type == "aidat",             # ✅ SADECE AİDAT
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

        # Bu Bill'lere bağlı tüm ödemeleri çek (site bazlı)
        if bill_key_by_id:
            payments = (
                Payment.query
                .filter(
                    Payment.site_id == site_id,   # ✅ SİTE FİLTRESİ
                    Payment.bill_id.in_(bill_key_by_id.keys())
                )
                .all()
            )
        else:
            payments = []

        # Ödenen toplamlar
        paid_totals = defaultdict(Decimal)
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

    # 4) Dairelere atanmış ilk aktif sakinleri tek sorguda çek (SADECE BU SİTENİN DAİRELERİ)
    resident_by_apartment = {}
    try:
        apt_ids = [apt.id for apt in apartments if apt.id is not None]
        if apt_ids:
            residents = (
                User.query
                .filter(
                    User.role == "resident",
                    User.is_active == True,  # noqa: E712
                    User.apartment_id.in_(apt_ids),  # ✅ SADECE BU SİTENİN DAİRELERİ
                )
                .order_by(User.name.asc())
                .all()
            )
        else:
            residents = []

        for u in residents:
            if u.apartment_id not in resident_by_apartment:
                resident_by_apartment[u.apartment_id] = u

    except SQLAlchemyError as exc:
        current_app.logger.exception("Sakin listesi alınamadı: %s", exc)
        flash("Sakin listesi alınırken bir hata oluştu.", "error")
        resident_by_apartment = {}

    # 5) Template'e veri hazırlama
    rows = []
    for apt in apartments:
        monthly_status = {}
        
        # ✅ HER DAİRE İÇİN AYLAR BAZINDA ÖDENEN VE KALAN
        monthly_paid = {}
        monthly_remaining = {}
        
        for m_num, _m_label in months:
            key = (apt.id, m_num)
            
            # Durum
            if key in status_map:
                monthly_status[m_num] = status_map[key]
            else:
                monthly_status[m_num] = None  # O ay için borç yok
            
            # Ödenen tutar
            paid_for_month = paid_totals.get(key, Decimal("0"))
            monthly_paid[m_num] = paid_for_month
            
            # Kalan borç
            billed_for_month = bill_totals.get(key, Decimal("0"))
            remaining_for_month = billed_for_month - paid_for_month
            monthly_remaining[m_num] = remaining_for_month if remaining_for_month > 0 else Decimal("0.00")

        resident = resident_by_apartment.get(apt.id)
        rows.append(
            {
                "apartment": apt,
                "resident": resident,
                "monthly": monthly_status,
                "monthly_paid": monthly_paid,           # ✅ YENİ
                "monthly_remaining": monthly_remaining, # ✅ YENİ
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
from sqlalchemy import func

@admin_bp.route("/payments", methods=["GET", "POST"])
@admin_required
def manage_payments():
    """Ödeme kayıtlarını yönetir (site bazlı)."""

    # --- Aktif site kontrolü ---
    admin_user = _get_current_admin()
    site_id = session.get("active_site_id") or (admin_user.site_id if admin_user else None)
    if not site_id:
        flash("Bu sayfayı kullanabilmek için bir siteye atanmış olmanız gerekiyor.", "error")
        return redirect(url_for("index"))

    if request.method == "POST":
        apartment_id = request.form.get("apartment_id")
        bill_id = request.form.get("bill_id") or None
        user_id = request.form.get("user_id") or None
        amount = (request.form.get("amount") or "").strip()
        payment_date_str = request.form.get("payment_date") or ""
        method = (request.form.get("method") or "").strip() or None
        bill_type = (request.form.get("bill_type") or "").strip() or None

        if not apartment_id or not amount:
            flash("Daire ve tutar zorunludur.", "error")
        else:
            try:
                created_payment_ids = []  # ✅ dağıtımda birden fazla ödeme satırı oluşabilir
                original_amount = None    # ✅ girilen tutarı sakla
                description = (request.form.get("description") or "").strip() or None

                # Temel ödeme objesini oluştur
                payment = Payment(
                    site_id=site_id,               # 🔴 BU SİTEYE AİT
                    apartment_id=int(apartment_id),
                    method=method,
                    description=description,

                )

                # Kullanıcı seçilmişse bağla
                if user_id:
                    payment.user_id = int(user_id)

                # Tutar
                try:
                    payment.amount = Decimal(amount.replace(",", "."))
                    original_amount = Decimal(payment.amount or 0)
                except (ValueError, ArithmeticError):
                    flash("Tutar sayısal olmalıdır.", "error")
                    return redirect(url_for("admin.manage_payments"))

                # Tarih
                if payment_date_str:
                    try:
                        payment.payment_date = _parse_date_flex(payment_date_str)
                    except ValueError:
                        flash("Ödeme tarihi anlaşılamadı. Örnek: 04.01.2026", "error")
                        return redirect(url_for("admin.manage_payments"))
                else:
                    payment.payment_date = datetime.utcnow().date()

                apt_id_int = int(apartment_id)
                remaining_amount = Decimal(payment.amount or 0)

                # ==========================================================
                # ÖDEME DAĞITIMI
                # Bill seçilmişse: Seçilen bill'e bağla
                # Bill seçilmemişse: Dairenin açık borçlarına FIFO dağıt
                # ==========================================================

                if bill_id and bill_id.strip():
                    # ✅ Seçilen bill'e direkt bağla (eski mantık)
                    payment.bill_id = int(bill_id)

                    # İstersen ödeme kaydında bill_type tutmak için:
                    # (Modelinde alan varsa zaten template fallback kullanıyorsun)
                    if bill_type:
                        try:
                            payment.bill_type = bill_type
                        except Exception:
                            pass

                    db.session.add(payment)
                    db.session.flush()
                    created_payment_ids.append(int(payment.id))
                else:
                    # ✅ Dairenin en eski açık borçlarını bul ve dağıt
                    # due_date NULL olan eski borçlar önce gelecek
                    open_bills = (
                        Bill.query.filter(
                            Bill.site_id == site_id,
                            Bill.apartment_id == apt_id_int,
                            Bill.status.in_(["open", "partial"]),
                        )
                        .order_by(
                            func.coalesce(Bill.due_date, Bill.created_at).asc(),
                            Bill.id.asc()
                        )
                        .all()
                    )

                    if not open_bills:
                        # Açık borç yoksa, ödemeyi direkt kaydet (devret olarak)
                        # (bill_id None kalır)
                        if bill_type:
                            try:
                                payment.bill_type = bill_type
                            except Exception:
                                pass

                        db.session.add(payment)
                        db.session.flush()
                        created_payment_ids.append(int(payment.id))
                    else:
                        # Ödemeyi açık borçlara dağıt
                        for bill in open_bills:
                            if remaining_amount <= 0:
                                break

                            # Bu borç için daha ödenen toplam
                            already_paid = (
                                db.session.query(func.coalesce(func.sum(Payment.amount), 0))
                                .filter(Payment.bill_id == bill.id)
                                .scalar()
                            )
                            already_paid = Decimal(already_paid or 0)

                            bill_amount = Decimal(bill.amount or 0)
                            bill_remaining = bill_amount - already_paid

                            if bill_remaining <= 0:
                                # Bu borç tamamen ödendi, atla
                                continue

                            # Bu borca ne kadar ödeme yapacağız?
                            pay_for_this_bill = min(remaining_amount, bill_remaining)
                            
                            description = (request.form.get("description") or "").strip() or None
                            # Ödeme satırı oluştur (bir ödeme = bir borç)
                            payment_line = Payment(
                                site_id=site_id,
                                apartment_id=apt_id_int,
                                bill_id=bill.id,
                                user_id=int(user_id) if user_id else None,
                                amount=pay_for_this_bill,
                                payment_date=payment.payment_date,
                                method=payment.method,
                                description=description,
                            )

                            # Modelinde bill_type alanı varsa ve frontend gönderiyorsa:
                            if bill_type:
                                try:
                                    payment_line.bill_type = bill_type
                                except Exception:
                                    pass

                            db.session.add(payment_line)
                            db.session.flush()
                            created_payment_ids.append(int(payment_line.id))

                            # Kalan ödemeyi azalt
                            remaining_amount -= pay_for_this_bill

                        # Eğer ödeme kaldıysa (tüm borçlar ödenmiş), devret hesabına al
                        if remaining_amount > 0:
                            payment.amount = remaining_amount
                            payment.bill_id = None

                            if bill_type:
                                try:
                                    payment.bill_type = bill_type
                                except Exception:
                                    pass

                            db.session.add(payment)
                            db.session.flush()
                            created_payment_ids.append(int(payment.id))

                # İlgili borcun/borçların durumunu güncelle
                if bill_id:
                    # Seçilen bill'in statusunu güncelle
                    bill = Bill.query.get(int(bill_id))
                    if bill and bill.site_id == site_id:
                        total_paid_for_bill = (
                            db.session.query(func.coalesce(func.sum(Payment.amount), 0))
                            .filter(Payment.bill_id == bill.id)
                            .scalar()
                        )
                        total_paid_for_bill = Decimal(total_paid_for_bill or 0)
                        bill_amount = Decimal(bill.amount or 0)

                        if total_paid_for_bill >= bill_amount:
                            bill.status = "paid"
                        elif total_paid_for_bill > 0:
                            bill.status = "partial"
                        else:
                            bill.status = "open"
                else:
                    # Tüm açık borçların statusını güncelle
                    open_bills = (
                        Bill.query.filter(
                            Bill.site_id == site_id,
                            Bill.apartment_id == apt_id_int,
                            Bill.status.in_(["open", "partial"]),
                        )
                        .all()
                    )
                    for bill in open_bills:
                        total_paid_for_bill = (
                            db.session.query(func.coalesce(func.sum(Payment.amount), 0))
                            .filter(Payment.bill_id == bill.id)
                            .scalar()
                        )
                        total_paid_for_bill = Decimal(total_paid_for_bill or 0)
                        bill_amount = Decimal(bill.amount or 0)

                        if total_paid_for_bill >= bill_amount:
                            bill.status = "paid"
                        elif total_paid_for_bill > 0:
                            bill.status = "partial"
                        else:
                            bill.status = "open"

                db.session.commit()

                # ✅ Audit Log (CREATE Payment) — dağıtımda çok satır oluşabilir
                try:
                    for pid in (created_payment_ids or []):
                        try:
                            p = Payment.query.get(int(pid))
                        except Exception:
                            p = None

                        log_action(
                            action="CREATE",
                            entity_type="Payment",
                            entity_id=int(pid) if pid else None,
                            old_values=None,
                            new_values=_payment_audit_dict(p) if p else {
                                "site_id": site_id,
                                "apartment_id": apartment_id,
                                "bill_id": bill_id,
                                "user_id": user_id,
                                "amount": str(original_amount) if original_amount is not None else amount,
                                "payment_date": payment_date_str,
                                "method": method,
                                "bill_type": bill_type,
                            },
                            description=f"Ödeme oluşturuldu (id={pid})",
                            site_id=site_id,
                            status="success",
                        )
                except Exception:
                    current_app.logger.exception("Audit log yazılamadı (CREATE Payment)")

                if bill_id:
                    flash("Ödeme kaydı oluşturuldu.", "success")
                else:
                    # remaining_amount dağıtım sonrası kaldıysa devret'e alındı (payment objesinde)
                    if remaining_amount > 0:
                        flash(f"Ödeme dağıtıldı. Kalan {remaining_amount:.2f} TL devret hesabına alındı.", "success")
                    else:
                        flash("Ödeme açık borçlara dağıtıldı.", "success")

            except (ValueError, SQLAlchemyError) as exc:
                db.session.rollback()
                current_app.logger.exception("Ödeme kaydı eklenemedi: %s", exc)
            
                # ✅ Audit Log (FAILURE - CREATE Payment)
                try:
                    attempted = {
                        "site_id": site_id,
                        "apartment_id": apartment_id,
                        "bill_id": bill_id,
                        "user_id": user_id,
                        "amount": amount,
                        "payment_date": payment_date_str,
                        "method": method,
                        "bill_type": bill_type,
                        "description": description,
                    }
                    log_action(
                        action="CREATE",
                        entity_type="Payment",
                        entity_id=None,
                        old_values=None,
                        new_values=attempted,
                        description="Ödeme oluşturma başarısız",
                        site_id=site_id,
                        status="failure",
                        error_message=str(exc),
                    )
                except Exception:
                    current_app.logger.exception("Audit log yazılamadı (FAILURE CREATE Payment)")

                flash("Ödeme kaydedilirken bir hata oluştu.", "error")

    apartments = []
    bills = []
    users = []
    payments = []

    try:
        # Sadece bu sitenin daireleri
        apartments = (
            Apartment.query
            .filter_by(site_id=site_id)
            .order_by(
                Apartment.block.asc(),
                Apartment.floor.asc(),
                Apartment.number.asc(),
            )
            .all()
        )

        # Sadece bu sitenin borçları
        bills = (
            Bill.query
            .filter_by(site_id=site_id)
            .order_by(Bill.created_at.desc())
            .limit(200)
            .all()
        )

        # Sadece bu sitenin kullanıcıları
        users = (
            User.query
            .filter_by(site_id=site_id)
            .order_by(User.name.asc())
            .all()
        )

        # Sadece bu sitenin ödemeleri
        payments = (
            db.session.query(Payment, Apartment, User, Bill)
            .outerjoin(Apartment, Payment.apartment_id == Apartment.id)
            .outerjoin(User, Payment.user_id == User.id)
            .outerjoin(Bill, Payment.bill_id == Bill.id)
            .filter(Payment.site_id == site_id)          # 🔴 SİTEYE GÖRE
            .order_by(Payment.payment_date.desc())
            .limit(200)
            .all()
        )

    except SQLAlchemyError as exc:
        current_app.logger.exception("Ödeme listesi alınamadı: %s", exc)
        flash("Ödeme listesi alınırken bir hata oluştu.", "error")

    # ✅ Bills -> JS payload (ödenen / kalan hesaplarıyla)
    bill_ids = [b.id for b in bills] if bills else []

    paid_map = {}
    if bill_ids:
        rows = (
            db.session.query(
                Payment.bill_id,
                func.coalesce(func.sum(Payment.amount), 0)
            )
            .filter(Payment.site_id == site_id)
            .filter(Payment.bill_id.in_(bill_ids))
            .group_by(Payment.bill_id)
            .all()
        )
        paid_map = {int(bid): float(total or 0) for (bid, total) in rows if bid is not None}

    bills_payload = []
    for b in (bills or []):
        amount = float(getattr(b, "amount", 0) or 0)
        paid = float(paid_map.get(int(b.id), 0))
        remaining = max(0.0, amount - paid)

        bills_payload.append({
            "id": int(b.id),
            "apartment_id": int(getattr(b, "apartment_id", 0) or 0),
            "type": getattr(b, "type", None),
            "description": getattr(b, "description", None) or getattr(b, "desc", None) or "",
            "amount": amount,
            "paid": paid,
            "remaining": remaining,
        })

    return render_template(
        "admin/odemeler.html",
        apartments=apartments,
        bills=bills,
        users=users,
        payments=payments,
        bills_payload=bills_payload,   # ✅ bunu ekledik
    )


@admin_bp.route("/payments/<int:payment_id>/update", methods=["POST"])
@admin_required
def update_payment(payment_id: int):
    """Tek bir ödeme kaydını satır içi (inline) düzenlemek için."""

    # --- Aktif site kontrolü ---
    admin_user = _get_current_admin()
    site_id = session.get("active_site_id") or (admin_user.site_id if admin_user else None)
    if not site_id:
        return jsonify({"ok": False, "error": "Herhangi bir siteye atanmış değilsiniz."}), 403

    try:
        payment = Payment.query.get(payment_id)
        if not payment:
            return jsonify({"ok": False, "error": "Ödeme kaydı bulunamadı."}), 404

        # 🔴 Başka sitenin ödemesi ise iptal
        if payment.site_id != site_id:
            return jsonify({"ok": False, "error": "Bu ödeme için yetkiniz yok."}), 403

        # ✅ Audit için eski değer snapshot
        old_snapshot = _payment_audit_dict(payment)

        amount_str = (request.form.get("amount") or "").strip()
        method = (request.form.get("method") or "").strip() or None
        date_str = (request.form.get("payment_date") or "").strip()

        if not amount_str:
            return jsonify({"ok": False, "error": "Tutar boş olamaz."}), 400

        try:
            payment.amount = Decimal(amount_str.replace(",", "."))
        except (ValueError, ArithmeticError):
            return jsonify({"ok": False, "error": "Tutar sayısal olmalıdır."}), 400

        payment.method = method

        if date_str:
            try:
                payment.payment_date = _parse_date_flex(date_str)
            except ValueError:
                return jsonify({"ok": False, "error": "Tarih anlaşılamadı. Örn: 04.01.2026"}), 400

        # Faturaya bağlıysa status recalculation
        if payment.bill_id:
            bill = Bill.query.get(payment.bill_id)
            if bill and bill.site_id == site_id:
                _recalc_bill_status(bill)

        db.session.commit()

        # ✅ Audit Log (UPDATE Payment)
        try:
            new_snapshot = _payment_audit_dict(payment)
            log_action(
                action="UPDATE",
                entity_type="Payment",
                entity_id=payment.id,
                old_values=old_snapshot,
                new_values=new_snapshot,
                description=f"Ödeme güncellendi (id={payment.id})",
                site_id=site_id,
                status="success",
            )
        except Exception:
            current_app.logger.exception("Audit log yazılamadı (UPDATE Payment)")

        # Formatlanmış stringler
        return jsonify({
            "ok": True,
            "amount": f"{payment.amount:.2f}",
            "payment_date": payment.payment_date.strftime("%d.%m.%Y") if payment.payment_date else "",
            "method": payment.method or "",
        })

    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Ödeme kaydı güncellenemedi: %s", exc)

        # ✅ Audit Log (FAILURE - UPDATE Payment)
        try:
            attempted = {
                "payment_id": payment_id,
                "amount": (request.form.get("amount") or "").strip(),
                "method": (request.form.get("method") or "").strip() or None,
                "payment_date": (request.form.get("payment_date") or "").strip(),
            }
            log_action(
                action="UPDATE",
                entity_type="Payment",
                entity_id=payment_id,
                old_values=old_snapshot if "old_snapshot" in locals() else None,
                new_values=attempted,
                description="Ödeme güncelleme başarısız",
                site_id=site_id,
                status="failure",
                error_message=str(exc),
            )
        except Exception:
            current_app.logger.exception("Audit log yazılamadı (FAILURE UPDATE Payment)")

        return jsonify(
            {"ok": False, "error": "Ödeme güncellenirken bir hata oluştu."}
        ), 500


@admin_bp.route("/payments/<int:payment_id>/delete", methods=["POST"])
@admin_required
def delete_payment(payment_id: int):
    """Tek bir ödeme kaydını silmek için."""

    # --- Aktif site kontrolü ---
    admin_user = _get_current_admin()
    site_id = session.get("active_site_id") or (admin_user.site_id if admin_user else None)
    if not site_id:
        return jsonify({"ok": False, "error": "Herhangi bir siteye atanmış değilsiniz."}), 403

    try:
        payment = Payment.query.get(payment_id)
        if not payment:
            return jsonify({"ok": False, "error": "Ödeme kaydı bulunamadı."}), 404

        # ✅ Audit için eski değer snapshot (silmeden önce)
        old_snapshot = _payment_audit_dict(payment)

        # 🔴 Başka sitenin ödemesi ise iptal
        if payment.site_id != site_id:
            return jsonify({"ok": False, "error": "Bu ödeme için yetkiniz yok."}), 403

        bill_id = payment.bill_id

        db.session.delete(payment)

        if bill_id:
            bill = Bill.query.get(bill_id)
            if bill and bill.site_id == site_id:
                _recalc_bill_status(bill)

        db.session.commit()

        # ✅ Audit Log (DELETE Payment)
        try:
            log_action(
                action="DELETE",
                entity_type="Payment",
                entity_id=payment_id,
                old_values=old_snapshot,
                new_values=None,
                description=f"Ödeme silindi (id={payment_id})",
                site_id=site_id,
                status="success",
            )
        except Exception:
                current_app.logger.exception("Audit log yazılamadı (DELETE Payment)")

        return jsonify({"ok": True})

    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Ödeme kaydı silinemedi: %s", exc)

        # ✅ Audit Log (FAILURE - DELETE Payment)
        try:
            log_action(
                action="DELETE",
                entity_type="Payment",
                entity_id=payment_id,
                old_values=old_snapshot if "old_snapshot" in locals() else None,
                new_values=None,
                description="Ödeme silme başarısız",
                site_id=site_id,
                status="failure",
                error_message=str(exc),
            )
        except Exception:
            current_app.logger.exception("Audit log yazılamadı (FAILURE DELETE Payment)")

        return jsonify(
            {"ok": False, "error": "Ödeme silinirken bir hata oluştu."}
        ), 500


def _payment_audit_dict(payment: Payment) -> dict:
    """Ödeme kaydını audit log için JSON-dostu sözlüğe çevir."""
    if not payment:
        return {}

    return {
        "id": getattr(payment, "id", None),
        "site_id": getattr(payment, "site_id", None),
        "apartment_id": getattr(payment, "apartment_id", None),
        "user_id": getattr(payment, "user_id", None),
        "bill_id": getattr(payment, "bill_id", None),
        "bill_type": getattr(payment, "bill_type", None),
        "amount": str(getattr(payment, "amount", "") or ""),
        "method": getattr(payment, "method", None),
        "payment_date": (
            getattr(payment, "payment_date", None).strftime("%Y-%m-%d")
            if getattr(payment, "payment_date", None)
            else None
        ),
        "created_at": (
            getattr(payment, "created_at", None).strftime("%Y-%m-%d %H:%M:%S")
            if getattr(payment, "created_at", None)
            else None
        ),
    }

# ============== PDF Makbuz indir ===============================
@admin_bp.route("/payments/<int:payment_id>/receipt", methods=["GET"])
@admin_required
def payment_receipt(payment_id: int):
    """Tek bir ödeme için profesyonel PDF makbuz üret ve indir."""

    # --- Aktif site kontrolü ---
    admin_user = _get_current_admin()
    site_id = session.get("active_site_id") or (admin_user.site_id if admin_user else None)
    if not site_id:
        flash("Bu işlem için bir siteye atanmış olmanız gerekiyor.", "error")
        return redirect(url_for("admin.manage_payments"))

    try:
        row = (
            db.session.query(Payment, Apartment, User, Bill)
            .outerjoin(Apartment, Payment.apartment_id == Apartment.id)
            .outerjoin(User, Payment.user_id == User.id)
            .outerjoin(Bill, Payment.bill_id == Bill.id)
            .filter(Payment.id == payment_id)
            .first()
        )

        if not row:
            flash("Ödeme kaydı bulunamadı.", "error")
            return redirect(url_for("admin.manage_payments"))

        payment, apartment, user, bill = row

        # 🔴 Başka sitenin ödemesi ise izin verme
        if payment.site_id != site_id:
            flash("Bu ödeme için makbuz oluşturma yetkiniz yok.", "error")
            return redirect(url_for("admin.manage_payments"))

        # =========================
        #   DİL (I18N) - GÜÇLÜ TESPİT
        # =========================
        def _normalize_lang(val: str) -> str:
            if not val:
                return "tr"
            v = str(val).strip().lower()
            # en-US, tr-TR gibi gelebilir
            if "-" in v:
                v = v.split("-", 1)[0]
            if "_" in v:
                v = v.split("_", 1)[0]
            return v

        def _detect_lang() -> str:
            # 1) Flask-Babel varsa
            try:
                from flask_babel import get_locale  # type: ignore
                loc = get_locale()
                if loc:
                    return _normalize_lang(str(loc))
            except Exception:
                pass

            # 2) g üzerinden (uygulamada set ediliyor olabilir)
            try:
                from flask import g
                for key in ("lang", "locale", "language", "current_lang"):
                    if hasattr(g, key):
                        v = getattr(g, key)
                        if v:
                            return _normalize_lang(v)
            except Exception:
                pass

            # 3) session üzerinden (birçok olası anahtar)
            for key in ("lang", "locale", "language", "current_lang", "selected_lang", "ui_lang"):
                v = session.get(key)
                if v:
                    return _normalize_lang(v)

            # 4) cookie üzerinden
            try:
                for key in ("lang", "locale", "language"):
                    v = request.cookies.get(key)
                    if v:
                        return _normalize_lang(v)
            except Exception:
                pass

            # 5) Accept-Language header (en yoğun fallback)
            try:
                hdr = request.headers.get("Accept-Language", "")
                if hdr:
                    # "en-US,en;q=0.9,tr;q=0.8" -> "en"
                    first = hdr.split(",", 1)[0]
                    return _normalize_lang(first)
            except Exception:
                pass

            return "tr"

        lang = _detect_lang()
        if lang not in ("tr", "en", "me"):
            lang = "tr"

        current_app.logger.info("Makbuz dili (payment_receipt) = %s", lang)

        I18N = {
            "tr": {
                "RECEIPT_TITLE": "ÖDEME MAKBUZU",
                "RECEIPT_NO": "Makbuz No",
                "APARTMENT": "Daire",
                "PAYER": "Ödemeyi Yapan",
                "PAYMENT_DATE": "Ödeme Tarihi",
                "DEBT_BOX_TITLE": "Borç / Ödeme Bilgileri",
                "DEBT_TYPE": "Borç Türü",
                "DESCRIPTION": "Açıklama",
                "AMOUNT": "Tutar",
                "PAYMENT_METHOD": "Ödeme Yöntemi",
                "AUTHORIZED_SIGNATURE": "Yetkili İmzası:",
                "FOOTER_1": "Bu makbuz belirtilen tutarda ödemenin alındığını gösterir. Dijital ortamda oluşturulmuştur.",
                "FOOTER_2": "Kaşe ve ıslak imza gerekmeksizin geçerlidir; gerektiğinde sistem kayıtlarıyla birlikte tevsik edilir.",
                "NOT_SPECIFIED": "Belirtilmedi",
                "DASH": "-",
                "CUR": "TL",
                "SITE_FALLBACK": "Site / Apartman",
                "BILL_aidat": "Aidat",
                "BILL_elektrik": "Elektrik",
                "BILL_su": "Su",
                "BILL_dogalgaz": "Doğalgaz",
                "BILL_ekstra": "Ekstra Gider",
                "METHOD_nakit": "Nakit",
                "METHOD_banka": "Banka Havalesi / EFT",
                "METHOD_pos": "POS / Kredi Kartı",
                "METHOD_online": "Online Ödeme",
            },
            "en": {
                "RECEIPT_TITLE": "PAYMENT RECEIPT",
                "RECEIPT_NO": "Receipt No",
                "APARTMENT": "Apartment",
                "PAYER": "Payer",
                "PAYMENT_DATE": "Payment Date",
                "DEBT_BOX_TITLE": "Bill / Payment Details",
                "DEBT_TYPE": "Bill Type",
                "DESCRIPTION": "Description",
                "AMOUNT": "Amount",
                "PAYMENT_METHOD": "Payment Method",
                "AUTHORIZED_SIGNATURE": "Authorized Signature:",
                "FOOTER_1": "This receipt confirms that the specified amount has been received. It is generated digitally.",
                "FOOTER_2": "It is valid without stamp or wet signature; it can be substantiated with system records if needed.",
                "NOT_SPECIFIED": "Not specified",
                "DASH": "-",
                "CUR": "TRY",
                "SITE_FALLBACK": "Site / Building",
                "BILL_aidat": "Dues",
                "BILL_elektrik": "Electricity",
                "BILL_su": "Water",
                "BILL_dogalgaz": "Natural Gas",
                "BILL_ekstra": "Extra Expense",
                "METHOD_nakit": "Cash",
                "METHOD_banka": "Bank Transfer / EFT",
                "METHOD_pos": "POS / Credit Card",
                "METHOD_online": "Online Payment",
            },
            "me": {
                "RECEIPT_TITLE": "POTVRDA O UPLATI",
                "RECEIPT_NO": "Broj potvrde",
                "APARTMENT": "Stan",
                "PAYER": "Uplatilac",
                "PAYMENT_DATE": "Datum uplate",
                "DEBT_BOX_TITLE": "Detalji duga / uplate",
                "DEBT_TYPE": "Vrsta duga",
                "DESCRIPTION": "Opis",
                "AMOUNT": "Iznos",
                "PAYMENT_METHOD": "Način plaćanja",
                "AUTHORIZED_SIGNATURE": "Ovlašćeni potpis:",
                "FOOTER_1": "Ova potvrda pokazuje da je navedeni iznos primljen. Generisana je digitalno.",
                "FOOTER_2": "Važeća je bez pečata i mokrog potpisa; po potrebi se može dokazati sistemskim zapisima.",
                "NOT_SPECIFIED": "Nije navedeno",
                "DASH": "-",
                "CUR": "EUR",
                "SITE_FALLBACK": "Zgrada / Kompleks",
                "BILL_aidat": "Održavanje",
                "BILL_elektrik": "Struja",
                "BILL_su": "Voda",
                "BILL_dogalgaz": "Gas",
                "BILL_ekstra": "Dodatni trošak",
                "METHOD_nakit": "Gotovina",
                "METHOD_banka": "Bankovni transfer / EFT",
                "METHOD_pos": "POS / Kartica",
                "METHOD_online": "Online plaćanje",
            },
        }

        def t(key: str) -> str:
            return I18N.get(lang, I18N["tr"]).get(key, key)

        # Sistem ayarlarından site/apartman adı
        try:
            settings_obj = SystemSetting.get_singleton()
        except SQLAlchemyError:
            settings_obj = None

        # 🔹 Öncelik: session'daki aktif site adı
        site_name = session.get("active_site_name")

        # 🔹 Yoksa DB'den oku
        if not site_name and payment.site_id:
            site_obj = Site.query.get(payment.site_id)
            if site_obj:
                site_name = site_obj.name

        # 🔹 Yine bulunamazsa fallback
        if not site_name:
            site_name = t("SITE_FALLBACK")

        # FONT KAYDI (Türkçe için TTF)
        font_dir = os.path.join(current_app.root_path, "static", "fonts")
        regular_font = "DejaVu"
        bold_font = "DejaVu-Bold"

        regular_path = os.path.join(font_dir, "DejaVuSans.ttf")
        bold_path = os.path.join(font_dir, "DejaVuSans-Bold.ttf")

        # Varsayılan olarak Helvetica kullan, eğer TTF yoksa
        use_custom_font = False
        if os.path.exists(regular_path) and os.path.exists(bold_path):
            try:
                pdfmetrics.registerFont(TTFont(regular_font, regular_path))
                pdfmetrics.registerFont(TTFont(bold_font, bold_path))
                use_custom_font = True
            except Exception as e:
                current_app.logger.warning("TTF font kaydı başarısız: %s", e)

        # PDF'yi hafızada oluştur
        buffer = io.BytesIO()
        pdf = canvas.Canvas(buffer, pagesize=A4)
        width, height = A4

        # Kenar boşlukları
        margin_left = 40
        margin_right = width - 40
        margin_top = height - 40
        margin_bottom = 40

        # Yardımcı fonksiyonlar
        def set_font_bold(size):
            if use_custom_font:
                pdf.setFont(bold_font, size)
            else:
                pdf.setFont("Helvetica-Bold", size)

        def set_font_regular(size):
            if use_custom_font:
                pdf.setFont(regular_font, size)
            else:
                pdf.setFont("Helvetica", size)

        y = margin_top

        # =========================
        #   BAŞLIK BÖLÜMÜ
        # =========================
        set_font_bold(18)
        pdf.drawString(margin_left, y, t("RECEIPT_TITLE"))
        y -= 20

        set_font_bold(16)
        pdf.drawString(margin_left, y, site_name)
        y -= 28

        set_font_regular(11)
        pdf.drawRightString(margin_right, y, f"{t('RECEIPT_NO')}: {payment.id}")
        y -= 25

        pdf.setLineWidth(0.5)
        pdf.line(margin_left, y, margin_right, y)
        y -= 20

        set_font_bold(12)
        pdf.drawString(margin_left, y, site_name)
        y -= 18

        set_font_regular(10)
        if apartment:
            daire_str = f"{apartment.block} Blok, {apartment.floor}. Kat, No: {apartment.number}"
            pdf.drawString(margin_left, y, f"{t('APARTMENT')}: {daire_str}")
            y -= 16

        if user:
            pdf.drawString(margin_left, y, f"{t('PAYER')}: {user.name}")
            y -= 16

        date_str = (
            payment.payment_date.strftime("%d.%m.%Y")
            if payment.payment_date
            else datetime.utcnow().strftime("%d.%m.%Y")
        )
        pdf.drawString(margin_left, y, f"{t('PAYMENT_DATE')}: {date_str}")
        y -= 24

        # BORÇ / ÖDEME DETAY KUTUSU
        bill_type_raw = None
        if bill and bill.type:
            bill_type_raw = bill.type
        elif getattr(payment, "bill_type", None):
            bill_type_raw = payment.bill_type

        bill_type_label = t("NOT_SPECIFIED")
        if bill_type_raw:
            key = f"BILL_{bill_type_raw}"
            if key in I18N.get(lang, {}):
                bill_type_label = t(key)
            else:
                bill_type_label = str(bill_type_raw).capitalize()

        description = t("DASH")
        if bill and bill.description:
            description = bill.description

        box_top = y
        box_bottom = box_top - 90
        if box_bottom < margin_bottom + 60:
            pdf.showPage()
            y = margin_top
            box_top = y
            box_bottom = box_top - 90

        pdf.setLineWidth(0.7)
        pdf.rect(margin_left, box_bottom, (margin_right - margin_left), (box_top - box_bottom))

        inner_y = box_top - 15
        inner_x = margin_left + 10

        set_font_bold(11)
        pdf.drawString(inner_x, inner_y, t("DEBT_BOX_TITLE"))
        inner_y -= 18

        set_font_regular(10)
        pdf.drawString(inner_x, inner_y, f"{t('DEBT_TYPE')} : {bill_type_label}")
        inner_y -= 16
        pdf.drawString(inner_x, inner_y, f"{t('DESCRIPTION')}   : {description}")
        inner_y -= 16

        amount_str = f"{payment.amount:.2f} {t('CUR')}"
        set_font_bold(11)
        pdf.drawString(inner_x, inner_y, f"{t('AMOUNT')}      : {amount_str}")
        inner_y -= 20

        method_label = t("DASH")
        if payment.method:
            mkey = f"METHOD_{payment.method}"
            if mkey in I18N.get(lang, {}):
                method_label = t(mkey)
            else:
                method_label = str(payment.method).capitalize()

        set_font_regular(10)
        pdf.drawString(inner_x, inner_y, f"{t('PAYMENT_METHOD')} : {method_label}")

        y = box_bottom - 30

        set_font_regular(10)
        pdf.drawString(margin_left, y, t("AUTHORIZED_SIGNATURE"))
        pdf.line(margin_left + 80, y - 2, margin_left + 220, y - 2)
        y -= 40

        set_font_regular(9)
        pdf.drawString(margin_left, y, t("FOOTER_1"))
        y -= 14
        pdf.drawString(margin_left, y, t("FOOTER_2"))

        pdf.showPage()
        pdf.save()

        buffer.seek(0)
        filename = f"odeme_makbuzu_{payment.id}.pdf"
        return send_file(
            buffer,
            as_attachment=True,
            download_name=filename,
            mimetype="application/pdf",
        )

    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Ödeme makbuzu oluşturulamadı: %s", exc)
        flash("Makbuz oluşturulurken bir hata oluştu.", "error")
        return redirect(url_for("admin.manage_payments"))



# ======================
#  DUYURULAR
# ======================

@admin_bp.route("/announcements", methods=["GET", "POST"])
@admin_required
def manage_announcements():
    """Duyuru oluşturma ve listeleme (site bazlı)."""
    admin_user = _get_current_admin()

    # Aktif site kontrolü (dashboard / bills / payments ile aynı mantık)
    from models.site_model import Site  # döngü olmasın diye lokal import da yapabilirsin
    site_id = session.get("active_site_id") or (admin_user.site_id if admin_user else None)

    if not site_id:
        flash("Duyurular bölümünü kullanabilmek için bir siteye atanmış olmanız gerekiyor.", "error")
        return redirect(url_for("index"))

    if request.method == "POST":
        title = (request.form.get("title") or "").strip()
        content = (request.form.get("content") or "").strip()
        target = (request.form.get("target") or "all").strip()

        if not title or not content:
            flash("Başlık ve içerik zorunludur.", "error")
        else:
            try:
                ann = Announcement(
                    site_id=site_id,  # 🔴 ZORUNLU ALAN: HANGİ SİTEYE AİT
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
            .filter(Announcement.site_id == site_id)   # 🔴 SADECE BU SİTENİN DUYURULARI
            .order_by(Announcement.created_at.desc())
            .limit(100)
            .all()
        )
    except SQLAlchemyError as exc:
        current_app.logger.exception("Duyuru listesi alınamadı: %s", exc)
        flash("Duyuru listesi alınırken bir hata oluştu.", "error")

    today = date.today()

    return render_template(
        "admin/duyurular.html",
        announcements=announcements,
        today=today,
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

    # ✅ Aktif siteyi bul (admin: kendi sitesi, super_admin: aktif site varsa o site)
    admin_user = _get_current_admin()
    site_id = session.get("active_site_id") or (admin_user.site_id if admin_user else None)

    is_super = (admin_user and admin_user.role == "super_admin")
    global_mode = is_super and not site_id  # super_admin site seçmezse tüm siteler

    if not is_super and not site_id:
        flash("Talep listesi için bir siteye atanmış olmanız gerekiyor.", "error")
        return redirect(url_for("admin.dashboard"))

    tickets = []
    try:
        q = (
            db.session.query(Ticket, Apartment, User)
            .outerjoin(Apartment, Ticket.apartment_id == Apartment.id)
            .outerjoin(User, Ticket.user_id == User.id)
        )

        # ✅ Normal admin: sadece kendi sitesi
        # ✅ Super admin: site seçtiyse sadece o site, seçmediyse global (hepsi)
        if not global_mode:
            q = q.filter(Ticket.site_id == site_id)

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

    admin_user = _get_current_admin()
    site_id = session.get("active_site_id") or (admin_user.site_id if admin_user else None)
    is_super = (admin_user and admin_user.role == "super_admin")
    global_mode = is_super and not site_id

    try:
        ticket = Ticket.query.get(ticket_id)
        if not ticket:
            flash("Talep bulunamadı.", "error")
            return redirect(url_for("admin.manage_tickets"))

        # ✅ Normal admin: sadece kendi sitesinin talebini güncelleyebilir
        # ✅ Super admin: global modda hepsi, site seçiliyse o site
        if not global_mode and ticket.site_id != site_id:
            flash("Bu talep başka bir siteye ait. İşlem yapamazsınız.", "error")
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

# ==================================================================================
from routes.ledger_module import register_ledger_routes
register_ledger_routes(admin_bp, admin_required, _get_current_admin, _parse_date_flex)

# ======================
#  AYARLAR
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
    """
    Site bazlı ayarlar:
    - Site adı (Site.name)
    - Aylık aidat tutarı (Site.monthly_dues_amount)
    Diğer yönetici/iletişim alanları şimdilik SystemSetting'te kalabilir,
    ama aidat mutlaka site bazlıdır.
    """
    admin_user = _get_current_admin()
    site_id = session.get("active_site_id") or (admin_user.site_id if admin_user else None)
    if not site_id:
        flash("Ayarlar için bir site seçmelisiniz.", "error")
        return redirect(url_for("admin.dashboard"))

    # Site kaydı
    site = Site.query.get(site_id)
    if not site:
        flash("Site bulunamadı.", "error")
        return redirect(url_for("admin.dashboard"))

    # Diğer (global) ayarlar sende kullanılıyorsa koruyalım:
    try:
        settings_obj = SystemSetting.get_singleton()
    except SQLAlchemyError as exc:
        current_app.logger.exception("Ayarlar alınamadı: %s", exc)
        settings_obj = None

    if request.method == "POST":
        site_name = (request.form.get("site_name") or "").strip()
        monthly_dues_amount = (request.form.get("default_monthly_dues_amount") or "").strip()

        # (Opsiyonel) global alanlar
        address = (request.form.get("address") or "").strip()
        manager_name = (request.form.get("manager_name") or "").strip()
        manager_phone = (request.form.get("manager_phone") or "").strip()
        manager_email = (request.form.get("manager_email") or "").strip()

        try:
            # ✅ Site adı site tablosuna
            if site_name:
                site.name = site_name

            # ✅ Site aidat tutarı site tablosuna
            if monthly_dues_amount != "":
                # virgül yazılırsa düzelt
                val = Decimal(monthly_dues_amount.replace(",", "."))
                if val < 0:
                    raise ValueError("Aidat tutarı negatif olamaz.")
                if hasattr(site, "monthly_dues_amount"):
                    site.monthly_dues_amount = val
                else:
                    # Site modelinde alan yoksa kırılmasın
                    # (İstersen burada flash da atabilirsin)
                    pass


            # Global alanlar (kullanıyorsan)
            if settings_obj:
                settings_obj.address = address or None
                settings_obj.manager_name = manager_name or None
                settings_obj.manager_phone = manager_phone or None
                settings_obj.manager_email = manager_email or None

            db.session.commit()

            # ✅ Session isim güncellemesi (sidebar/topbar anında güncellensin)
            session["active_site_name"] = site.name
            session["site_name"] = site.name

            flash("Site ayarları kaydedildi.", "success")
        except (ValueError, SQLAlchemyError) as exc:
            db.session.rollback()
            current_app.logger.exception("Site ayarları kaydedilemedi: %s", exc)
            flash("Ayarlar kaydedilirken bir hata oluştu.", "error")

    return render_template(
        "admin/ayarlar.html",
        settings=settings_obj,
        site=site,
    )
# ============================= ne lazım ========================================
def _get_active_site_id_for_user(user: Optional[User]) -> Optional[int]:
    # 1) Session'dan
    site_id = session.get("active_site_id")
    if site_id:
        return int(site_id)

    # 2) Kullanıcı site_id
    if user and getattr(user, "site_id", None):
        return int(user.site_id)

    # 3) get_current_site fallback (session'ı da dolduruyor)
    site = get_current_site()
    return int(site.id) if site else None

@admin_bp.route("/ne-lazim", methods=["GET"])
@admin_required
def ne_lazim():
    admin_user = _get_current_admin()
    site_id = _get_active_site_id_for_user(admin_user)
    if not site_id:
        flash("Bu sayfayı görmek için aktif bir site seçili olmalı.", "error")
        return redirect(url_for("admin.dashboard"))

    items = (
        NeedItem.query
        .filter_by(site_id=site_id, is_active=True)
        .order_by(NeedItem.sort_order.asc(), NeedItem.id.desc())
        .all()
    )

    return render_template(
        "ne_lazim.html",
        items=items,
        active_site_name=session.get("active_site_name"),
    )
@admin_bp.route("/ne-lazim/manage", methods=["GET"])
@admin_required
def ne_lazim_manage():
    if not _require_super_admin():
        flash("Bu sayfayı sadece Süper Admin görüntüleyebilir.", "error")
        return redirect(url_for("admin.ne_lazim"))

    sites = Site.query.order_by(Site.name.asc()).all()
    if not sites:
        flash("Önce en az 1 site oluşturmalısınız.", "error")
        return redirect(url_for("admin.dashboard"))

    selected_site_id = request.args.get("site_id", type=int) or sites[0].id

    items = (
        NeedItem.query
        .filter_by(site_id=selected_site_id)
        .order_by(NeedItem.sort_order.asc(), NeedItem.id.desc())
        .all()
    )

    items_json = [
        {
            "id": it.id,
            "title": it.title,
            "category": it.category or "",
            "company_name": it.company_name or "",
            "sort_order": it.sort_order or 0,
            "address": it.address or "",
            "phone": it.phone or "",
            "email": it.email or "",
            "website": it.website or "",
            "image_url": it.image_url or "",
            "description": it.description or "",
            "is_active": bool(it.is_active),
        }
        for it in items
    ]

    return render_template(
        "admin/ne_lazim_manage.html",
        sites=sites,
        selected_site_id=selected_site_id,
        items=items,
        items_json=items_json,
    )



@admin_bp.route("/ne-lazim/save", methods=["POST"])
@admin_required
def ne_lazim_save():
    if not _require_super_admin():
        flash("Bu işlemi sadece Süper Admin yapabilir.", "error")
        return redirect(url_for("admin.ne_lazim"))

    site_id = request.form.get("site_id", type=int)
    if not site_id:
        flash("Site seçimi zorunlu.", "error")
        return redirect(url_for("admin.ne_lazim_manage"))

    item_id = request.form.get("item_id", type=int)
    title = (request.form.get("title") or "").strip()
    if not title:
        flash("Başlık zorunlu.", "error")
        return redirect(url_for("admin.ne_lazim_manage", site_id=site_id))

    def _s(v): return (v or "").strip() or None

    is_active = (request.form.get("is_active") or "1") == "1"
    sort_order = request.form.get("sort_order", type=int) or 0

    try:
        if item_id:
            it = NeedItem.query.get(item_id)
            if not it:
                flash("Kayıt bulunamadı.", "error")
                return redirect(url_for("admin.ne_lazim_manage", site_id=site_id))
            it.site_id = site_id
        else:
            it = NeedItem(site_id=site_id)
            db.session.add(it)

        it.title = title
        it.category = _s(request.form.get("category"))
        it.company_name = _s(request.form.get("company_name"))
        it.address = _s(request.form.get("address"))
        it.phone = _s(request.form.get("phone"))
        it.email = _s(request.form.get("email"))
        it.website = _s(request.form.get("website"))
        it.image_url = _s(request.form.get("image_url"))
        it.description = _s(request.form.get("description"))
        it.is_active = is_active
        it.sort_order = sort_order

        db.session.commit()
        flash("Kaydedildi.", "success")

    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Ne Lazım kaydetme hatası: %s", exc)
        flash("Kaydedilirken hata oluştu.", "error")

    return redirect(url_for("admin.ne_lazim_manage", site_id=site_id))


@admin_bp.route("/ne-lazim/<int:item_id>/delete", methods=["POST"])
@admin_required
def ne_lazim_delete(item_id: int):
    if not _require_super_admin():
        flash("Bu işlemi sadece Süper Admin yapabilir.", "error")
        return redirect(url_for("admin.ne_lazim"))

    site_id = request.form.get("site_id", type=int)

    try:
        it = NeedItem.query.get(item_id)
        if not it:
            flash("Kayıt bulunamadı.", "error")
            return redirect(url_for("admin.ne_lazim_manage", site_id=site_id))

        db.session.delete(it)
        db.session.commit()
        flash("Silindi.", "success")

    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Ne Lazım silme hatası: %s", exc)
        flash("Silinirken hata oluştu.", "error")

    return redirect(url_for("admin.ne_lazim_manage", site_id=site_id))
