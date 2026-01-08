"""
Denetim İzleri ve Loglama Sistemi
audit_logging.py - Models ve yardımcı fonksiyonlar
"""

from datetime import datetime
from decimal import Decimal
from typing import Any, Optional, Dict
import json
import logging

from flask import session, request, g, current_app
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Numeric
from decimal import Decimal  # Python'un kendi Decimal'ı kullan
from sqlalchemy.orm import relationship

from models import db


# ============================================================================
#  DENETIM İZLERİ (AUDIT LOG) MODELİ
# ============================================================================

class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True)

    # Kimliklendirme
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)  # eğer user tablon 'users' ise
    user = relationship("User", foreign_keys=[user_id], lazy="joined")

    site_id = Column(Integer, ForeignKey("sites.id"), nullable=True)  # ✅ düzeltildi
    site = relationship("Site", foreign_keys=[site_id], lazy="joined")

    # İşlem Bilgileri
    action = Column(String(50), nullable=False)
    entity_type = Column(String(50), nullable=False)
    entity_id = Column(Integer, nullable=True)

    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)

    old_values = Column(Text, nullable=True)
    new_values = Column(Text, nullable=True)

    description = Column(String(255), nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    status = Column(String(20), default="success")
    error_message = Column(Text, nullable=True)


    def __repr__(self):
        return f"<AuditLog {self.id}: {self.action} {self.entity_type} by user {self.user_id}>"

    def to_dict(self):
        """Denetim kaydını sözlük olarak döndür"""
        return {
            "id": self.id,
            "user": self.user.name if self.user else "Sistem",
            "user_id": self.user_id,
            "site_id": self.site_id,
            "action": self.action,
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "ip_address": self.ip_address,
            "description": self.description,
            "old_values": json.loads(self.old_values) if self.old_values else None,
            "new_values": json.loads(self.new_values) if self.new_values else None,
            "created_at": self.created_at.strftime("%d.%m.%Y %H:%M:%S"),
            "status": self.status,
            "error_message": self.error_message,
        }


# ============================================================================
#  DENETIM İZLERİ KAYDETME FONKSİYONLARI
# ============================================================================

def get_client_ip():
    """İstemcinin IP adresini al"""
    if request.environ.get("HTTP_CF_CONNECTING_IP"):
        return request.environ.get("HTTP_CF_CONNECTING_IP")
    return request.remote_addr


def get_user_agent():
    """İstemcinin User-Agent bilgisini al"""
    return request.headers.get("User-Agent", "")[:500]


def get_current_user_id() -> Optional[int]:
    """Mevcut oturum açmış kullanıcı ID'sini al"""
    return session.get("user_id")


def log_action(
    action: str,
    entity_type: str,
    entity_id: Optional[int] = None,
    old_values: Optional[Dict[str, Any]] = None,
    new_values: Optional[Dict[str, Any]] = None,
    description: Optional[str] = None,
    site_id: Optional[int] = None,
    status: str = "success",
    error_message: Optional[str] = None,
):
    """
    Bir işlemi denetim günlüğüne kaydet.
    
    Args:
        action: İşlem türü (CREATE, UPDATE, DELETE, LOGIN, LOGOUT, etc.)
        entity_type: İşlemin hangi veri türü üzerine olduğu (User, Apartment, Bill, Payment, etc.)
        entity_id: İşlem yapılan veri kaydının ID'si
        old_values: Eski değerler (UPDATE için)
        new_values: Yeni değerler (CREATE/UPDATE için)
        description: İşlemin açıklaması
        site_id: İşlemin yapıldığı site
        status: İşlem sonucu (success/failure)
        error_message: Hata mesajı (status=failure ise)
    """
    try:
        user_id = get_current_user_id()
        site_id = site_id or session.get("active_site_id")

        # Değerleri JSON'a çevir
        old_json = json.dumps(old_values, default=str) if old_values else None
        new_json = json.dumps(new_values, default=str) if new_values else None

        audit = AuditLog(
            user_id=user_id,
            site_id=site_id,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            ip_address=get_client_ip(),
            user_agent=get_user_agent(),
            old_values=old_json,
            new_values=new_json,
            description=description,
            status=status,
            error_message=error_message,
            created_at=datetime.utcnow(),
        )

        db.session.add(audit)
        db.session.commit()

        current_app.logger.info(
            f"Denetim: {action} {entity_type} (ID: {entity_id}) "
            f"- Kullanıcı: {user_id} - Site: {site_id}"
        )

    except Exception as e:
        current_app.logger.exception(f"Denetim kaydı oluştururken hata: {e}")
        db.session.rollback()


def log_login(email: str, success: bool = True, error_msg: Optional[str] = None):
    """Giriş denemesini kaydet"""
    try:
        audit = AuditLog(
            user_id=None,  # Başlangıçta kullanıcı bilinmiyor
            action="LOGIN",
            entity_type="User",
            ip_address=get_client_ip(),
            user_agent=get_user_agent(),
            description=f"Email ile giriş: {email}",
            status="success" if success else "failure",
            error_message=error_msg,
            created_at=datetime.utcnow(),
        )
        db.session.add(audit)
        db.session.commit()
    except Exception as e:
        current_app.logger.exception(f"Giriş denetim kaydı oluştururken hata: {e}")


def log_logout():
    """Çıkış işlemini kaydet"""
    try:
        user_id = get_current_user_id()
        audit = AuditLog(
            user_id=user_id,
            action="LOGOUT",
            entity_type="User",
            ip_address=get_client_ip(),
            user_agent=get_user_agent(),
            status="success",
            created_at=datetime.utcnow(),
        )
        db.session.add(audit)
        db.session.commit()
    except Exception as e:
        current_app.logger.exception(f"Çıkış denetim kaydı oluştururken hata: {e}")


# ============================================================================
#  KOLAYLAŞTIRICI FONKSIYONLAR
# ============================================================================

def compare_values(old_obj, new_obj, fields_to_track: list) -> tuple:
    """
    İki nesne arasındaki değişiklikleri karşılaştır.
    
    Returns:
        (old_values_dict, new_values_dict)
    """
    old_values = {}
    new_values = {}

    for field in fields_to_track:
        old_val = getattr(old_obj, field, None) if old_obj else None
        new_val = getattr(new_obj, field, None) if new_obj else None

        # Decimal'leri string'e çevir (JSON serializable olmadığı için)
        if isinstance(old_val, Decimal):
            old_val = str(old_val)
        if isinstance(new_val, Decimal):
            new_val = str(new_val)

        old_values[field] = old_val
        new_values[field] = new_val

    return old_values, new_values


def get_site_id_from_obj(obj) -> Optional[int]:
    """Bir nesneden site_id'sini al"""
    if hasattr(obj, "site_id"):
        return obj.site_id
    elif hasattr(obj, "apartment") and obj.apartment:
        return obj.apartment.site_id
    elif hasattr(obj, "user") and obj.user:
        return obj.user.site_id
    return None


# ============================================================================
#  DENETIM GÜNLÜĞÜ GÖRÜNTÜLEME ROUTE'LAR (Admin için)
# ============================================================================

def register_audit_routes(app, admin_bp):
    """
    Admin blueprint'ine denetim günlüğü route'larını ekle.
    
    Kullanım:
        from audit_logging import register_audit_routes
        register_audit_routes(app, admin_bp)
    """
    from flask import render_template, request as flask_request
    from sqlalchemy.exc import SQLAlchemyError
    
    @admin_bp.route("/audit-logs", methods=["GET"])
    def view_audit_logs():
        """Denetim günlüklerini görüntüle (sadece admin)"""
        from models.user_model import User
        
        page = flask_request.args.get("page", 1, type=int) or 1
        if page < 1:
            page = 1
        
        per_page = 50
        
        # Filtreler
        entity_type = (flask_request.args.get("entity_type") or "").strip()
        action = (flask_request.args.get("action") or "").strip()
        user_id_filter = flask_request.args.get("user_id", type=int)
        
        try:
            query = AuditLog.query
            
            if entity_type:
                query = query.filter_by(entity_type=entity_type)
            if action:
                query = query.filter_by(action=action)
            if user_id_filter:
                query = query.filter_by(user_id=user_id_filter)
            
            total = query.count()
            logs = (
                query
                .order_by(AuditLog.created_at.desc())
                .offset((page - 1) * per_page)
                .limit(per_page)
                .all()
            )
            
            pages = (total + per_page - 1) // per_page if total > 0 else 1
            
            # Benzersiz entity_types ve actions
            all_entity_types = set()
            all_actions = set()
            try:
                results = db.session.query(
                    AuditLog.entity_type,
                    AuditLog.action
                ).distinct().all()
                for et, act in results:
                    if et:
                        all_entity_types.add(et)
                    if act:
                        all_actions.add(act)
            except SQLAlchemyError:
                pass
            
            return render_template(
                "admin/audit_logs.html",
                logs=logs,
                page=page,
                pages=pages,
                total=total,
                entity_type=entity_type,
                action=action,
                user_id_filter=user_id_filter,
                all_entity_types=sorted(all_entity_types),
                all_actions=sorted(all_actions),
            )
            
        except SQLAlchemyError as exc:
            from flask import flash, redirect, url_for
            current_app.logger.exception("Denetim günlükleri alınamadı: %s", exc)
            flash("Denetim günlükleri alınırken hata oluştu.", "error")
            return redirect(url_for("admin.dashboard"))
    
    @admin_bp.route("/audit-logs/<int:log_id>", methods=["GET"])
    def view_audit_log_detail(log_id: int):
        """Denetim kaydının detaylarını görüntüle"""
        try:
            log = AuditLog.query.get(log_id)
            if not log:
                from flask import flash, redirect, url_for
                flash("Denetim kaydı bulunamadı.", "error")
                return redirect(url_for("admin.view_audit_logs"))
            
            return render_template(
                "admin/audit_log_detail.html",
                log=log,
            )
        except SQLAlchemyError as exc:
            from flask import flash, redirect, url_for
            current_app.logger.exception("Denetim kaydı alınamadı: %s", exc)
            flash("Denetim kaydı alınırken hata oluştu.", "error")
            return redirect(url_for("admin.view_audit_logs"))
