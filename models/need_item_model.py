# models/need_item_model.py
from datetime import datetime
from models import db

class NeedItem(db.Model):
    __tablename__ = "need_items"

    id = db.Column(db.Integer, primary_key=True)

    # Her kayıt bir siteye bağlı
    site_id = db.Column(db.Integer, db.ForeignKey("sites.id"), nullable=False, index=True)

    title = db.Column(db.String(160), nullable=False)              # İlan başlığı
    description = db.Column(db.Text, nullable=True)                # kısa açıklama

    # Görsel (küçük kartta sol tarafta)
    image_url = db.Column(db.String(500), nullable=True)

    # Firma bilgileri
    company_name = db.Column(db.String(160), nullable=True)
    category = db.Column(db.String(80), nullable=True)             # örn: Market / Kuaför / Eczane
    address = db.Column(db.String(300), nullable=True)

    # İletişim
    phone = db.Column(db.String(50), nullable=True)
    email = db.Column(db.String(120), nullable=True)
    website = db.Column(db.String(200), nullable=True)

    # Liste kontrol
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    sort_order = db.Column(db.Integer, default=0, nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # İstersen ilişkisel erişim:
    site = db.relationship("Site", backref=db.backref("need_items", lazy="dynamic"))
