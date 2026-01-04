from decimal import Decimal
from models import db


class SystemSetting(db.Model):
    __tablename__ = "system_settings"

    id = db.Column(db.Integer, primary_key=True)
    # Varsayılan aylık aidat tutarı (ör: 1000.00)
    default_monthly_dues_amount = db.Column(db.Numeric(10, 2), nullable=False, default=Decimal("1000.00"))

    @classmethod
    def get_singleton(cls):
        """
        Uygulama için tek bir ayar satırı kullanıyoruz.
        Yoksa oluşturup döner.
        """
        obj = cls.query.get(1)
        if not obj:
            obj = cls(id=1, default_monthly_dues_amount=Decimal("1000.00"))
            db.session.add(obj)
            db.session.commit()
        return obj
