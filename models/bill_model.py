from datetime import datetime
from sqlalchemy import Numeric

from models import db


class Bill(db.Model):
    """
    Aidat / borç kaydı.
    status: open, partial, paid
    type: aidat, elektrik, su, ekstra vb.
    """
    __tablename__ = "bills"

    id = db.Column(db.Integer, primary_key=True)

    # Hangi siteye ait
    site_id = db.Column(db.Integer, db.ForeignKey("sites.id"), nullable=False)

    apartment_id = db.Column(db.Integer, db.ForeignKey("apartments.id"), nullable=False)
    description = db.Column(db.String(255), nullable=True)
    amount = db.Column(Numeric(10, 2), nullable=False)
    due_date = db.Column(db.Date, nullable=True)

    status = db.Column(db.String(20), nullable=False, default="open")
    type = db.Column(db.String(50), nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    # Ödemeler
    payments = db.relationship("Payment", backref="bill", lazy="dynamic")

    def __repr__(self) -> str:
        return (
            f"<Bill id={self.id} site_id={self.site_id} "
            f"apartment_id={self.apartment_id} amount={self.amount}>"
        )
