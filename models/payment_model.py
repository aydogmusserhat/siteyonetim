from datetime import datetime
from sqlalchemy import Numeric

from models import db


class Payment(db.Model):
    """
    Ödeme hareketleri.
    method: nakit, banka, POS, online vb.
    """
    __tablename__ = "payments"

    id = db.Column(db.Integer, primary_key=True)
    bill_id = db.Column(db.Integer, db.ForeignKey("bills.id"), nullable=True)
    apartment_id = db.Column(db.Integer, db.ForeignKey("apartments.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

    amount = db.Column(Numeric(10, 2), nullable=False)
    payment_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    method = db.Column(db.String(50), nullable=True)

    user = db.relationship("User", backref="payments", lazy=True)

    def __repr__(self) -> str:
        return f"<Payment id={self.id} amount={self.amount} method={self.method}>"
