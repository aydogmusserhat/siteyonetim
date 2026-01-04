from datetime import datetime

from models import db


class Ticket(db.Model):
    """
    Talep / arıza kayıtları.
    status: open, in_progress, closed
    priority: low, normal, high
    """
    __tablename__ = "tickets"

    id = db.Column(db.Integer, primary_key=True)
    apartment_id = db.Column(db.Integer, db.ForeignKey("apartments.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)

    status = db.Column(db.String(20), nullable=False, default="open")
    priority = db.Column(db.String(20), nullable=False, default="normal")

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )
    closed_at = db.Column(db.DateTime, nullable=True)

    user = db.relationship("User", backref="tickets", lazy=True)

    def __repr__(self) -> str:
        return f"<Ticket id={self.id} status={self.status}>"
