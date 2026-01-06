from models import db


class Apartment(db.Model):
    """Daire (blok, kat, numara, m², sahibi vb)."""
    __tablename__ = "apartments"

    id = db.Column(db.Integer, primary_key=True)

    # Bu dairenin bağlı olduğu site
    site_id = db.Column(db.Integer, db.ForeignKey("sites.id"), nullable=False)

    block = db.Column(db.String(50), nullable=False)
    floor = db.Column(db.String(20), nullable=False)
    number = db.Column(db.String(20), nullable=False)
    area_m2 = db.Column(db.Float, nullable=True)

    owner_name = db.Column(db.String(120))
    owner_phone = db.Column(db.String(32))
    notes = db.Column(db.Text)

    # User.apartment_id -> apartments.id üzerinden ilişki
    users = db.relationship("User", backref="apartment", lazy="dynamic")

    # İleride kullanacağımız ilişkiler
    bills = db.relationship("Bill", backref="apartment", lazy="dynamic")
    payments = db.relationship("Payment", backref="apartment", lazy="dynamic")
    tickets = db.relationship("Ticket", backref="apartment", lazy="dynamic")

    def __repr__(self) -> str:
        return (
            f"<Apartment id={self.id} site_id={self.site_id} "
            f"{self.block}-{self.floor}-{self.number}>"
        )
