from werkzeug.security import generate_password_hash, check_password_hash
from models import db


class User(db.Model):
    """
    Kullanıcı modeli:
    - super_admin / admin / resident rolü
    - admin ise site_id ile bir siteye bağlanır
    - resident ise apartment_id ile bir daireye bağlanabilir
    """
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)

    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    phone = db.Column(db.String(32), nullable=True)

    password_hash = db.Column(db.String(255), nullable=False)

    # super_admin | admin | resident
    role = db.Column(db.String(20), nullable=False, default="resident")

    # Kullanıcının bağlı olduğu site (admin / resident için)
    site_id = db.Column(db.Integer, db.ForeignKey("sites.id"), nullable=True)

    # Sakinin bağlı olduğu daire
    apartment_id = db.Column(
        db.Integer,
        db.ForeignKey("apartments.id"),
        nullable=True,
    )

    is_active = db.Column(db.Boolean, default=True, nullable=False)

    # -------------------
    # Şifre yardımcıları
    # -------------------
    def set_password(self, password: str) -> None:
        """Şifreyi güvenli şekilde hash'ler."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        """Girilen şifreyi hash ile karşılaştırır."""
        return check_password_hash(self.password_hash, password)

    # -------------------
    # Rol yardımcıları
    # -------------------
    @property
    def is_super_admin(self) -> bool:
        return self.role == "super_admin"

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    @property
    def is_resident(self) -> bool:
        return self.role == "resident"

    def __repr__(self) -> str:
        return (
            f"<User id={self.id} email={self.email!r} "
            f"role={self.role} site_id={self.site_id}>"
        )
