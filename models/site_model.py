from models import db


class Site(db.Model):
    """
    Site / Apartman / Site grubu

    - name        : Site adı (zorunlu, unique)
    - description : Kısa açıklama / adres
    - db_path     : İleride her site için ayrı DB dosyası kullanmak istersen burada tutulacak
    - is_active   : Aktif / pasif
    """
    __tablename__ = "sites"

    id = db.Column(db.Integer, primary_key=True)

    # Örn: "Güneş Park Evleri"
    name = db.Column(db.String(150), nullable=False, unique=True)

    # Kısa açıklama / adres
    description = db.Column(db.String(255), nullable=True)

    # İleride fiziksel olarak ayrı DB dosyası için kullanılacak.
    # Örn: instance/site_1.db
    db_path = db.Column(db.String(255), nullable=True)

    is_active = db.Column(db.Boolean, nullable=False, default=True)

    # Bu siteye bağlı kullanıcılar (admin + resident)
    users = db.relationship("User", backref="site", lazy="dynamic")

    def __repr__(self) -> str:
        return f"<Site id={self.id} name={self.name!r}>"
