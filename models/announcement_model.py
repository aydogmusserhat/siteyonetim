from datetime import datetime

from models import db


class Announcement(db.Model):
    """
    Duyuru / mesaj panosu.
    target: all, admins, block_A vb. basit string.
    """
    __tablename__ = "announcements"

    id = db.Column(db.Integer, primary_key=True)

    # Hangi siteye ait
    site_id = db.Column(db.Integer, db.ForeignKey("sites.id"), nullable=False)

    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    target = db.Column(db.String(50), nullable=False, default="all")

    author = db.relationship("User", backref="announcements", lazy=True)

    def __repr__(self) -> str:
        return f"<Announcement id={self.id} site_id={self.site_id} title={self.title!r}>"
