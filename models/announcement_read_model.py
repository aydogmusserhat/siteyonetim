from datetime import datetime
from models import db

class AnnouncementRead(db.Model):
    __tablename__ = "announcement_reads"

    id = db.Column(db.Integer, primary_key=True)
    site_id = db.Column(db.Integer, index=True, nullable=False)
    announcement_id = db.Column(db.Integer, index=True, nullable=False)
    user_id = db.Column(db.Integer, index=True, nullable=False)
    read_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (
        db.UniqueConstraint("announcement_id", "user_id", name="uq_announcement_read"),
    )
