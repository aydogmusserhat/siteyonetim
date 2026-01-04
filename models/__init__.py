from flask_sqlalchemy import SQLAlchemy

# Uygulama genelinde kullanılacak SQLAlchemy örneği
db = SQLAlchemy()

# Modelleri burada import ederek metadata'nın hepsinden haberdar olmasını sağlıyoruz.
# Bu importlar dairesel import hatası vermez; çünkü modeller sadece `db` yi kullanıyor.
from .user_model import User  # noqa: F401
from .apartment_model import Apartment  # noqa: F401
from .bill_model import Bill  # noqa: F401
from .payment_model import Payment  # noqa: F401
from .announcement_model import Announcement  # noqa: F401
from .ticket_model import Ticket  # noqa: F401
