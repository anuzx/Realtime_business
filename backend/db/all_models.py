# db/all_models.py
from db.base import Base  # noqa: F401

# Import every model here — this ensures SQLAlchemy registers
# each table exactly once, no matter how many routes import them
from models.user import User        # noqa: F401
from models.api_key import APIKey   # noqa: F401
from models.log import Log          # noqa: F401
from models.alert import Alert      # noqa: F401