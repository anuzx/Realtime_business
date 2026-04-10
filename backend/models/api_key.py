import uuid
import secrets
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, func
from sqlalchemy.orm import relationship
from db.base import Base


class APIKey(Base):
    __tablename__ = "api_keys"

    id         = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    key        = Column(String, unique=True, index=True, nullable=False,
                        default=lambda: f"sk_{secrets.token_urlsafe(32)}")
    user_id    = Column(String, ForeignKey("users.id"), nullable=False)
    is_active  = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User", back_populates="api_keys")