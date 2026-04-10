import uuid
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, func
from sqlalchemy.orm import relationship
from db.base import Base


class Alert(Base):
    __tablename__ = "alerts"

    id          = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    log_id      = Column(String, ForeignKey("logs.id"), nullable=False)
    api_key_id  = Column(String, ForeignKey("api_keys.id"), nullable=False)

    severity    = Column(String, nullable=False)   # low | medium | high | critical
    title       = Column(String, nullable=False)   # short label
    message     = Column(String, nullable=False)   # plain-English sentence shown in dashboard
    resolved    = Column(Boolean, default=False)

    created_at  = Column(DateTime(timezone=True), server_default=func.now())

    log     = relationship("Log")
    api_key = relationship("APIKey")