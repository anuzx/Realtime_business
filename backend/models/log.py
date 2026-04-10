import uuid
from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, ForeignKey, func
from sqlalchemy.orm import relationship
from db.base import Base


class Log(Base):
    __tablename__ = "logs"

    id                   = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    api_key_id           = Column(String, ForeignKey("api_keys.id"), nullable=False)

    # WHO
    actor_email          = Column(String, nullable=True)
    actor_id             = Column(String, nullable=True)
    actor_role           = Column(String, nullable=True)   # e.g. "admin", "user"

    # WHAT
    event_type           = Column(String, nullable=False)  # login | logout | download | role_change | etc.
    resource             = Column(String, nullable=True)   # file name, endpoint, channel…
    action_count         = Column(Integer, default=1)      # e.g. number of files downloaded

    # WHERE / WHEN
    ip_address           = Column(String, nullable=True)
    location             = Column(String, nullable=True)
    user_agent           = Column(String, nullable=True)
    occurred_at          = Column(DateTime(timezone=True), nullable=True)  # client-supplied
    received_at          = Column(DateTime(timezone=True), server_default=func.now())

    # HTTP details (optional)
    endpoint             = Column(String, nullable=True)
    method               = Column(String, nullable=True)
    status_code          = Column(Integer, nullable=True)
    response_time_ms     = Column(Float, nullable=True)

    # RISK
    privilege_escalation = Column(Boolean, default=False)
    severity             = Column(String, default="low")   # low | medium | high | critical

    # Extra JSON payload stored as string
    meta_data             = Column(String, nullable=True)

    api_key = relationship("APIKey")