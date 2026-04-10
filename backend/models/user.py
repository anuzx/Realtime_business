import uuid
from sqlalchemy import Column, String, DateTime, func
from db.base import Base


class User(Base):
    __tablename__ = "users"

    id            = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    company_name  = Column(String, nullable=True)
    first_name    = Column(String, nullable=True)
    last_name     = Column(String, nullable=True)   # fixed: was "lastName"
    email         = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    created_at    = Column(DateTime(timezone=True), server_default=func.now())
    updated_at    = Column(DateTime(timezone=True), onupdate=func.now())