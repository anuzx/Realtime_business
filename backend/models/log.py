from sqlalchemy import Column, String, Integer, Float
import uuid
from db.base import Base

class Log(Base):
    __tablename__ = "logs"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    event_type = Column(String)
    ip_address = Column(String)
    endpoint = Column(String)
    status_code = Column(Integer)
    response_time = Column(Float)