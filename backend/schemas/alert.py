# schemas/alert.py
from pydantic import BaseModel
from datetime import datetime


class AlertResponse(BaseModel):
    id: str
    log_id: str
    api_key_id: str
    severity: str
    title: str
    message: str
    resolved: bool
    created_at: datetime

    model_config = {"from_attributes": True}