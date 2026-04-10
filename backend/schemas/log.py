from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime


class LogIngest(BaseModel):
    """Schema companies POST to /logs"""
    event_type: str = Field(..., examples=["login", "logout", "privilege_escalation"])
    actor_email: Optional[str] = None
    actor_id: Optional[str] = None
    ip_address: Optional[str] = None
    location: Optional[str] = None
    user_agent: Optional[str] = None
    endpoint: Optional[str] = None
    method: Optional[str] = None
    status_code: Optional[int] = None
    response_time_ms: Optional[float] = None
    privilege_escalation: bool = False
    severity: str = Field(default="low", pattern="^(low|medium|high|critical)$")
    metadata: Optional[dict] = None
    occurred_at: Optional[datetime] = None
 
 
class LogResponse(BaseModel):
    id: str
    api_key_id: str
    event_type: str
    actor_email: Optional[str]
    actor_id: Optional[str]
    ip_address: Optional[str]
    location: Optional[str]
    user_agent: Optional[str]
    endpoint: Optional[str]
    method: Optional[str]
    status_code: Optional[int]
    response_time_ms: Optional[float]
    privilege_escalation: bool
    severity: str
    metadata: Optional[str]
    occurred_at: Optional[datetime]
    received_at: datetime
 
    class Config:
        from_attributes = True