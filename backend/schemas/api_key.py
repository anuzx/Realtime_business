from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime

class APIKeyResponse(BaseModel):
    id: str
    key: str
    is_active: bool
    created_at: datetime
 
    class Config:
        from_attributes = True