from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime

class StatsResponse(BaseModel):
    total_logs: int
    alerts: int
    high_risk: int