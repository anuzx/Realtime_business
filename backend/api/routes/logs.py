import json
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime

from api.deps import get_db
from api.deps_api_key import verify_api_key
from models.user import User
from models.api_key import APIKey        
from models.log import Log
from models.alert import Alert
from schemas.log import LogIngest, LogResponse
from kafka.producer import publish_log
from core.config import settings


router = APIRouter(prefix="/logs", tags=["Logs"])


# ── POST /logs  (main ingest endpoint used by companies) ──────────────────────

@router.post("/", status_code=202)
async def ingest_log(
    payload: LogIngest,
    api_key: APIKey = Depends(verify_api_key),
):
    """
    Main endpoint. Companies send activity logs here with their API key in the
    `x-api-key` header. The log is published to Kafka immediately; the consumer
    persists it to the DB and evaluates alert rules asynchronously.
    """
    log_data = {
        **payload.model_dump(),
        "api_key_id": api_key.id,
        # serialise datetime / dict fields so Kafka can JSON-encode them
        "occurred_at": payload.occurred_at.isoformat() if payload.occurred_at else None,
        "metadata": json.dumps(payload.metadata) if payload.metadata else None,
    }

    await publish_log(settings.KAFKA_LOGS_TOPIC, log_data)

    return {"status": "accepted", "message": "Log queued for processing"}


# ── GET /logs  (UI — list logs for the logged-in company) ─────────────────────

@router.get("/", response_model=List[LogResponse])
def get_logs(
    user_email: str,
    severity: Optional[str] = Query(None, pattern="^(low|medium|high|critical)$"),
    event_type: Optional[str] = None,
    from_date: Optional[datetime] = None,
    to_date: Optional[datetime] = None,
    privilege_escalation: Optional[bool] = None,
    limit: int = Query(100, le=500),
    offset: int = 0,
    db: Session = Depends(get_db),
):
    """
    Return logs for the company's API keys.
    Supports filtering by severity, event_type, date range, and privilege flag.
    """
    

    user = db.query(User).filter(User.email == user_email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # collect all api_key ids belonging to this company
    
    key_ids = [k.id for k in db.query(APIKeyModel).filter(APIKeyModel.user_id == user.id).all()]

    q = db.query(Log).filter(Log.api_key_id.in_(key_ids))

    if severity:
        q = q.filter(Log.severity == severity)
    if event_type:
        q = q.filter(Log.event_type == event_type)
    if from_date:
        q = q.filter(Log.received_at >= from_date)
    if to_date:
        q = q.filter(Log.received_at <= to_date)
    if privilege_escalation is not None:
        q = q.filter(Log.privilege_escalation == privilege_escalation)

    return q.order_by(Log.received_at.desc()).offset(offset).limit(limit).all()


# ── GET /stats ─────────────────────────────────────────────────────────────────

@router.get("/stats")
def get_stats(user_email: str, db: Session = Depends(get_db)):
    """
    Returns { totalLogs, alerts, highRisk } for the dashboard.
    """
   

    user = db.query(User).filter(User.email == user_email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    key_ids = [k.id for k in db.query(APIKeyModel).filter(APIKeyModel.user_id == user.id).all()]

    total_logs = db.query(Log).filter(Log.api_key_id.in_(key_ids)).count()
    alerts     = db.query(Alert).filter(Alert.api_key_id.in_(key_ids)).count()
    high_risk  = (
        db.query(Alert)
        .filter(Alert.api_key_id.in_(key_ids), Alert.severity.in_(["high", "critical"]))
        .count()
    )

    return {"totalLogs": total_logs, "alerts": alerts, "highRisk": high_risk}