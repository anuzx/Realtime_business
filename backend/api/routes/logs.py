from datetime import datetime
from typing import Optional
import json

from fastapi import APIRouter, Depends, Query
from sqlalchemy import or_
from sqlalchemy.orm import Session

from api.deps import get_current_user, get_db
from api.deps_api_key import verify_api_key
from core.config import settings
from db.session import SessionLocal
from kafka.producer import publish_log
from models.alert import Alert
from models.api_key import APIKey
from models.log import Log
from models.user import User
from schemas.log import LogIngest, LogResponse
from services.anomaly import detect
from websocket.manager import ws_manager

router = APIRouter(prefix="/logs", tags=["Logs"])


def _get_company_key_ids(user_id: str, db: Session) -> list[str]:
    return [k.id for k in db.query(APIKey).filter(APIKey.user_id == user_id).all()]


def _to_log_response(log: Log) -> dict:
    return {
        "id": log.id,
        "api_key_id": log.api_key_id,
        "event_type": log.event_type,
        "actor_email": log.actor_email,
        "actor_id": log.actor_id,
        "ip_address": log.ip_address,
        "location": log.location,
        "user_agent": log.user_agent,
        "endpoint": log.endpoint,
        "method": log.method,
        "status_code": log.status_code,
        "response_time_ms": log.response_time_ms,
        "privilege_escalation": log.privilege_escalation,
        "severity": log.severity,
        "metadata": log.meta_data,
        "occurred_at": log.occurred_at,
        "received_at": log.received_at,
    }


@router.post("", status_code=202)
async def ingest_log(payload: LogIngest, api_key: APIKey = Depends(verify_api_key)):
    log_data = {
        **payload.model_dump(),
        "api_key_id": api_key.id,
        "occurred_at": payload.occurred_at.isoformat() if payload.occurred_at else None,
    }

    published = await publish_log(settings.KAFKA_LOGS_TOPIC, log_data)

    if published:
        return {"status": "accepted", "message": "Log queued for processing"}

    db = SessionLocal()
    try:
        log = Log(
            api_key_id=api_key.id,
            actor_email=payload.actor_email,
            actor_id=payload.actor_id,
            event_type=payload.event_type,
            ip_address=payload.ip_address,
            location=payload.location,
            user_agent=payload.user_agent,
            endpoint=payload.endpoint,
            method=payload.method,
            status_code=payload.status_code,
            response_time_ms=payload.response_time_ms,
            privilege_escalation=payload.privilege_escalation,
            severity=payload.severity,
            meta_data=json.dumps(payload.metadata) if payload.metadata else None,
            occurred_at=payload.occurred_at,
        )
        db.add(log)
        db.commit()
        db.refresh(log)

        for hit in detect(log_data):
            alert = Alert(
                log_id=log.id,
                api_key_id=log.api_key_id,
                severity=hit["severity"],
                title=hit["title"],
                message=hit["message"],
            )
            db.add(alert)
            db.commit()
            db.refresh(alert)
            await ws_manager.broadcast(
                log.api_key_id,
                {
                    "type": "new_alert",
                    "data": {
                        "id": alert.id,
                        "log_id": alert.log_id,
                        "severity": alert.severity,
                        "title": alert.title,
                        "message": alert.message,
                        "resolved": alert.resolved,
                        "created_at": alert.created_at.isoformat()
                        if alert.created_at
                        else None,
                    },
                },
            )
    finally:
        db.close()

    return {"status": "accepted", "message": "Log ingested directly"}


@router.get("", response_model=list[LogResponse])
def get_logs(
    current_user: User = Depends(get_current_user),
    severity: Optional[str] = Query(None, pattern="^(low|medium|high|critical)$"),
    event_type: Optional[str] = None,
    from_date: Optional[datetime] = None,
    to_date: Optional[datetime] = None,
    privilege_escalation: Optional[bool] = None,
    q: Optional[str] = None,
    limit: int = Query(100, le=500),
    offset: int = 0,
    db: Session = Depends(get_db),
):
    key_ids = _get_company_key_ids(current_user.id, db)
    if not key_ids:
        return []

    query = db.query(Log).filter(Log.api_key_id.in_(key_ids))

    if severity:
        query = query.filter(Log.severity == severity)
    if event_type:
        query = query.filter(Log.event_type == event_type)
    if from_date:
        query = query.filter(Log.received_at >= from_date)
    if to_date:
        query = query.filter(Log.received_at <= to_date)
    if privilege_escalation is not None:
        query = query.filter(Log.privilege_escalation == privilege_escalation)
    if q and q.strip():
        term = f"%{q.strip()}%"
        query = query.filter(
            or_(
                Log.event_type.ilike(term),
                Log.actor_email.ilike(term),
                Log.endpoint.ilike(term),
                Log.ip_address.ilike(term),
                Log.location.ilike(term),
            )
        )

    logs = query.order_by(Log.received_at.desc()).offset(offset).limit(limit).all()
    return [_to_log_response(log) for log in logs]


@router.get("/stats")
def get_stats(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    key_ids = _get_company_key_ids(current_user.id, db)
    if not key_ids:
        return {"total_logs": 0, "alerts": 0, "high_risk": 0}

    total_logs = db.query(Log).filter(Log.api_key_id.in_(key_ids)).count()
    alerts = db.query(Alert).filter(Alert.api_key_id.in_(key_ids)).count()
    high_risk = (
        db.query(Alert)
        .filter(Alert.api_key_id.in_(key_ids), Alert.severity.in_(["high", "critical"]))
        .count()
    )

    return {"total_logs": total_logs, "alerts": alerts, "high_risk": high_risk}
