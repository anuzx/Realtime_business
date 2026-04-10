from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional

from api.deps import get_db
from models.alert import Alert
from models.api_key import APIKey
from models.user import User
from schemas.alert import AlertResponse

router = APIRouter(prefix="/alerts", tags=["Alerts"])


def _get_key_ids(user_email: str, db: Session) -> List[str]:
    user = db.query(User).filter(User.email == user_email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return [k.id for k in db.query(APIKey).filter(APIKey.user_id == user.id).all()]


@router.get("/", response_model=List[AlertResponse])
def list_alerts(
    user_email: str,
    severity: Optional[str] = Query(None, pattern="^(low|medium|high|critical)$"),
    resolved: Optional[bool] = None,
    limit: int = Query(50, le=200),
    offset: int = 0,
    db: Session = Depends(get_db),
):
    """GET /alerts?severity=high  — list alerts, filterable by severity & resolved status."""
    key_ids = _get_key_ids(user_email, db)

    q = db.query(Alert).filter(Alert.api_key_id.in_(key_ids))

    if severity:
        q = q.filter(Alert.severity == severity)
    if resolved is not None:
        q = q.filter(Alert.resolved == resolved)

    return q.order_by(Alert.created_at.desc()).offset(offset).limit(limit).all()


@router.get("/{alert_id}", response_model=AlertResponse)
def get_alert(alert_id: str, user_email: str, db: Session = Depends(get_db)):
    """GET /alerts/:id — fetch a single alert."""
    key_ids = _get_key_ids(user_email, db)

    alert = (
        db.query(Alert)
        .filter(Alert.id == alert_id, Alert.api_key_id.in_(key_ids))
        .first()
    )
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    return alert


@router.patch("/{alert_id}/resolve", response_model=AlertResponse)
def resolve_alert(alert_id: str, user_email: str, db: Session = Depends(get_db)):
    """Mark an alert as resolved."""
    key_ids = _get_key_ids(user_email, db)

    alert = (
        db.query(Alert)
        .filter(Alert.id == alert_id, Alert.api_key_id.in_(key_ids))
        .first()
    )
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.resolved = True
    db.commit()
    db.refresh(alert)
    return alert