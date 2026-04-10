from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional

from api.deps import get_current_user, get_db
from models.alert import Alert
from models.api_key import APIKey
from models.user import User
from schemas.alert import AlertResponse

router = APIRouter(prefix="/alerts", tags=["Alerts"])


def _get_key_ids(user_id: str, db: Session) -> List[str]:
    return [k.id for k in db.query(APIKey).filter(APIKey.user_id == user_id).all()]


@router.get("", response_model=List[AlertResponse])
def list_alerts(
    current_user: User = Depends(get_current_user),
    severity: Optional[str] = Query(None, pattern="^(low|medium|high|critical)$"),
    resolved: Optional[bool] = None,
    limit: int = Query(50, le=200),
    offset: int = 0,
    db: Session = Depends(get_db),
):
    key_ids = _get_key_ids(current_user.id, db)
    if not key_ids:
        return []

    q = db.query(Alert).filter(Alert.api_key_id.in_(key_ids))

    if severity:
        q = q.filter(Alert.severity == severity)
    if resolved is not None:
        q = q.filter(Alert.resolved == resolved)

    return q.order_by(Alert.created_at.desc()).offset(offset).limit(limit).all()


@router.get("/{alert_id}", response_model=AlertResponse)
def get_alert(
    alert_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    key_ids = _get_key_ids(current_user.id, db)

    alert = (
        db.query(Alert)
        .filter(Alert.id == alert_id, Alert.api_key_id.in_(key_ids))
        .first()
    )
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    return alert


@router.patch("/{alert_id}/resolve", response_model=AlertResponse)
@router.patch("/{alert_id}", response_model=AlertResponse)
def resolve_alert(
    alert_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    key_ids = _get_key_ids(current_user.id, db)

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
