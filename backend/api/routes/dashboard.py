from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect, Query
from sqlalchemy.orm import Session
from typing import Optional

from api.deps import get_db, get_current_user
from models.log import Log
from models.alert import Alert
from models.api_key import APIKey
from models.user import User
from schemas.stats import StatsResponse
from websocket.manager import ws_manager

router = APIRouter(tags=["Dashboard"])


# ── GET /stats ─────────────────────────────────────────────────────────────────
@router.get("/stats", response_model=StatsResponse)
def get_stats(
    current_user: User = Depends(get_current_user),
    db: Session        = Depends(get_db),
):
    """
    Returns { total_logs, alerts, high_risk } for the dashboard header cards.
    Matches the design from the spec:
        { "totalLogs": 1000, "alerts": 25, "highRisk": 5 }
    """
    key_ids = [k.id for k in
               db.query(APIKey).filter(APIKey.user_id == current_user.id).all()]

    total_logs = db.query(Log).filter(Log.api_key_id.in_(key_ids)).count()
    alerts     = db.query(Alert).filter(Alert.api_key_id.in_(key_ids)).count()
    high_risk  = (
        db.query(Alert)
        .filter(Alert.api_key_id.in_(key_ids),
                Alert.severity.in_(["high", "critical"]),
                Alert.resolved == False)  # noqa
        .count()
    )

    return StatsResponse(total_logs=total_logs, alerts=alerts, high_risk=high_risk)


# ── WebSocket /ws/{api_key_id} ─────────────────────────────────────────────────
@router.websocket("/ws/{api_key_id}")
async def websocket_endpoint(
    websocket: WebSocket,
    api_key_id: str,
    db: Session = Depends(get_db),
):
    """
    Real-time dashboard connection.

    The frontend connects once:
        const ws = new WebSocket("ws://host/ws/<api_key_id>")

    The worker broadcasts to this room whenever a new alert fires.
    Message format:
        {
          "type": "new_alert",
          "data": { id, severity, title, message, resolved, created_at }
        }

    On connect we also send a "connected" ACK with current room size.
    """
    # Validate api_key exists
    key = db.query(APIKey).filter(APIKey.id == api_key_id,
                                  APIKey.is_active == True).first()  # noqa
    if not key:
        await websocket.close(code=4001)
        return

    await ws_manager.connect(websocket, api_key_id)

    # Send connection ACK
    await websocket.send_json({
        "type": "connected",
        "data": {
            "api_key_id":  api_key_id,
            "room_size":   ws_manager.room_size(api_key_id),
            "message":     "Connected to real-time alert stream",
        },
    })

    try:
        # Keep the socket alive; client can send pings if desired
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        await ws_manager.disconnect(websocket, api_key_id)