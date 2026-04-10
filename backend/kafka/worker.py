"""
Kafka Worker  (runs as a background asyncio task inside the FastAPI process)

Pipeline:
  raw_logs topic
      └─► persist Log row
      └─► run anomaly detection rules
              └─► for each hit: persist Alert + WebSocket broadcast
"""
import json
import logging
import asyncio
from aiokafka import AIOKafkaConsumer
from sqlalchemy.orm import Session

from core.config import settings
from db.session import SessionLocal
from models.log import Log
from models.alert import Alert
from services.anomaly import detect
from websocket.manager import ws_manager

logger = logging.getLogger(__name__)


async def _handle_message(data: dict):
    """Process one log message end-to-end."""
    db: Session = SessionLocal()
    try:
        # 1. Persist the log row
        log = Log(
            api_key_id           = data["api_key_id"],
            actor_email          = data.get("actor_email"),
            actor_id             = data.get("actor_id"),
            actor_role           = data.get("actor_role"),
            event_type           = data["event_type"],
            resource             = data.get("resource"),
            action_count         = data.get("action_count", 1),
            ip_address           = data.get("ip_address"),
            location             = data.get("location"),
            user_agent           = data.get("user_agent"),
            occurred_at          = data.get("occurred_at"),
            endpoint             = data.get("endpoint"),
            method               = data.get("method"),
            status_code          = data.get("status_code"),
            response_time_ms     = data.get("response_time_ms"),
            privilege_escalation = data.get("privilege_escalation", False),
            severity             = data.get("severity", "low"),
            meta_data             = json.dumps(data.get("metadata")) if data.get("metadata") else None,
        )
        db.add(log)
        db.commit()
        db.refresh(log)
        logger.info("Persisted log id=%s event=%s", log.id, log.event_type)

        # 2. Run all detection rules
        hits = detect(data)

        # 3. For each rule hit → persist Alert + WebSocket push
        for hit in hits:
            alert = Alert(
                log_id     = log.id,
                api_key_id = log.api_key_id,
                severity   = hit["severity"],
                title      = hit["title"],
                message    = hit["message"],
            )
            db.add(alert)
            db.commit()
            db.refresh(alert)
            logger.info("Alert created id=%s title=%s", alert.id, alert.title)

            # ── Real-time push to dashboard ───────────────────────────────────
            await ws_manager.broadcast(
                log.api_key_id,
                {
                    "type": "new_alert",
                    "data": {
                        "id":         alert.id,
                        "log_id":     alert.log_id,
                        "severity":   alert.severity,
                        "title":      alert.title,
                        "message":    alert.message,
                        "resolved":   alert.resolved,
                        "created_at": alert.created_at.isoformat(),
                    },
                },
            )

    except Exception as exc:
        db.rollback()
        logger.error("Worker failed for message: %s | error: %s", data, exc)
    finally:
        db.close()


async def run_worker():
    """Long-running coroutine — start as asyncio.create_task() in lifespan."""
    consumer = AIOKafkaConsumer(
        settings.KAFKA_LOGS_TOPIC,
        bootstrap_servers=settings.KAFKA_BOOTSTRAP_SERVERS,
        group_id=settings.KAFKA_GROUP_ID,
        value_deserializer=lambda v: json.loads(v.decode("utf-8")),
        auto_offset_reset="earliest",
    )

    await consumer.start()
    logger.info("Worker listening on topic '%s'", settings.KAFKA_LOGS_TOPIC)

    try:
        async for msg in consumer:
            await _handle_message(msg.value)
    except asyncio.CancelledError:
        logger.info("Worker shutting down…")
    finally:
        await consumer.stop()