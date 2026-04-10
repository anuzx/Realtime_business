import json
import logging
from aiokafka import AIOKafkaProducer
from core.config import settings


logger = logging.getLogger(__name__)

_producer: AIOKafkaProducer | None = None


async def get_producer() -> AIOKafkaProducer:
    global _producer
    if _producer is None:
        _producer = AIOKafkaProducer(
            bootstrap_servers=settings.KAFKA_BOOTSTRAP_SERVERS,
            value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
        )
        await _producer.start()
        logger.info("Kafka producer started")
    return _producer


async def stop_producer():
    global _producer
    if _producer:
        await _producer.stop()
        _producer = None
        logger.info("Kafka producer stopped")


async def publish_log(topic: str, data: dict):
    """Publish a message. Returns True on success, False on failure."""
    try:
        producer = await get_producer()
        await producer.send_and_wait(topic, data)
        return True
    except Exception as exc:
        logger.error("Kafka publish error topic=%s: %s", topic, exc)
        return False
