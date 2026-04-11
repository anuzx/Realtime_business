from fastapi import APIRouter

from core.config import settings

router = APIRouter(prefix="/env", tags=["Environment"])


def _mask_secret(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"


@router.get("")
def get_environment():
    return {
        "DATABASE_URL": _mask_secret(settings.DATABASE_URL),
        "SECRET_KEY": _mask_secret(settings.SECRET_KEY),
        "ALGORITHM": settings.ALGORITHM,
        "ACCESS_TOKEN_EXPIRE_MINUTES": settings.ACCESS_TOKEN_EXPIRE_MINUTES,
        "KAFKA_BOOTSTRAP_SERVERS": settings.KAFKA_BOOTSTRAP_SERVERS,
        "KAFKA_LOGS_TOPIC": settings.KAFKA_LOGS_TOPIC,
        "KAFKA_ALERTS_TOPIC": settings.KAFKA_ALERTS_TOPIC,
        "KAFKA_GROUP_ID": settings.KAFKA_GROUP_ID,
    }
