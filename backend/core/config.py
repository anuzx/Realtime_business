from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Database
    DATABASE_URL: str = "postgresql+pg8000://postgres:mysecretpassword@localhost:5432/postgres"

    # JWT
    SECRET_KEY: str = "change-me-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # Kafka
    KAFKA_BOOTSTRAP_SERVERS: str = "localhost:9092"
    KAFKA_LOGS_TOPIC: str = "raw_logs"        # company → API → here
    KAFKA_ALERTS_TOPIC: str = "alerts"         # worker → here → WebSocket
    KAFKA_GROUP_ID: str = "securelog-workers"

    class Config:
        env_file = ".env"


settings = Settings()