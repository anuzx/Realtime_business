from fastapi import Depends, HTTPException, Header
from sqlalchemy.orm import Session
from jose import jwt, JWTError
from db.session import SessionLocal
from core.config import settings
from models.user import User
from models.api_key import APIKey


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ── JWT auth (for dashboard users) ────────────────────────────────────────────

def get_current_user(
    authorization: str = Header(...),
    db: Session = Depends(get_db),
) -> User:
    token = authorization.removeprefix("Bearer ").strip()
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        email: str = payload.get("sub")
        if not email:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


# ── API Key auth (for company log ingestion) ───────────────────────────────────

def get_api_key(
    x_api_key: str = Header(..., alias="x-api-key"),
    db: Session = Depends(get_db),
) -> APIKey:
    key = (
        db.query(APIKey)
        .filter(APIKey.key == x_api_key, APIKey.is_active == True)  # noqa
        .first()
    )
    if not key:
        raise HTTPException(status_code=401, detail="Invalid or inactive API key")
    return key