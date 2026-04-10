from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List

from api.deps import get_db
from models.api_key import APIKey
from models.user import User
from schemas.api_key import APIKeyResponse

router = APIRouter(prefix="/apikey", tags=["API Keys"])


@router.post("/generate", response_model=APIKeyResponse, status_code=201)
def generate_api_key(user_email: str, db: Session = Depends(get_db)):
    """
    Generate a new API key for the authenticated company.
    Called right after sign-up / sign-in.
    """
    user = db.query(User).filter(User.email == user_email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    api_key = APIKey(user_id=user.id)
    db.add(api_key)
    db.commit()
    db.refresh(api_key)

    return api_key


@router.get("/", response_model=List[APIKeyResponse])
def list_api_keys(user_email: str, db: Session = Depends(get_db)):
    """Return all API keys belonging to the company."""
    user = db.query(User).filter(User.email == user_email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return db.query(APIKey).filter(APIKey.user_id == user.id).all()


@router.delete("/{key_id}", status_code=204)
def revoke_api_key(key_id: str, user_email: str, db: Session = Depends(get_db)):
    """Revoke (deactivate) an API key."""
    user = db.query(User).filter(User.email == user_email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    api_key = (
        db.query(APIKey)
        .filter(APIKey.id == key_id, APIKey.user_id == user.id)
        .first()
    )
    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")

    api_key.is_active = False
    db.commit()