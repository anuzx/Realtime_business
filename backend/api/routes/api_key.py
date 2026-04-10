from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session
from typing import List
from pydantic import BaseModel

from api.deps import get_db, get_current_user
from models.api_key import APIKey
from models.user import User
from schemas.api_key import APIKeyResponse

router = APIRouter(tags=["API Keys"])


class CreateAPIKeyBody(BaseModel):
    name: str | None = None


def _create_key_for_user(user: User, db: Session) -> APIKey:
    api_key = APIKey(user_id=user.id)
    db.add(api_key)
    db.commit()
    db.refresh(api_key)
    return api_key


@router.post("/generate", response_model=APIKeyResponse, status_code=201)
def generate_api_key(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return _create_key_for_user(current_user, db)


@router.post("", response_model=APIKeyResponse, status_code=status.HTTP_201_CREATED)
def create_api_key(
    _: CreateAPIKeyBody | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return _create_key_for_user(current_user, db)


@router.get("", response_model=List[APIKeyResponse])
def list_api_keys(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return db.query(APIKey).filter(APIKey.user_id == current_user.id).all()


@router.delete("/{key_id}", status_code=204)
def revoke_api_key(
    key_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    api_key = (
        db.query(APIKey)
        .filter(APIKey.id == key_id, APIKey.user_id == current_user.id)
        .first()
    )
    if api_key:
        api_key.is_active = False
        db.commit()

    return None
