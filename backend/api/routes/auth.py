from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from schemas.auth import RegisterSchema, LoginSchema, TokenResponse
from models.user import User
from core.security import hash_password, verify_password, create_access_token
from api.deps import get_db

router = APIRouter()


@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(data: RegisterSchema, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == data.email).first():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists.",
        )

    new_user = User(
        company_name=data.companyName,
        first_name=data.firstName,
        last_name=data.lastName,
        email=data.email,
        password_hash=hash_password(data.password),
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {"msg": "Account created successfully.", "user_id": new_user.id}


@router.post("/login", response_model=TokenResponse)
def login(data: LoginSchema, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email).first()

    # Unified message — don't reveal whether the email exists
    if not user or not verify_password(data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token({"sub": user.email, "user_id": user.id})
    return TokenResponse(access_token=token)