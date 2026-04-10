from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from schemas.auth import RegisterSchema, LoginSchema, TokenResponse
from models.user import User
from models.api_key import APIKey
from core.security import hash_password, verify_password, create_access_token
from api.deps import get_db, get_current_user

router = APIRouter()


@router.get("/me")
def get_me(current_user: User = Depends(get_current_user)):
    """Return the currently authenticated user's profile."""
    return {
        "id": current_user.id,
        "email": current_user.email,
        "first_name": current_user.first_name,
        "last_name": current_user.last_name,
        "company_name": current_user.company_name,
    }


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

    api_key = APIKey(user_id=new_user.id)
    db.add(api_key)
    db.commit()
    db.refresh(api_key)

    return {
        "msg": "Account created successfully.",
        "user_id": new_user.id,
        "api_key": api_key.key,
    }


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

    api_key = (
        db.query(APIKey)
        .filter(APIKey.user_id == user.id, APIKey.is_active == True)  # noqa: E712
        .order_by(APIKey.created_at.asc())
        .first()
    )

    if not api_key:
        api_key = APIKey(user_id=user.id)
        db.add(api_key)
        db.commit()
        db.refresh(api_key)

    return TokenResponse(
        access_token=token,
        user={
            "id": user.id,
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "company_name": user.company_name,
        },
        api_key=api_key.key,
    )
