from pydantic import BaseModel, EmailStr, field_validator
from typing import Optional


class RegisterSchema(BaseModel):
    companyName: Optional[str] = None
    firstName: str
    lastName: str
    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def password_length(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        if len(v) > 72:
            raise ValueError("Password cannot be longer than 72 characters")
        return v


class LoginSchema(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"