from pydantic import BaseModel, EmailStr, field_validator


class RegisterSchema(BaseModel):
    companyName: str | None = None
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


class UserProfile(BaseModel):
    id: str
    email: EmailStr
    first_name: str | None = None
    last_name: str | None = None
    company_name: str | None = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserProfile
    api_key: str
