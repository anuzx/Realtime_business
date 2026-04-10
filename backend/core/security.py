from datetime import datetime, timedelta
from typing import Optional

from jose import JWTError, jwt
import bcrypt

# ⚠️  Move SECRET_KEY to an environment variable before going to production
#     Generate one with:  openssl rand -hex 32
SECRET_KEY = "change-me-use-openssl-rand-hex-32"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

def _truncate(password: str) -> bytes:
    """Explicitly truncate to 72 bytes — bcrypt's hard limit."""
    return password.encode("utf-8")[:72]

def hash_password(password: str) -> str:
    pwd_bytes = _truncate(password)
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode('utf-8')

def verify_password(plain: str, hashed: str) -> bool:
    pwd_bytes = _truncate(plain)
    hashed_bytes = hashed.encode('utf-8')
    return bcrypt.checkpw(pwd_bytes, hashed_bytes)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    payload = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    payload["exp"] = expire
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None