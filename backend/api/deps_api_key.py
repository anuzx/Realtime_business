from fastapi import Header, HTTPException, Depends
from sqlalchemy.orm import Session
from api.deps import get_db
from models.api_key import APIKey


async def verify_api_key(
    x_api_key: str = Header(..., alias="x-api-key"),
    db: Session = Depends(get_db),
) -> APIKey:
    api_key = (
        db.query(APIKey)
        .filter(APIKey.key == x_api_key, APIKey.is_active == True)  # noqa: E712
        .first()
    )
    if not api_key:
        raise HTTPException(status_code=401, detail="Invalid or inactive API key")
    return api_key