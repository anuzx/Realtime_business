from fastapi import FastAPI, APIRouter
from api.routes import auth, users, logs, alerts
from db.session import engine
from db.base import Base

from models import user


Base.metadata.create_all(bind=engine)

app = FastAPI()

api_router = APIRouter(prefix="/api")
api_router.include_router(auth.router, prefix="/auth", tags=["Auth"])
#api_router.include_router(users.router, prefix="/users", tags=["Users"])
#api_router.include_router(logs.router, prefix="/logs", tags=["Logs"])
#api_router.include_router(alerts.router, prefix="/alerts", tags=["Alerts"])

app.include_router(api_router)
