from fastapi import FastAPI
from api.routes import auth, users, logs, alerts, dashboard

from db.session import engine
from db.base import Base

Base.metadata.create_all(bind=engine)

app = FastAPI()

app.include_router(auth.router, prefix="/auth", tags=["Auth"])
app.include_router(users.router, prefix="/users", tags=["Users"])
app.include_router(logs.router, prefix="/logs", tags=["Logs"])
app.include_router(alerts.router, prefix="/alerts", tags=["Alerts"])
app.include_router(dashboard.router, prefix="/dashboard", tags=["Dashboard"])
