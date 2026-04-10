# main.py
import db.all_models  

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, APIRouter
from fastapi.middleware.cors import CORSMiddleware

from kafka.worker import run_worker
from kafka.producer import stop_producer
from api.routes import auth, api_key, logs, alerts, dashboard

logging.basicConfig(level=logging.INFO)

@asynccontextmanager
async def lifespan(app: FastAPI):
    worker_task = asyncio.create_task(run_worker())
    yield
    worker_task.cancel()
    try:
        await worker_task
    except asyncio.CancelledError:
        pass
    await stop_producer()

app = FastAPI(
    title="SecureLog",
    description="Real-time security log ingestion, anomaly detection, and dashboard.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Remove the dead api_router (you created it but never used it) ─────────────
app.include_router(auth.router)
app.include_router(api_key.router)
app.include_router(logs.router)
app.include_router(alerts.router)
app.include_router(dashboard.router)


@app.get("/health", tags=["Health"])
def health():
    return {"status": "ok"}