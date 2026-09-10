"""
FastAPI application entrypoint.

App instance, config, and DB connections (Postgres + Elasticsearch), APIs
for alerts/incidents/audit/auth, and the automatic detection/correlation
scheduler's startup/shutdown lifecycle (see app.scheduler).
"""

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.alerts import router as alerts_router
from app.api.audit import router as audit_router
from app.api.auth import router as auth_router
from app.api.health import router as health_router
from app.api.incidents import router as incidents_router
from app.scheduler import lifespan

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

app = FastAPI(
    title="Threat Hunting & Security Monitoring Platform",
    version="0.2.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health_router)
app.include_router(alerts_router)
app.include_router(incidents_router)
app.include_router(audit_router)
app.include_router(auth_router)


@app.get("/")
def root():
    return {"message": "Threat Hunting Platform API is running"}
