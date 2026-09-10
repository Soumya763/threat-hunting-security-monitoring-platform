"""
Health check endpoint.

Verifies the backend process is up and can reach Postgres and
Elasticsearch — useful for confirming the foundation is wired correctly
before building detection/correlation logic on top of it.
"""

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.database.postgres import get_db
from app.database.elasticsearch import es_client

router = APIRouter()


@router.get("/health")
def health_check(db: Session = Depends(get_db)):
    status = {"api": "ok", "postgres": "unknown", "elasticsearch": "unknown"}

    try:
        db.execute(text("SELECT 1"))
        status["postgres"] = "ok"
    except Exception as exc:
        status["postgres"] = f"error: {exc}"

    try:
        status["elasticsearch"] = "ok" if es_client.ping() else "unreachable"
    except Exception as exc:
        status["elasticsearch"] = f"error: {exc}"

    return status
