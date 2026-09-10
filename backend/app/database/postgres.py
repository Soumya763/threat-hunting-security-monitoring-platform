"""
SQLAlchemy engine/session setup for Postgres.

No models are defined yet — this only provides the connection plumbing
(engine, session factory, and a FastAPI dependency) that later stages
(detection, correlation, incidents, etc.) will build models on top of.
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from app.config import settings

engine = create_engine(settings.postgres_url, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Session:
    """FastAPI dependency that yields a DB session and closes it after use."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
