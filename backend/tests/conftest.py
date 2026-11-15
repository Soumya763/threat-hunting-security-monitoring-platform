"""
Shared test setup.

1. Puts `backend/` on sys.path so `from app...` imports resolve however
   pytest is invoked.
2. Provides a non-secret JWT key for the test process ONLY, so importing
   app.config (which refuses to start without a real secret) works in CI
   and locally. The value is a fixed test string, never used outside tests.
   A real JWT_SECRET_KEY in the environment still takes precedence.
3. Provides an in-memory SQLite session factory for tests that need the
   ORM (alerts, correlation, history authorisation). Production always uses
   PostgreSQL; SQLite is only a test double for model logic.
"""

import os
import sys
from pathlib import Path

_BACKEND_ROOT = str(Path(__file__).resolve().parent.parent)
if _BACKEND_ROOT not in sys.path:
    sys.path.insert(0, _BACKEND_ROOT)

os.environ.setdefault(
    "JWT_SECRET_KEY", "test-only-key-not-a-secret-0123456789abcdef0123456789"
)

import pytest  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from app.database.base import Base  # noqa: E402
import app.models  # noqa: E402,F401


@pytest.fixture()
def sqlite_session_factory():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    yield factory
    engine.dispose()
