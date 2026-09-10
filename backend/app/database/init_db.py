"""
Creates all tables registered on Base.metadata (currently: alerts, incidents).

Run manually with:
    python -m app.database.init_db
"""

from app.database.base import Base
from app.database.postgres import engine

# Import models so they register themselves on Base.metadata before create_all.
import app.models  # noqa: F401


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    print("Tables created:", list(Base.metadata.tables.keys()))


if __name__ == "__main__":
    init_db()
