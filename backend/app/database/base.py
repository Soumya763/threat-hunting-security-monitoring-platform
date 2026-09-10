"""
Shared SQLAlchemy declarative base.

All ORM models (alerts, incidents, and whatever future stages add) inherit
from this so they share one metadata object for table creation.
"""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass
