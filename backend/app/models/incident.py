"""
Incident model.

An incident groups one or more related alerts under a single case that
analysts investigate and resolve. The correlation stage (not built yet)
will be responsible for deciding when alerts get grouped into an incident;
this only defines the storage shape.
"""

import enum
from datetime import datetime

from sqlalchemy import String, Text, DateTime, Enum, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.database.base import Base


class IncidentSeverity(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class IncidentStatus(str, enum.Enum):
    open = "open"
    investigating = "investigating"
    resolved = "resolved"
    closed = "closed"


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(primary_key=True)

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    severity: Mapped[IncidentSeverity] = mapped_column(
        Enum(IncidentSeverity, native_enum=False, length=20),
        default=IncidentSeverity.medium,
        nullable=False,
    )
    status: Mapped[IncidentStatus] = mapped_column(
        Enum(IncidentStatus, native_enum=False, length=20),
        default=IncidentStatus.open,
        nullable=False,
    )

    # Assigned analyst (Phase 3). Nullable - most incidents start
    # unassigned. Column added to the live DB via database/migrate.py's
    # idempotent ADD COLUMN IF NOT EXISTS (same pattern as Alert's
    # mitre_tactic/mitre_technique) - the ForeignKey here is ORM-level
    # metadata only, used for the assigned_user relationship/join; the
    # API layer (see api/incidents.py) validates the target username
    # actually exists in `users` before assigning.
    assigned_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )
    assigned_user: Mapped["User"] = relationship()

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    alerts: Mapped[list["Alert"]] = relationship(back_populates="incident")
