"""
Audit log model.

Records every alert/incident status transition performed through the
status-transition endpoints (api/alerts.py, api/incidents.py). One shared
table for both entity types, discriminated by entity_type/entity_id,
rather than two near-identical tables — the row shape (who, when, from
what, to what, optional note) is identical either way.

No database-level foreign key from entity_id to alerts.id/incidents.id:
a single column can't reference two different tables, and entity_type/
entity_id values only ever come from the validated status-transition
routes, so application-level correctness is sufficient here.
"""

import enum
from datetime import datetime

from sqlalchemy import DateTime, Enum, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from app.database.base import Base


class AuditEntityType(str, enum.Enum):
    alert = "alert"
    incident = "incident"


class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_logs_entity", "entity_type", "entity_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)

    entity_type: Mapped[AuditEntityType] = mapped_column(
        Enum(AuditEntityType, native_enum=False, length=20), nullable=False
    )
    entity_id: Mapped[int] = mapped_column(Integer, nullable=False)

    # Plain strings, not a shared status Enum column: AlertStatus and
    # IncidentStatus (models/alert.py, models/incident.py) are different,
    # non-overlapping enums, so no single DB enum type could represent
    # both. Values are validated against the correct per-entity enum at
    # the API layer (schemas.py) before a row is ever written here.
    from_status: Mapped[str] = mapped_column(String(20), nullable=False)
    to_status: Mapped[str] = mapped_column(String(20), nullable=False)

    # Self-reported analyst identifier. There is no authentication system
    # yet, so this is supplied by the caller in the request body rather
    # than derived from a logged-in user.
    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
