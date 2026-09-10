"""
Investigation note model.

A persistent, analyst-authored note attached to an Incident (Phase 3:
SOC Analyst Investigation Workflow). Distinct from AuditLog: audit_logs
records status/assignment *transitions* the system enforces; notes are
free-form investigative findings an analyst chooses to record, with no
lifecycle of their own beyond being created.

Immutable by construction - there is no update/delete endpoint for these
rows (see api/incidents.py), so no updated_at column is needed here.

Uses the existing `users` table for authorship (author_id -> User.id) per
the Phase 3 requirement to not introduce a separate analyst table.
"""

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.database.base import Base


class InvestigationNote(Base):
    __tablename__ = "investigation_notes"

    id: Mapped[int] = mapped_column(primary_key=True)

    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.id"), nullable=False, index=True
    )
    author_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # No back-reference on Incident (mirrors AuditLog's convention of not
    # adding a relationship on the alert/incident side) - notes are
    # queried directly by incident_id (see api/incidents.py).
    author: Mapped["User"] = relationship()
