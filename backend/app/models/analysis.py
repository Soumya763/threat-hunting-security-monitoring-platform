"""
Analysis-history models (PostgreSQL).

analyses            One row per file, URL or indicator-search request. The
                    full, already-normalised result lives in `result` (JSON).
                    Files are referenced by quarantine key only; file bytes
                    are never stored in the database.
analysis_notes      Analyst notes attached to an analysis (immutable once written).
analysis_incident_links  Many-to-many link between an analysis and an incident.
intel_cache         Normalised provider responses with expiry (short-lived cache).

Ownership: every analysis has owner_id. Reads and writes are scoped to the
owner in api/analysis.py, so one user cannot open another user's records.
"""

from datetime import datetime

from sqlalchemy import (
    JSON,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.database.base import Base


class Analysis(Base):
    __tablename__ = "analyses"
    __table_args__ = (
        Index("ix_analyses_owner_created", "owner_id", "created_at"),
        Index("ix_analyses_owner_kind", "owner_id", "kind"),
        Index("ix_analyses_risk_level", "risk_level"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)

    # "file" | "url" | "indicator"
    kind: Mapped[str] = mapped_column(String(20), nullable=False)
    # file: "file"; url: "url"; indicator: "ip" | "domain" | "md5" | "sha1" | "sha256" | "url"
    indicator_type: Mapped[str] = mapped_column(String(20), nullable=False)
    # URL, IP, domain, hash, or the file's SHA-256 for file analyses.
    indicator_value: Mapped[str] = mapped_column(String(2048), nullable=False, index=True)
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # "queued" | "running" | "complete" | "partial" | "failed"
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="queued", index=True)
    # "clean" | "low" | "medium" | "high" | "critical" | "insufficient_evidence"
    risk_level: Mapped[str | None] = mapped_column(String(30), nullable=True)
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)

    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    file_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    detected_type: Mapped[str | None] = mapped_column(String(50), nullable=True)

    # Quarantine key (random name, not the user's file name). Null once purged.
    quarantine_key: Mapped[str | None] = mapped_column(String(80), nullable=True)
    file_purged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    retention_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Set when an analyst explicitly consents to send the file to a provider.
    external_submission_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    owner: Mapped["User"] = relationship()


class AnalysisNote(Base):
    __tablename__ = "analysis_notes"

    id: Mapped[int] = mapped_column(primary_key=True)
    analysis_id: Mapped[int] = mapped_column(ForeignKey("analyses.id"), nullable=False, index=True)
    author_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    author: Mapped["User"] = relationship()


class AnalysisIncidentLink(Base):
    __tablename__ = "analysis_incident_links"
    __table_args__ = (UniqueConstraint("analysis_id", "incident_id", name="uq_analysis_incident"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    analysis_id: Mapped[int] = mapped_column(ForeignKey("analyses.id"), nullable=False, index=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), nullable=False, index=True)
    linked_by_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class IntelCache(Base):
    __tablename__ = "intel_cache"
    __table_args__ = (
        UniqueConstraint("provider", "indicator_type", "indicator", name="uq_intel_cache_key"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    provider: Mapped[str] = mapped_column(String(40), nullable=False)
    indicator_type: Mapped[str] = mapped_column(String(20), nullable=False)
    indicator: Mapped[str] = mapped_column(String(2048), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)


__all__ = [
    "Analysis",
    "AnalysisNote",
    "AnalysisIncidentLink",
    "IntelCache",
]
