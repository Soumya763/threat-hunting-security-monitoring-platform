"""
Persistence helpers for analyses: owner-scoped queries, serialisation,
notes, incident links, and audit entries.

Every read and write takes the requesting user's id. A record that belongs to
another user is reported as not found, not as forbidden, so the API does not
reveal which analysis ids exist.
"""

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.config import settings
from app.models.analysis import Analysis, AnalysisIncidentLink, AnalysisNote
from app.models.audit_log import AuditEntityType
from app.services import audit as audit_service

SORT_FIELDS = {"created_at": Analysis.created_at, "risk_score": Analysis.risk_score}
KINDS = ("file", "url", "indicator")
RISK_LEVELS = ("clean", "low", "medium", "high", "critical", "insufficient_evidence")


def create_analysis(db: Session, *, owner_id: int, kind: str, indicator_type: str,
                    indicator_value: str, display_name: str | None = None,
                    sha256: str | None = None, file_size: int | None = None,
                    quarantine_key: str | None = None,
                    retention_until: datetime | None = None) -> Analysis:
    row = Analysis(
        owner_id=owner_id,
        kind=kind,
        indicator_type=indicator_type,
        indicator_value=indicator_value,
        display_name=display_name,
        sha256=sha256,
        file_size=file_size,
        quarantine_key=quarantine_key,
        retention_until=retention_until,
        status="queued",
    )
    db.add(row)
    db.flush()
    return row


def get_owned(db: Session, analysis_id: int, owner_id: int) -> Analysis | None:
    return db.scalar(select(Analysis).where(Analysis.id == analysis_id, Analysis.owner_id == owner_id))


def list_owned(db: Session, owner_id: int, *, kind: str | None = None, risk: str | None = None,
               q: str | None = None, sort: str = "created_at", order: str = "desc",
               page: int = 1, page_size: int = 20) -> tuple[list[Analysis], int]:
    stmt = select(Analysis).where(Analysis.owner_id == owner_id)
    if kind:
        stmt = stmt.where(Analysis.kind == kind)
    if risk:
        stmt = stmt.where(Analysis.risk_level == risk)
    if q:
        pattern = f"%{q.strip()[:200]}%"
        stmt = stmt.where(or_(
            Analysis.indicator_value.ilike(pattern),
            Analysis.display_name.ilike(pattern),
            Analysis.sha256.ilike(pattern),
        ))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0

    column = SORT_FIELDS.get(sort, Analysis.created_at)
    column = column.asc() if order == "asc" else column.desc()
    stmt = stmt.order_by(column, Analysis.id.desc()).offset((page - 1) * page_size).limit(page_size)
    return list(db.scalars(stmt)), total


def summary(row: Analysis) -> dict[str, Any]:
    result = row.result or {}
    return {
        "id": row.id,
        "kind": row.kind,
        "indicator_type": row.indicator_type,
        "indicator_value": row.indicator_value,
        "display_name": row.display_name,
        "status": row.status,
        "risk_level": row.risk_level,
        "risk_score": row.risk_score,
        "risk_label": result.get("classification_label"),
        "sha256": row.sha256,
        "file_size": row.file_size,
        "detected_type": row.detected_type,
        "file_available": bool(row.quarantine_key),
        "external_submitted": row.external_submission_at is not None,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "completed_at": row.completed_at.isoformat() if row.completed_at else None,
        "error": row.error,
    }


def detail(row: Analysis) -> dict[str, Any]:
    return {
        **summary(row),
        "retention_until": row.retention_until.isoformat() if row.retention_until else None,
        "file_purged_at": row.file_purged_at.isoformat() if row.file_purged_at else None,
        "external_submission_at": row.external_submission_at.isoformat() if row.external_submission_at else None,
        "result": row.result,
    }


def list_notes(db: Session, analysis_id: int) -> list[AnalysisNote]:
    return list(db.scalars(select(AnalysisNote).where(AnalysisNote.analysis_id == analysis_id)
                            .order_by(AnalysisNote.created_at.asc())))


def add_note(db: Session, analysis: Analysis, author_id: int, content: str) -> AnalysisNote:
    note = AnalysisNote(analysis_id=analysis.id, author_id=author_id, content=content)
    db.add(note)
    db.flush()
    return note


def links_for(db: Session, analysis_id: int) -> list[AnalysisIncidentLink]:
    return list(db.scalars(select(AnalysisIncidentLink).where(AnalysisIncidentLink.analysis_id == analysis_id)))


def audit(db: Session, analysis_id: int, actor: str, action: str, note: str | None = None) -> None:
    """Analysis audit entries reuse the shared audit_logs table: from/to hold the action."""
    audit_service.record(
        db,
        entity_type=AuditEntityType.analysis,
        entity_id=analysis_id,
        from_status="analysis",
        to_status=action[:20],
        actor=actor,
        note=note[:2000] if note else None,
    )


def retention_deadline() -> datetime:
    return datetime.now(timezone.utc) + timedelta(hours=settings.file_retention_hours)
