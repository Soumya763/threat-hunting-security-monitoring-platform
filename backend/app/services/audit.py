"""
Audit-log write/read helper used by the alert and incident status-
transition endpoints (api/alerts.py, api/incidents.py) and the read-only
audit API (api/audit.py).
"""

from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.audit_log import AuditEntityType, AuditLog


def record(
    db: Session,
    *,
    entity_type: AuditEntityType,
    entity_id: int,
    from_status: str,
    to_status: str,
    actor: str,
    note: str | None = None,
) -> AuditLog:
    """
    Stage (but do not commit) a new audit log row. The caller is expected
    to commit once, together with the entity status change itself, so
    the mutation and its audit entry land in the same transaction.
    """
    entry = AuditLog(
        entity_type=entity_type,
        entity_id=entity_id,
        from_status=from_status,
        to_status=to_status,
        actor=actor,
        note=note,
    )
    db.add(entry)
    db.flush()
    return entry


def list_entries(
    db: Session,
    entity_type: Optional[AuditEntityType] = None,
    entity_id: Optional[int] = None,
    limit: int = 500,
) -> list[AuditLog]:
    """Most-recent-first audit entries, optionally filtered by entity."""
    stmt = select(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit)

    if entity_type is not None:
        stmt = stmt.where(AuditLog.entity_type == entity_type)
    if entity_id is not None:
        stmt = stmt.where(AuditLog.entity_id == entity_id)

    return list(db.scalars(stmt))
