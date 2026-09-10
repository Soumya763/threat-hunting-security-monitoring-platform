"""
Audit log read API.

Requires authentication (Phase 2) - the audit trail reveals analyst
identities and actions, unlike the plain alert/incident/health reads
which stay public. The only place audit_logs rows get written is inside
the alert/incident status-transition endpoints (api/alerts.py,
api/incidents.py) via app.services.audit.record().
"""

from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user
from app.database.postgres import get_db
from app.models.audit_log import AuditEntityType, AuditLog
from app.models.user import User
from app.services import audit as audit_service

router = APIRouter(prefix="/api/v1/audit-logs", tags=["audit"])


def _serialize(entry: AuditLog) -> dict:
    return {
        "id": entry.id,
        "entity_type": entry.entity_type.value,
        "entity_id": entry.entity_id,
        "from_status": entry.from_status,
        "to_status": entry.to_status,
        "actor": entry.actor,
        "note": entry.note,
        "created_at": entry.created_at.isoformat() if entry.created_at else None,
    }


@router.get("")
def list_audit_logs(
    entity_type: Optional[AuditEntityType] = Query(default=None),
    entity_id: Optional[int] = Query(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Return audit log entries, most recent first. Optionally filtered to
    a single entity (e.g. ?entity_type=alert&entity_id=5) or a single
    entity type (?entity_type=incident); with no filters, returns the
    most recent entries across both alerts and incidents. Requires a
    logged-in user.
    """
    entries = audit_service.list_entries(db, entity_type=entity_type, entity_id=entity_id)
    return [_serialize(e) for e in entries]
