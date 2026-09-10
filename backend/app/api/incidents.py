"""
Incidents API.

Read endpoints (list/get) stay public. The status-transition endpoint
requires authentication (Phase 2) - the audit trail's actor is now the
verified logged-in username, never a client-supplied string. The
assignment and investigation-notes endpoints (Phase 3) follow the same
rule: authenticated only, actor/author always derived server-side.
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user
from app.database.postgres import get_db
from app.models.audit_log import AuditEntityType
from app.models.incident import Incident, IncidentStatus
from app.models.investigation_note import InvestigationNote
from app.models.user import User
from app.schemas import AssignmentRequest, IncidentStatusTransitionRequest, NoteCreateRequest
from app.services import audit as audit_service
from app.services.status_transitions import INCIDENT_LIFECYCLE_ORDER, is_forward_or_reopen

router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])

_UNASSIGNED = "unassigned"


def _serialize(incident: Incident) -> dict:
    return {
        "id": incident.id,
        "title": incident.title,
        "description": incident.description,
        "severity": incident.severity.value,
        "status": incident.status.value,
        "assigned_user_id": incident.assigned_user_id,
        "assigned_username": (
            incident.assigned_user.username if incident.assigned_user else None
        ),
        "created_at": incident.created_at.isoformat() if incident.created_at else None,
        "updated_at": incident.updated_at.isoformat() if incident.updated_at else None,
        "closed_at": incident.closed_at.isoformat() if incident.closed_at else None,
        "alert_ids": [a.id for a in incident.alerts],
    }


def _serialize_note(note: InvestigationNote) -> dict:
    return {
        "id": note.id,
        "incident_id": note.incident_id,
        "author": note.author.username,
        "content": note.content,
        "created_at": note.created_at.isoformat() if note.created_at else None,
    }


@router.get("")
def list_incidents(db: Session = Depends(get_db)):
    """Return all incidents, most recent first."""
    incidents = db.query(Incident).order_by(Incident.created_at.desc()).all()
    return [_serialize(i) for i in incidents]


@router.get("/{incident_id}")
def get_incident(incident_id: int, db: Session = Depends(get_db)):
    """Return a single incident (with linked alert ids) by id, or 404."""
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    return _serialize(incident)


@router.patch("/{incident_id}/status")
def update_incident_status(
    incident_id: int,
    payload: IncidentStatusTransitionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Transition an incident's status. Only the next step in the incident
    lifecycle (open -> investigating -> resolved -> closed) or a reopen
    back to "open" from any later state is allowed; every successful
    transition is recorded in the audit log under the authenticated
    user's identity.

    closed_at is set when the incident transitions to "closed", and
    cleared back to null if it's later reopened - it always reflects
    "currently closed since," not "was ever closed at some point." The
    full close/reopen history still lives in the audit log regardless.
    """
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    from_status = incident.status.value
    to_status = payload.to_status.value

    if from_status == to_status:
        raise HTTPException(
            status_code=400,
            detail=f"Incident {incident_id} already has status '{to_status}'",
        )

    if not is_forward_or_reopen(INCIDENT_LIFECYCLE_ORDER, from_status, to_status):
        raise HTTPException(
            status_code=400,
            detail=(
                f"Cannot move Incident {incident_id} from '{from_status}' to '{to_status}'. "
                "Only the next lifecycle step or reopening to 'open' is allowed."
            ),
        )

    was_closed = incident.status == IncidentStatus.closed
    incident.status = payload.to_status

    if payload.to_status == IncidentStatus.closed:
        incident.closed_at = datetime.now(timezone.utc)
    elif was_closed:
        incident.closed_at = None

    audit_service.record(
        db,
        entity_type=AuditEntityType.incident,
        entity_id=incident.id,
        from_status=from_status,
        to_status=to_status,
        actor=current_user.username,
        note=payload.note,
    )

    db.commit()
    db.refresh(incident)
    return _serialize(incident)


@router.patch("/{incident_id}/assignment")
def update_incident_assignment(
    incident_id: int,
    payload: AssignmentRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Assign (or unassign, when `username` is omitted/null) an incident to
    an existing user. Authenticated only - no anonymous assignment.
    Reuses the existing audit_logs table/service exactly as-is: from/to
    hold the previous/new assignee (a username, or "unassigned"), same
    shape as a status-transition audit row, so AuditTrail.jsx already
    renders it correctly with no changes needed there.
    """
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    if payload.username is None:
        target_user = None
    else:
        target_user = db.query(User).filter(User.username == payload.username).first()
        if target_user is None:
            raise HTTPException(
                status_code=404, detail=f"User '{payload.username}' not found"
            )

    from_assignee = (
        incident.assigned_user.username if incident.assigned_user else _UNASSIGNED
    )
    to_assignee = target_user.username if target_user else _UNASSIGNED

    if from_assignee == to_assignee:
        raise HTTPException(
            status_code=400,
            detail=f"Incident {incident_id} is already assigned to '{from_assignee}'"
            if target_user
            else f"Incident {incident_id} is already unassigned",
        )

    incident.assigned_user_id = target_user.id if target_user else None

    audit_service.record(
        db,
        entity_type=AuditEntityType.incident,
        entity_id=incident.id,
        from_status=from_assignee,
        to_status=to_assignee,
        actor=current_user.username,
        note=None,
    )

    db.commit()
    db.refresh(incident)
    return _serialize(incident)


@router.get("/{incident_id}/notes")
def list_incident_notes(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Return an incident's investigation notes, oldest first (a running
    case log, read top-to-bottom in the order they were written).
    Requires login, same as the audit-log endpoint - notes reveal analyst
    identity and investigative content.
    """
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    notes = (
        db.query(InvestigationNote)
        .filter(InvestigationNote.incident_id == incident_id)
        .order_by(InvestigationNote.created_at.asc())
        .all()
    )
    return [_serialize_note(n) for n in notes]


@router.post("/{incident_id}/notes")
def create_incident_note(
    incident_id: int,
    payload: NoteCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Add an investigation note to an incident. Authenticated only - no
    anonymous notes. Notes are immutable once created: there is no
    update/delete endpoint.
    """
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    note = InvestigationNote(
        incident_id=incident_id,
        author_id=current_user.id,
        content=payload.content,
    )
    db.add(note)
    db.commit()
    db.refresh(note)
    return _serialize_note(note)
