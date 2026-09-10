"""
Alerts API.

Read endpoints (list/get) stay public. The status-transition endpoint
requires authentication (Phase 2) - the audit trail's actor is now the
verified logged-in username, never a client-supplied string. The
assignment endpoint (Phase 3) follows the same rule: authenticated only,
actor always derived server-side. The IP-reputation endpoint (Phase 4)
follows it too - see app.services.threat_intel for the AbuseIPDB lookup
itself, which is fetched on demand and never persisted on the alert.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user
from app.database.postgres import get_db
from app.models.alert import Alert
from app.models.audit_log import AuditEntityType
from app.models.user import User
from app.schemas import AlertStatusTransitionRequest, AssignmentRequest
from app.services import audit as audit_service
from app.services import threat_intel
from app.services.status_transitions import ALERT_LIFECYCLE_ORDER, is_forward_or_reopen

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"])

_UNASSIGNED = "unassigned"


def _serialize(alert: Alert) -> dict:
    return {
        "id": alert.id,
        "event_type": alert.event_type,
        "description": alert.description,
        "severity": alert.severity.value,
        "status": alert.status.value,
        "source_type": alert.source_type,
        "source_ip": alert.source_ip,
        "destination_ip": alert.destination_ip,
        "es_index": alert.es_index,
        "es_doc_id": alert.es_doc_id,
        "mitre_tactic": alert.mitre_tactic,
        "mitre_technique": alert.mitre_technique,
        "incident_id": alert.incident_id,
        "assigned_user_id": alert.assigned_user_id,
        "assigned_username": alert.assigned_user.username if alert.assigned_user else None,
        "created_at": alert.created_at.isoformat() if alert.created_at else None,
        "updated_at": alert.updated_at.isoformat() if alert.updated_at else None,
    }


@router.get("")
def list_alerts(db: Session = Depends(get_db)):
    """Return all alerts, most recent first."""
    alerts = db.query(Alert).order_by(Alert.created_at.desc()).all()
    return [_serialize(a) for a in alerts]


@router.get("/{alert_id}")
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    """Return a single alert by id, or 404 if it doesn't exist."""
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    return _serialize(alert)


@router.patch("/{alert_id}/status")
def update_alert_status(
    alert_id: int,
    payload: AlertStatusTransitionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Transition an alert's status. Only the next step in the alert
    lifecycle (open -> acknowledged -> closed) or a reopen back to
    "open" from any later state is allowed; every successful transition
    is recorded in the audit log under the authenticated user's identity.
    """
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")

    from_status = alert.status.value
    to_status = payload.to_status.value

    if from_status == to_status:
        raise HTTPException(
            status_code=400,
            detail=f"Alert {alert_id} already has status '{to_status}'",
        )

    if not is_forward_or_reopen(ALERT_LIFECYCLE_ORDER, from_status, to_status):
        raise HTTPException(
            status_code=400,
            detail=(
                f"Cannot move Alert {alert_id} from '{from_status}' to '{to_status}'. "
                "Only the next lifecycle step or reopening to 'open' is allowed."
            ),
        )

    alert.status = payload.to_status

    audit_service.record(
        db,
        entity_type=AuditEntityType.alert,
        entity_id=alert.id,
        from_status=from_status,
        to_status=to_status,
        actor=current_user.username,
        note=payload.note,
    )

    db.commit()
    db.refresh(alert)
    return _serialize(alert)


@router.post("/{alert_id}/reputation")
def check_alert_ip_reputation(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Check the alert's source IP against AbuseIPDB (Phase 4). Authenticated
    only - no anonymous lookups, no client-supplied IP or actor: the
    target IP always comes from the alert's own `source_ip` column, and
    the audit actor is always the verified logged-in username.

    Always returns 200 with a `status` field describing the outcome (see
    app.services.threat_intel.get_ip_reputation for the full list) -
    a missing source IP, a private IP, an unconfigured/unreachable
    provider, etc. are all legitimate, successfully-handled outcomes of
    "we tried to check", not request errors. Only a nonexistent alert or
    missing authentication is a transport-level error (404/401).

    An audit entry is written whenever a real IP was actually considered
    (i.e. not for the "no_source_ip" case, where nothing was queried) -
    it records that a lookup was requested and its outcome, never the
    raw AbuseIPDB response or the API key.
    """
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")

    ip = alert.source_ip
    if not ip:
        result = {
            "status": "no_source_ip",
            "detail": "This alert has no recorded source IP.",
            "reputation": None,
        }
    else:
        result = threat_intel.get_ip_reputation(ip)

    if result["status"] != "no_source_ip":
        note = f"Checked AbuseIPDB reputation for {ip}: status={result['status']}"
        if result["status"] == "ok":
            note += f", abuse_confidence_score={result['reputation']['abuse_confidence_score']}"

        audit_service.record(
            db,
            entity_type=AuditEntityType.alert,
            entity_id=alert.id,
            from_status="ip_reputation",
            to_status="checked",
            actor=current_user.username,
            note=note,
        )
        db.commit()

    return {"alert_id": alert.id, "source_ip": ip, **result}


@router.patch("/{alert_id}/assignment")
def update_alert_assignment(
    alert_id: int,
    payload: AssignmentRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Assign (or unassign, when `username` is omitted/null) an alert to an
    existing user. Authenticated only - no anonymous assignment. Reuses
    the existing audit_logs table/service exactly as-is: from/to hold the
    previous/new assignee (a username, or "unassigned"), same shape as a
    status-transition audit row, so AuditTrail.jsx already renders it
    correctly with no changes needed there.
    """
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")

    if payload.username is None:
        target_user = None
    else:
        target_user = db.query(User).filter(User.username == payload.username).first()
        if target_user is None:
            raise HTTPException(
                status_code=404, detail=f"User '{payload.username}' not found"
            )

    from_assignee = alert.assigned_user.username if alert.assigned_user else _UNASSIGNED
    to_assignee = target_user.username if target_user else _UNASSIGNED

    if from_assignee == to_assignee:
        raise HTTPException(
            status_code=400,
            detail=f"Alert {alert_id} is already assigned to '{from_assignee}'"
            if target_user
            else f"Alert {alert_id} is already unassigned",
        )

    alert.assigned_user_id = target_user.id if target_user else None

    audit_service.record(
        db,
        entity_type=AuditEntityType.alert,
        entity_id=alert.id,
        from_status=from_assignee,
        to_status=to_assignee,
        actor=current_user.username,
        note=None,
    )

    db.commit()
    db.refresh(alert)
    return _serialize(alert)
