"""
Pydantic request schemas.

Only request bodies use Pydantic here - API responses keep the project's
existing hand-written `_serialize(obj) -> dict` convention already used
in api/alerts.py and api/incidents.py, rather than introducing a second,
competing serialization approach.

`actor` is intentionally NOT a client-supplied field here (Phase 1 had
it as free text; Phase 2 adds real authentication). Once a request is
authenticated, the audit trail's "who" comes from the verified
current_user, never from a string the caller could set to anything -
see app.auth.dependencies.get_current_user and its use in api/alerts.py
/api/incidents.py.
"""

from pydantic import BaseModel, Field

from app.models.alert import AlertStatus
from app.models.incident import IncidentStatus


class AlertStatusTransitionRequest(BaseModel):
    to_status: AlertStatus
    note: str | None = Field(default=None, max_length=2000)


class IncidentStatusTransitionRequest(BaseModel):
    to_status: IncidentStatus
    note: str | None = Field(default=None, max_length=2000)


class AssignmentRequest(BaseModel):
    """
    Shared by both alert and incident assignment endpoints (Phase 3).
    `username` identifies an existing row in the `users` table - the API
    layer looks it up and 404s if it doesn't exist (see api/alerts.py /
    api/incidents.py). Omitting the field, or passing it as null,
    unassigns.
    """

    username: str | None = Field(default=None, min_length=1, max_length=255)


class NoteCreateRequest(BaseModel):
    """Investigation note body (Phase 3, incidents only)."""

    content: str = Field(min_length=1, max_length=4000)
