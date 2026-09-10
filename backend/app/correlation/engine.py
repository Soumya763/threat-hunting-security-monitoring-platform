"""
Correlation engine.

Groups related, ungrouped, open alerts into incidents. For now, two alerts
are considered related when they share the same source_ip OR the same
event_type, and were created within 15 minutes of each other. Relations
are transitive (if A relates to B and B relates to C, all three land in
the same incident) via a union-find over the candidate alerts.

Only considers alerts that are still AlertStatus.open and not yet linked
to an incident (incident_id IS NULL), so re-running this repeatedly is
safe and won't disturb alerts already triaged into an incident.
"""

from datetime import timedelta
from itertools import combinations
from typing import Iterable

from app.database.postgres import SessionLocal
from app.models.alert import Alert, AlertStatus
from app.models.incident import Incident, IncidentSeverity, IncidentStatus

CORRELATION_WINDOW = timedelta(minutes=15)

# Worst-first severity ordering, used to pick an incident's severity from
# whichever correlated alert is most severe.
_SEVERITY_ORDER = ["critical", "high", "medium", "low"]


class _UnionFind:
    """Minimal union-find over a fixed set of alert ids."""

    def __init__(self, ids: Iterable[int]):
        self._parent = {i: i for i in ids}

    def find(self, i: int) -> int:
        while self._parent[i] != i:
            self._parent[i] = self._parent[self._parent[i]]
            i = self._parent[i]
        return i

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self._parent[rb] = ra

    def groups(self) -> dict[int, list[int]]:
        result: dict[int, list[int]] = {}
        for i in self._parent:
            result.setdefault(self.find(i), []).append(i)
        return result


def _related(a: Alert, b: Alert) -> bool:
    """
    Two alerts are related if they were created within CORRELATION_WINDOW
    of each other AND (share a non-null source_ip OR share event_type).
    """
    if abs(a.created_at - b.created_at) > CORRELATION_WINDOW:
        return False

    same_source_ip = a.source_ip is not None and a.source_ip == b.source_ip
    same_event_type = a.event_type == b.event_type

    return same_source_ip or same_event_type


def _incident_severity(alerts: list[Alert]) -> IncidentSeverity:
    """Use the most severe correlated alert's severity for the incident."""
    for level in _SEVERITY_ORDER:
        for alert in alerts:
            if alert.severity.value == level:
                return IncidentSeverity(level)
    return IncidentSeverity.medium


def _build_incident_title(alerts: list[Alert]) -> str:
    event_types = sorted({a.event_type for a in alerts})
    label = event_types[0] if len(event_types) == 1 else f"{len(event_types)} related alert types"
    return f"Correlated incident: {label} ({len(alerts)} alerts)"


def run_correlation() -> list[Incident]:
    """
    Fetch open, ungrouped alerts, cluster related ones, and create an
    Incident (linking each member alert via incident_id) for every
    cluster of 2 or more alerts. Returns the newly created incidents.
    """
    db = SessionLocal()
    created: list[Incident] = []

    try:
        candidates = (
            db.query(Alert)
            .filter(Alert.status == AlertStatus.open)
            .filter(Alert.incident_id.is_(None))
            .all()
        )

        if len(candidates) < 2:
            return []

        uf = _UnionFind(a.id for a in candidates)
        for a, b in combinations(candidates, 2):
            if _related(a, b):
                uf.union(a.id, b.id)

        by_id = {a.id: a for a in candidates}

        for member_ids in uf.groups().values():
            if len(member_ids) < 2:
                continue  # no correlation found, leave the alert ungrouped

            group_alerts = [by_id[i] for i in member_ids]

            incident = Incident(
                title=_build_incident_title(group_alerts),
                description=(
                    f"Auto-correlated from {len(group_alerts)} alerts sharing "
                    f"source_ip or event_type within "
                    f"{int(CORRELATION_WINDOW.total_seconds() // 60)} minutes."
                ),
                severity=_incident_severity(group_alerts),
                status=IncidentStatus.open,
            )
            db.add(incident)
            db.flush()  # assigns incident.id so alerts can link to it

            for alert in group_alerts:
                alert.incident_id = incident.id

            created.append(incident)

        db.commit()
        for incident in created:
            db.refresh(incident)
    finally:
        db.close()

    return created


if __name__ == "__main__":
    incidents = run_correlation()
    if not incidents:
        print("No correlated groups found (need 2+ open, ungrouped alerts that match).")
    for incident in incidents:
        print(f"Incident id={incident.id} severity={incident.severity} title={incident.title!r}")
