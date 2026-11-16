"""
Correlation engine.

Groups open, unlinked alerts into incidents. Two alerts are related only
when BOTH hold:
  1. they were created within CORRELATION_WINDOW of each other, and
  2. they share concrete evidence: the same non-empty source_ip, or the
     same entity (same entity_type AND entity_key, e.g. the same user).

Sharing an event type is NOT evidence and no longer groups alerts. Alerts
for two different users from the same rule therefore stay separate.
Relations are transitive via union-find, so A~B and B~C put A, B and C
in one incident. Groups are bounded by the same window as each pair, so a
long chain of alerts cannot span an unbounded time range.

An open, linked incident also absorbs new alerts that share evidence with
one of its members within ATTACH_WINDOW, so one attack does not spawn a
new incident every detection cycle.

Only AlertStatus.open alerts with incident_id IS NULL are considered for
new grouping, so re-running this is safe.
"""

from datetime import datetime, timedelta, timezone
from itertools import combinations
from typing import Iterable

from app.database.postgres import SessionLocal
from app.models.alert import Alert, AlertStatus
from app.models.incident import Incident, IncidentSeverity, IncidentStatus

CORRELATION_WINDOW = timedelta(minutes=15)
ATTACH_WINDOW = timedelta(minutes=60)
_ACTIVE_INCIDENT_STATUSES = (IncidentStatus.open, IncidentStatus.investigating)

# Worst-first severity ordering, used to pick an incident's severity.
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


def shared_evidence(a: Alert, b: Alert) -> list[str]:
    """Describe the concrete evidence two alerts share (empty if none)."""
    evidence = []
    if a.source_ip and a.source_ip == b.source_ip:
        evidence.append(f"source IP {a.source_ip}")
    if (
        a.entity_type
        and a.entity_key
        and a.entity_type == b.entity_type
        and a.entity_key == b.entity_key
    ):
        evidence.append(f"{a.entity_type} {a.entity_key}")
    return evidence


def _related(a: Alert, b: Alert, window: timedelta = CORRELATION_WINDOW) -> bool:
    if abs(a.created_at - b.created_at) > window:
        return False
    return bool(shared_evidence(a, b))


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


def _group_evidence(group: list[Alert]) -> list[str]:
    found: set[str] = set()
    for i, a in enumerate(group):
        for b in group[i + 1:]:
            found.update(shared_evidence(a, b))
    return sorted(found)


def _find_open_incident_for(db, members: list[Alert]) -> Incident | None:
    """An open incident with a linked alert that shares evidence with a member."""
    cutoff = datetime.now(timezone.utc) - ATTACH_WINDOW
    linked = (
        db.query(Alert)
        .join(Incident, Alert.incident_id == Incident.id)
        .filter(Incident.status.in_(_ACTIVE_INCIDENT_STATUSES))
        .filter(Alert.created_at >= cutoff)
        .all()
    )
    for member in members:
        for candidate in linked:
            if _related(member, candidate, ATTACH_WINDOW):
                return db.get(Incident, candidate.incident_id)
    return None


def run_correlation() -> list[Incident]:
    """
    Cluster open, ungrouped alerts by shared evidence. Each cluster of 2+
    alerts becomes a new Incident, unless an open incident already holds
    related alerts, in which case the cluster is attached to that
    incident. Returns the newly created incidents.
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
        if not candidates:
            return []

        uf = _UnionFind(a.id for a in candidates)
        for a, b in combinations(candidates, 2):
            if _related(a, b):
                uf.union(a.id, b.id)

        by_id = {a.id: a for a in candidates}

        for member_ids in uf.groups().values():
            group_alerts = [by_id[i] for i in member_ids]

            target = _find_open_incident_for(db, group_alerts)
            if target is not None:
                for alert in group_alerts:
                    alert.incident_id = target.id
                continue

            if len(group_alerts) < 2:
                continue  # no evidence shared with anything: stay ungrouped

            evidence = _group_evidence(group_alerts)
            incident = Incident(
                title=_build_incident_title(group_alerts),
                description=(
                    f"Auto-correlated from {len(group_alerts)} alerts within "
                    f"{int(CORRELATION_WINDOW.total_seconds() // 60)} minutes. "
                    f"Shared evidence: {', '.join(evidence)}."
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
        print("No correlated groups found.")
    for incident in incidents:
        print(f"Incident id={incident.id} severity={incident.severity} title={incident.title!r}")
