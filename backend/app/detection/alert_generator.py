"""
Alert generator.

Evaluates a rule's Elasticsearch aggregation response (as returned by
app.detection.executor.execute_rule) against the rule's `threshold`, and
writes an Alert row to PostgreSQL for each match that isn't a recent
duplicate. Uses the existing Alert model and DB session as-is - no schema
changes beyond the alert's own mitre_tactic/mitre_technique columns. This
only creates alerts; it does not schedule runs (see app.scheduler),
expose an API, correlate alerts into incidents, or touch the frontend.
"""

from datetime import datetime, timedelta, timezone
from typing import Any

from app.database.postgres import SessionLocal
from app.models.alert import Alert, AlertSeverity

DEFAULT_WINDOW_MINUTES = 15


def _infer_source_type(index_pattern: str) -> str:
    """
    Derive a short source_type (e.g. "windows") from an index pattern like
    "events-windows-*", to populate Alert.source_type.
    """
    name = index_pattern.strip("*").strip("-")
    if name.startswith("events-"):
        name = name[len("events-"):]
    return name or index_pattern


def _entity_marker(entity: str) -> str:
    """
    Stable prefix embedded at the start of Alert.description identifying
    what/who triggered the alert (currently: the bucketed username).
    Used both for readability and as the duplicate-detection key, since
    the existing Alert model has no dedicated column for it.
    """
    return f"[entity={entity}]"


def _extract_matches(rule: dict[str, Any], response: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Walk the rule's aggregation response and return one entry per bucket
    that meets the rule's threshold.

    Expects the shape produced for terms-agg + metric-sub-agg rules (like
    lateral_movement.yaml): aggregations.<agg_name>.buckets[] where each
    bucket has a "key" and a "<threshold.aggregation>": {"value": N}.
    """
    threshold = rule["threshold"]
    metric_name = threshold["aggregation"]
    min_count = threshold["min_count"]

    aggregations = response.get("aggregations", {}) if response else {}
    matches = []

    for agg_result in aggregations.values():
        for bucket in agg_result.get("buckets", []):
            metric = bucket.get(metric_name)
            if not metric or "value" not in metric:
                continue
            if metric["value"] >= min_count:
                matches.append({"entity": bucket.get("key"), "count": metric["value"]})

    return matches


def _duplicate_exists(db, rule_name: str, entity: str, window_minutes: int) -> bool:
    """
    An alert counts as a duplicate of an existing one if it's for the same
    rule, the same entity (e.g. username), and was created within the
    rule's own detection window - i.e. it's almost certainly the same
    underlying activity being re-detected on a subsequent run.
    """
    marker = _entity_marker(entity)
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)

    existing = (
        db.query(Alert)
        .filter(Alert.event_type == rule_name)
        .filter(Alert.description.like(f"{marker}%"))
        .filter(Alert.created_at >= cutoff)
        .first()
    )
    return existing is not None


def generate_alerts(rule: dict[str, Any], response: dict[str, Any]) -> list[Alert]:
    """
    Evaluate `response` against `rule`'s threshold and create an Alert for
    each match that doesn't already have a recent duplicate.

    Returns the Alert rows that were created (empty list if nothing met
    the threshold, or every match was a duplicate).
    """
    matches = _extract_matches(rule, response)
    if not matches:
        return []

    threshold = rule["threshold"]
    window_minutes = threshold.get("window_minutes", DEFAULT_WINDOW_MINUTES)

    try:
        severity = AlertSeverity(rule.get("severity", "low"))
    except ValueError:
        severity = AlertSeverity.low

    source_type = _infer_source_type(rule["index"])
    rule_name = rule["name"][:100]  # Alert.event_type is String(100)
    rule_description = (rule.get("description") or "").strip()

    created: list[Alert] = []

    db = SessionLocal()
    try:
        for match in matches:
            entity = match["entity"]

            if _duplicate_exists(db, rule_name, entity, window_minutes):
                continue

            marker = _entity_marker(entity)
            description = (
                f"{marker} {rule_description} "
                f"Matched: '{entity}' -> {match['count']} distinct hosts "
                f"(threshold={threshold['min_count']}, window={window_minutes}m)."
            ).strip()

            alert = Alert(
                event_type=rule_name,
                description=description,
                severity=severity,
                source_type=source_type,
                es_index=rule["index"],
                es_doc_id=None,  # aggregation-based match - no single source document
                # Copied verbatim from the rule that raised this alert -
                # query_loader.load_rules() already guarantees both keys
                # are present (REQUIRED_FIELDS), so no invented mapping.
                mitre_tactic=rule["mitre_tactic"],
                mitre_technique=rule["mitre_technique"],
            )

            db.add(alert)
            created.append(alert)

        db.commit()
        for alert in created:
            db.refresh(alert)
    finally:
        db.close()

    return created


if __name__ == "__main__":
    from app.detection.query_loader import load_rules
    from app.detection.executor import execute_rule, RuleExecutionError

    for rule in load_rules():
        try:
            response = execute_rule(rule)
        except RuleExecutionError as e:
            print(f"{rule['name']}: execution failed - {e}")
            continue

        new_alerts = generate_alerts(rule, response)
        if new_alerts:
            for a in new_alerts:
                print(f"{rule['name']}: ALERT id={a.id} severity={a.severity} -> {a.description}")
        else:
            print(f"{rule['name']}: no new alerts (threshold not met or duplicate)")
