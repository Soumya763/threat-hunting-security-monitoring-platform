"""
Alert generator.

Evaluates a rule's Elasticsearch aggregation response (as returned by
app.detection.executor.execute_rule) against the rule's `threshold`, and
writes an Alert row to PostgreSQL for each match that isn't a recent
duplicate.

Each rule declares threshold.entity_type ("user", "ip", "domain" or
"host"). That entity becomes Alert.entity_type / Alert.entity_key, and
when the entity is an IP address it is also written to Alert.source_ip.
For user-based rules, threshold.source_ip_aggregation may name a
sub-aggregation (a terms agg of size 1) that supplies the most common
source IP for that user, so the AbuseIPDB check has an IP to query.

Duplicate suppression uses (rule, entity_type, entity_key) inside the
rule's window, instead of matching on description text.
"""

from datetime import datetime, timedelta, timezone
from typing import Any

from app.database.postgres import SessionLocal
from app.models.alert import Alert, AlertSeverity

DEFAULT_WINDOW_MINUTES = 15
COUNT_METRIC = "_count"  # use the bucket's doc_count instead of a sub-aggregation


def _infer_source_type(index_pattern: str) -> str:
    """Derive a short source_type (e.g. "windows") from "events-windows-*"."""
    name = index_pattern.strip("*").strip("-")
    if name.startswith("events-"):
        name = name[len("events-"):]
    return name or index_pattern


def _metric_value(bucket: dict[str, Any], metric_name: str) -> float | None:
    if metric_name == COUNT_METRIC:
        return bucket.get("doc_count")
    metric = bucket.get(metric_name)
    if not isinstance(metric, dict) or "value" not in metric:
        return None
    return metric["value"]


def _extract_matches(rule: dict[str, Any], response: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Walk the rule's aggregation response and return one entry per bucket
    whose metric meets the rule's threshold. Each match carries the entity
    key, the metric value, and (optionally) the top source IP for that
    entity.
    """
    threshold = rule["threshold"]
    metric_name = threshold["aggregation"]
    min_count = threshold["min_count"]
    ip_agg = threshold.get("source_ip_aggregation")

    aggregations = response.get("aggregations", {}) if response else {}
    matches: list[dict[str, Any]] = []

    for agg_result in aggregations.values():
        for bucket in agg_result.get("buckets", []):
            value = _metric_value(bucket, metric_name)
            if value is None or value < min_count:
                continue

            top_ip = None
            if ip_agg:
                sub = bucket.get(ip_agg, {}).get("buckets", [])
                if sub:
                    top_ip = str(sub[0].get("key"))

            matches.append(
                {
                    "entity": str(bucket.get("key")),
                    "count": value,
                    "source_ip": top_ip,
                }
            )

    return matches


def _duplicate_exists(
    db, rule_name: str, entity_type: str, entity_key: str, window_minutes: int
) -> bool:
    """An alert for the same rule and entity inside the window is a duplicate."""
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
    existing = (
        db.query(Alert)
        .filter(Alert.event_type == rule_name)
        .filter(Alert.entity_type == entity_type)
        .filter(Alert.entity_key == entity_key)
        .filter(Alert.created_at >= cutoff)
        .first()
    )
    return existing is not None


def generate_alerts(rule: dict[str, Any], response: dict[str, Any]) -> list[Alert]:
    """
    Evaluate `response` against `rule`'s threshold and create an Alert for
    each match that doesn't already have a recent duplicate.

    Returns the Alert rows that were created.
    """
    matches = _extract_matches(rule, response)
    if not matches:
        return []

    threshold = rule["threshold"]
    entity_type = threshold["entity_type"]
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

            if _duplicate_exists(db, rule_name, entity_type, entity, window_minutes):
                continue

            description = (
                f"[entity={entity}] {rule_description} "
                f"Matched: '{entity}' -> {match['count']} "
                f"(threshold={threshold['min_count']}, window={window_minutes}m)."
            ).strip()

            # An IP-entity alert's source is the IP itself; a user-entity
            # alert takes the top source IP supplied by the rule, if any.
            source_ip = entity if entity_type == "ip" else match["source_ip"]

            alert = Alert(
                event_type=rule_name,
                description=description,
                severity=severity,
                source_type=source_type,
                source_ip=source_ip,
                entity_type=entity_type,
                entity_key=entity[:255],
                es_index=rule["index"],
                es_doc_id=None,  # aggregation-based match
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
