"""
Alert generation and correlation, run against an in-memory SQLite database.

These cover the Priority 1 correctness fixes:
  - source_ip is written for IP-entity alerts and for user alerts whose rule
    supplies a top source IP;
  - duplicates are suppressed by (rule, entity), not description text;
  - correlation groups alerts only with shared evidence (IP or entity),
    never merely because they share an event type.
"""

from datetime import datetime, timedelta, timezone

import pytest

from app.correlation import engine as correlation
from app.detection import alert_generator
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.models.incident import Incident


@pytest.fixture()
def db_factory(sqlite_session_factory, monkeypatch):
    monkeypatch.setattr(alert_generator, "SessionLocal", sqlite_session_factory)
    monkeypatch.setattr(correlation, "SessionLocal", sqlite_session_factory)
    return sqlite_session_factory


def _rule(entity_type, metric="distinct_hosts", ip_agg=None, min_count=3):
    threshold = {
        "aggregation": metric,
        "min_count": min_count,
        "window_minutes": 15,
        "entity_type": entity_type,
    }
    if ip_agg:
        threshold["source_ip_aggregation"] = ip_agg
    return {
        "name": "Test Rule",
        "description": "test",
        "mitre_tactic": "TA0008 - Lateral Movement",
        "mitre_technique": "T1021 - Remote Services",
        "severity": "high",
        "index": "events-windows-*",
        "threshold": threshold,
    }


def _user_response(user, hosts, ip):
    return {
        "aggregations": {
            "by_user": {
                "buckets": [
                    {
                        "key": user,
                        "distinct_hosts": {"value": hosts},
                        "top_source_ip": {"buckets": [{"key": ip, "doc_count": 4}]},
                    }
                ]
            }
        }
    }


def test_user_alert_takes_source_ip_from_rule_subaggregation(db_factory):
    rule = _rule("user", ip_agg="top_source_ip")
    created = alert_generator.generate_alerts(rule, _user_response("alice", 4, "198.51.100.7"))
    assert len(created) == 1
    with db_factory() as db:
        alert = db.query(Alert).one()
        assert alert.source_ip == "198.51.100.7"
        assert alert.entity_type == "user"
        assert alert.entity_key == "alice"


def test_ip_entity_alert_sets_source_ip_to_the_entity(db_factory):
    rule = _rule("ip", metric="_count", min_count=2)
    response = {"aggregations": {"by_ip": {"buckets": [{"key": "203.0.113.9", "doc_count": 5}]}}}
    alert_generator.generate_alerts(rule, response)
    with db_factory() as db:
        alert = db.query(Alert).one()
        assert alert.source_ip == "203.0.113.9"
        assert alert.entity_key == "203.0.113.9"


def test_duplicate_suppressed_by_entity_not_description(db_factory):
    rule = _rule("user", ip_agg="top_source_ip")
    response = _user_response("bob", 3, "192.0.2.5")
    assert len(alert_generator.generate_alerts(rule, response)) == 1
    assert alert_generator.generate_alerts(rule, response) == []
    # A different user with the same rule is NOT a duplicate.
    other = _user_response("carol", 3, "192.0.2.5")
    assert len(alert_generator.generate_alerts(rule, other)) == 1


def test_entity_with_percent_or_underscore_is_matched_exactly(db_factory):
    rule = _rule("user", ip_agg="top_source_ip")
    alert_generator.generate_alerts(rule, _user_response("a_b%", 3, "192.0.2.1"))
    # "a_bX" would have matched a LIKE pattern on the old description-based check.
    assert len(alert_generator.generate_alerts(rule, _user_response("aXb", 3, "192.0.2.1"))) == 1


def _alert(db, *, event_type, ip=None, entity_type=None, entity_key=None, minutes_ago=0):
    created = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    alert = Alert(
        event_type=event_type,
        description="test",
        severity=AlertSeverity.medium,
        status=AlertStatus.open,
        source_ip=ip,
        entity_type=entity_type,
        entity_key=entity_key,
        created_at=created,
        updated_at=created,
    )
    db.add(alert)
    db.flush()
    return alert


def test_same_event_type_different_users_are_not_correlated(db_factory):
    with db_factory() as db:
        a = _alert(db, event_type="Lateral", entity_type="user", entity_key="alice", ip="10.0.0.1")
        b = _alert(db, event_type="Lateral", entity_type="user", entity_key="bob", ip="10.0.0.2")
        db.commit()
    assert correlation.run_correlation() == []
    with db_factory() as db:
        assert db.query(Alert).filter(Alert.incident_id.isnot(None)).count() == 0


def test_shared_source_ip_across_rules_is_correlated(db_factory):
    with db_factory() as db:
        _alert(db, event_type="Password spraying", ip="203.0.113.50", entity_type="ip", entity_key="203.0.113.50")
        _alert(db, event_type="Port scan", ip="203.0.113.50", entity_type="ip", entity_key="203.0.113.50")
        db.commit()
    incidents = correlation.run_correlation()
    assert len(incidents) == 1
    assert "source IP 203.0.113.50" in incidents[0].description


def test_shared_user_is_correlated_even_with_different_rules(db_factory):
    with db_factory() as db:
        _alert(db, event_type="Brute force", entity_type="user", entity_key="dave")
        _alert(db, event_type="Lateral", entity_type="user", entity_key="dave")
        db.commit()
    assert len(correlation.run_correlation()) == 1


def test_alerts_outside_window_are_not_correlated(db_factory):
    with db_factory() as db:
        _alert(db, event_type="X", ip="198.51.100.1", minutes_ago=60)
        _alert(db, event_type="Y", ip="198.51.100.1", minutes_ago=0)
        db.commit()
    assert correlation.run_correlation() == []


def test_new_alert_attaches_to_existing_open_incident(db_factory):
    with db_factory() as db:
        first = _alert(db, event_type="A", ip="192.0.2.77", minutes_ago=5)
        second = _alert(db, event_type="B", ip="192.0.2.77", minutes_ago=4)
        db.commit()
    assert len(correlation.run_correlation()) == 1

    with db_factory() as db:
        late = _alert(db, event_type="C", ip="192.0.2.77", minutes_ago=0)
        db.commit()
    assert correlation.run_correlation() == []  # attached, no new incident
    with db_factory() as db:
        late = db.query(Alert).filter(Alert.event_type == "C").one()
        assert late.incident_id is not None
        assert db.query(Incident).count() == 1
