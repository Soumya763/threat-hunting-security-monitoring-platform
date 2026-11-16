"""
Integration tests against a REAL OpenSearch server.

These run only when OPENSEARCH_HOST (default http://localhost:9200) answers.
Otherwise they are skipped, and the skip is reported, never counted as a pass.

They index documents shaped like the Logstash pipeline output into temporary
indices that match the production index patterns (for example
events-windows-itest-<id> matches events-windows-*), run the shipped detection
rules and the local pivot against them, and delete the indices afterwards.
"""

import uuid
from datetime import datetime, timezone

import pytest

from app.database.opensearch import opensearch_client
from app.detection import alert_generator, executor
from app.detection.query_loader import load_rules
from app.services import pivot


def _reachable() -> bool:
    try:
        return bool(opensearch_client.ping())
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _reachable(), reason="OpenSearch is not reachable (OPENSEARCH_HOST)")

RULES = {r["name"]: r for r in load_rules()}
RUN = uuid.uuid4().hex[:8]
CREATED: list[str] = []


def _now():
    return datetime.now(timezone.utc).isoformat()


def _index(pattern_prefix: str, docs: list[dict]) -> str:
    index = f"{pattern_prefix}-itest-{RUN}-{len(CREATED)}"
    CREATED.append(index)
    for doc in docs:
        opensearch_client.index(index=index, body=doc)
    opensearch_client.indices.refresh(index=index)
    return index


@pytest.fixture(scope="module", autouse=True)
def _cleanup():
    yield
    for index in CREATED:
        try:
            opensearch_client.indices.delete(index=index, ignore_unavailable=True)
        except Exception:
            pass


def _windows(user: str, ip: str, event: str, host: str = "WS-01") -> dict:
    return {"@timestamp": _now(), "event_type": event, "username": user, "source_ip": ip,
            "source_name": host, "source_type": "windows", "message": f"Security: User={user} SourceIP={ip}"}


def _matches_for(rule_name: str):
    rule = RULES[rule_name]
    response = executor.execute_rule(rule)
    return alert_generator._extract_matches(rule, response)


def test_cluster_is_reachable_and_healthy():
    assert opensearch_client.ping()
    assert opensearch_client.cluster.health()["status"] in ("green", "yellow")


def test_lateral_movement_rule_matches_one_user_on_three_hosts():
    user = f"lm-{RUN}"
    _index("events-windows", [
        _windows(user, "198.51.100.10", "windows_login", host) for host in ("WS-01", "WS-02", "WS-03")
    ])
    matches = [m for m in _matches_for("Lateral Movement - Multiple Host Logins by Single User") if m["entity"] == user]
    assert matches and matches[0]["count"] >= 3
    assert matches[0]["source_ip"] == "198.51.100.10"  # top_source_ip sub-aggregation


def test_brute_force_rule_counts_failed_logins_per_user():
    user = f"bf-{RUN}"
    _index("events-windows", [_windows(user, "203.0.113.20", "windows_login_failed") for _ in range(6)])
    matches = [m for m in _matches_for("Brute Force - Repeated Failed Logins for One Account") if m["entity"] == user]
    assert matches and matches[0]["count"] == 6


def test_password_spraying_rule_counts_distinct_accounts_per_source():
    ip = "203.0.113.30"
    _index("events-windows", [_windows(f"spray{i}-{RUN}", ip, "windows_login_failed") for i in range(5)])
    matches = [m for m in _matches_for("Password Spraying - Failed Logons Across Many Accounts from One IP") if m["entity"] == ip]
    assert matches and matches[0]["count"] >= 4


def test_port_scan_rule_counts_distinct_destination_ports():
    ip = "192.0.2.44"
    docs = [{"@timestamp": _now(), "event_type": "firewall_connection_denied", "source": {"ip": ip},
             "destination": {"port": port}, "source_type": "firewall"} for port in range(20, 33)]
    _index("events-firewall", docs)
    matches = [m for m in _matches_for("Network Scan - Denied Connections to Many Ports from One Source") if m["entity"] == ip]
    assert matches and matches[0]["count"] >= 10


def test_suspicious_dns_rule_flags_the_domain_entity():
    domain = f"c2-{RUN}.example"
    _index("events-dns", [{"@timestamp": _now(), "event_type": "dns_query_suspicious",
                           "dns": {"query": domain}, "source": {"ip": "192.168.1.50"}, "source_type": "dns"}])
    matches = [m for m in _matches_for("Suspicious DNS Query - Domain Name Matches Malware Keywords") if m["entity"] == domain]
    assert matches


def test_json_application_auth_failure_rule_reads_the_json_index():
    user = f"app-{RUN}"
    _index("events-json", [{"@timestamp": _now(), "event_type": "auth_failure", "user": {"name": user},
                            "source": {"ip": "198.51.100.77"}} for _ in range(5)])
    matches = [m for m in _matches_for("Application Authentication Failures - Repeated for One User") if m["entity"] == user]
    assert matches and matches[0]["source_ip"] == "198.51.100.77"


def test_local_pivot_finds_indexed_ip_and_reports_event_types():
    ip = f"203.0.113.{(int(RUN, 16) % 200) + 20}"
    _index("events-firewall", [{"@timestamp": _now(), "event_type": "firewall_connection_denied",
                                "source": {"ip": ip}, "destination": {"ip": "10.0.0.10"}, "source_type": "firewall",
                                "message": f"DROP TCP {ip}:1234 -> 10.0.0.10:445"}])
    result = pivot.search_local_context(ip)
    assert result["status"] == "ok"
    assert result["total"] >= 1
    assert any(e["event_type"] == "firewall_connection_denied" for e in result["event_types"])
    assert result["samples"][0]["source_ip"] == ip


def test_pivot_for_unknown_value_says_no_matching_events_not_unavailable():
    result = pivot.search_local_context(f"no-such-value-{RUN}.invalid")
    assert result["status"] == "ok"
    assert result["total"] == 0


def test_proxy_error_burst_rule_counts_errors_per_client():
    ip = "10.9.8.7"
    _index("events-proxy", [{"@timestamp": _now(), "event_type": "proxy_request_error", "source": {"ip": ip},
                             "url": {"original": f"http://example.com/p{i}"}, "http": {"response": {"status_code": 404}},
                             "source_type": "proxy"} for i in range(10)])
    matches = [m for m in _matches_for("Web Enumeration - Burst of HTTP Errors from One Client") if m["entity"] == ip]
    assert matches and matches[0]["count"] >= 10


def test_remote_admin_port_rule_counts_allowed_connections():
    ip = "10.4.4.4"
    _index("events-firewall", [{"@timestamp": _now(), "event_type": "firewall_connection_allowed",
                                "source": {"ip": ip}, "destination": {"port": 22}, "source_type": "firewall"}
                               for _ in range(3)])
    matches = [m for m in _matches_for("Remote Administration or SMB Access Allowed from One Source") if m["entity"] == ip]
    assert matches and matches[0]["count"] >= 3
