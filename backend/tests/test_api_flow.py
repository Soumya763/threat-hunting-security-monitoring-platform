"""
API integration tests (FastAPI TestClient, in-memory SQLite, no network).

Covers existing authentication and SOC workflows (regression) and the new
analysis API: submission, background completion, owner isolation, filters,
consent gates, rate limiting, notes, incident links, reports and deletion.
"""

import io

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api import analysis as analysis_api
from app.auth.security import create_access_token, hash_password
from app.config import settings
from app.database.base import Base
from app.database.postgres import get_db
from app.main import app
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.models.analysis import Analysis
from app.models.incident import Incident, IncidentSeverity, IncidentStatus
from app.models.user import User
from app.services import pivot, quarantine, url_pipeline
from app.services.intel import base
from app.services.intel import gateway as gateway_module
from app.services.intel.gateway import IntelGateway
from app.services.rate_limit import SlidingWindowLimiter

PDF_JS = b"%PDF-1.4\n1 0 obj << /OpenAction 2 0 R /JavaScript (app.alert(1)) >>\nendobj\n%%EOF"


@pytest.fixture()
def env(tmp_path, monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    factory = sessionmaker(bind=engine, autoflush=False)

    monkeypatch.setattr(settings, "quarantine_dir", str(tmp_path / "quarantine"))
    for key in ("virustotal_api_key", "malwarebazaar_auth_key", "otx_api_key", "urlscan_api_key", "abuseipdb_api_key"):
        monkeypatch.setattr(settings, key, "")
    monkeypatch.setattr(analysis_api, "session_factory", lambda: factory)
    monkeypatch.setattr(analysis_api, "submission_limiter", SlidingWindowLimiter(10_000, 60))
    monkeypatch.setattr(gateway_module, "_gateway", IntelGateway())
    monkeypatch.setattr(pivot, "search_local_context", lambda value, **k: {
        "status": "unavailable", "total": None, "message": "test stub", "samples": [], "event_types": []})
    # URL analysis never touches the real network in tests.
    monkeypatch.setattr(url_pipeline, "lookup_addresses", lambda host: {
        "A": ["93.184.216.34"], "AAAA": [], "public": ["93.184.216.34"], "non_public": [], "error": None})
    monkeypatch.setattr(url_pipeline, "fetch_with_redirects", lambda u: {
        "hops": [{"url": u, "status": 200, "ip": "93.184.216.34", "content_type": "text/html"}],
        "final_url": u, "status": 200, "headers": {"content-type": "text/html"},
        "body": b'<title>Sign in</title><form action="https://collector.example/p"><input type="password"></form>',
        "tls": None, "tls_problem": None, "redirect_count": 0, "blocked": None, "error": None})
    monkeypatch.setattr(url_pipeline, "lookup_domain", lambda d: {"status": "ok", "age_days": 2,
                                                                  "registrar": "R", "registered_at": "t"})

    def override_db():
        db = factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db

    db = factory()
    alice = User(username="alice", password_hash=hash_password("pw-alice-123456"))
    bob = User(username="bob", password_hash=hash_password("pw-bob-1234567"))
    db.add_all([alice, bob])
    db.commit()
    tokens = {"alice": create_access_token("alice"), "bob": create_access_token("bob")}
    ids = {"alice": alice.id, "bob": bob.id}
    db.close()

    client = TestClient(app)
    yield {"client": client, "factory": factory, "tokens": tokens, "ids": ids, "qdir": tmp_path / "quarantine"}
    app.dependency_overrides.clear()
    engine.dispose()


def _h(env, who="alice"):
    return {"Authorization": f"Bearer {env['tokens'][who]}"}


def _upload(env, name, data, who="alice"):
    return env["client"].post("/api/v1/files", headers=_h(env, who),
                              files={"file": (name, io.BytesIO(data), "application/octet-stream")})


# ---------------------------------------------------------------- existing platform (regression)

def test_login_and_protected_routes_require_a_token(env):
    client = env["client"]
    assert client.get("/api/v1/audit-logs").status_code == 401
    assert client.get("/api/v1/analyses").status_code == 401
    ok = client.post("/api/v1/auth/login", json={"username": "alice", "password": "pw-alice-123456"})
    assert ok.status_code == 200 and ok.json()["access_token"]
    bad = client.post("/api/v1/auth/login", json={"username": "alice", "password": "wrong"})
    assert bad.status_code == 401


def test_alert_and_incident_workflow_still_works_and_is_audited(env):
    client, factory = env["client"], env["factory"]
    db = factory()
    alert = Alert(event_type="Brute force", description="d", severity=AlertSeverity.high,
                  status=AlertStatus.open, source_ip="203.0.113.5", entity_type="user", entity_key="carol")
    db.add(alert)
    db.add(Incident(title="Existing incident", severity=IncidentSeverity.medium, status=IncidentStatus.open))
    db.commit()
    alert_id = alert.id
    db.close()

    assert client.get("/api/v1/alerts").status_code == 200
    body = client.get(f"/api/v1/alerts/{alert_id}").json()
    assert body["source_ip"] == "203.0.113.5" and body["entity_key"] == "carol"

    moved = client.patch(f"/api/v1/alerts/{alert_id}/status", headers=_h(env), json={"to_status": "acknowledged"})
    assert moved.status_code == 200 and moved.json()["status"] == "acknowledged"
    logs = client.get("/api/v1/audit-logs", headers=_h(env), params={"entity_type": "alert", "entity_id": alert_id}).json()
    assert logs and logs[0]["actor"] == "alice"
    assert client.get("/api/v1/incidents").status_code == 200


# ---------------------------------------------------------------- file analysis

def test_pdf_upload_is_analysed_in_the_background_with_explained_score(env):
    response = _upload(env, "invoice.pdf", PDF_JS)
    assert response.status_code == 202
    analysis_id = response.json()["id"]
    detail = env["client"].get(f"/api/v1/analyses/{analysis_id}", headers=_h(env)).json()
    assert detail["status"] in ("complete", "partial")
    assert detail["risk_level"] in ("medium", "high", "critical")
    assert detail["sha256"] and len(detail["sha256"]) == 64
    codes = {f["code"] for f in detail["result"]["factors"]}
    assert "pdf_javascript" in codes
    assert detail["result"]["file"]["size_bytes"] == len(PDF_JS)
    assert (env["qdir"] / (env["factory"]().get(Analysis, analysis_id).quarantine_key)).exists()


def test_upload_rejections_unsupported_empty_and_oversized(env, monkeypatch):
    assert _upload(env, "script.sh", b"echo hi").status_code == 415
    assert _upload(env, "empty.pdf", b"").status_code == 400
    monkeypatch.setattr(settings, "file_max_upload_bytes", 64)
    assert _upload(env, "big.pdf", b"%PDF" + b"x" * 500).status_code == 413
    assert list(env["qdir"].glob("*.quarantine")) == []  # nothing left behind


def test_history_is_owner_scoped_and_other_users_get_404(env):
    analysis_id = _upload(env, "a.pdf", PDF_JS).json()["id"]
    client = env["client"]
    assert client.get(f"/api/v1/analyses/{analysis_id}", headers=_h(env, "bob")).status_code == 404
    assert client.get(f"/api/v1/analyses/{analysis_id}/report.pdf", headers=_h(env, "bob")).status_code == 404
    assert client.delete(f"/api/v1/analyses/{analysis_id}", headers=_h(env, "bob")).status_code == 404
    assert client.post(f"/api/v1/analyses/{analysis_id}/notes", headers=_h(env, "bob"), json={"content": "x"}).status_code == 404
    listing = client.get("/api/v1/analyses", headers=_h(env, "bob")).json()
    assert listing["total"] == 0


def test_external_submission_requires_explicit_consent(env):
    analysis_id = _upload(env, "b.pdf", PDF_JS).json()["id"]
    client = env["client"]
    no_consent = client.post(f"/api/v1/analyses/{analysis_id}/external-submission", headers=_h(env),
                             json={"provider": "virustotal", "consent": False})
    assert no_consent.status_code == 422
    with_consent = client.post(f"/api/v1/analyses/{analysis_id}/external-submission", headers=_h(env),
                               json={"provider": "virustotal", "consent": True})
    assert with_consent.status_code == 200
    assert with_consent.json()["outcome"]["status"] == base.STATUS_NOT_CONFIGURED  # no key: nothing sent


def test_delete_removes_record_and_quarantined_bytes(env):
    analysis_id = _upload(env, "c.pdf", PDF_JS).json()["id"]
    db = env["factory"]()
    key = db.get(Analysis, analysis_id).quarantine_key
    db.close()
    assert (env["qdir"] / key).exists()
    assert env["client"].delete(f"/api/v1/analyses/{analysis_id}", headers=_h(env)).status_code == 204
    assert not (env["qdir"] / key).exists()
    assert env["client"].get(f"/api/v1/analyses/{analysis_id}", headers=_h(env)).status_code == 404


# ---------------------------------------------------------------- URL analysis

def test_url_submission_completes_with_lookalike_and_phishing_findings(env):
    response = env["client"].post("/api/v1/urls", headers=_h(env), json={"url": "https://paypa1-secure.com/login"})
    assert response.status_code == 202
    detail = env["client"].get(f"/api/v1/analyses/{response.json()['id']}", headers=_h(env)).json()
    assert detail["status"] in ("complete", "partial")
    assert detail["result"]["lookalike_of"] == "paypal.com"
    assert "login_form" in {f["code"] for f in detail["result"]["factors"]}
    assert detail["risk_level"] in ("medium", "high", "critical")


@pytest.mark.parametrize("url", ["http://127.0.0.1/admin", "ftp://example.com/", "http://user:pw@example.com/"])
def test_unsafe_url_submissions_are_rejected_before_any_work(env, url):
    assert env["client"].post("/api/v1/urls", headers=_h(env), json={"url": url}).status_code == 422


def test_urlscan_submission_requires_consent(env):
    response = env["client"].post("/api/v1/urls", headers=_h(env),
                                  json={"url": "https://example.com/", "submit_to_urlscan": True, "consent": False})
    assert response.status_code == 422


# ---------------------------------------------------------------- indicator search

def test_indicator_search_validates_input_and_completes_without_providers(env):
    client = env["client"]
    assert client.post("/api/v1/indicators/search", headers=_h(env), json={"query": "not an indicator!!"}).status_code == 422
    ok = client.post("/api/v1/indicators/search", headers=_h(env), json={"query": "8.8.8.8"})
    assert ok.status_code == 202
    detail = client.get(f"/api/v1/analyses/{ok.json()['id']}", headers=_h(env)).json()
    assert detail["indicator_type"] == "ip"
    assert detail["risk_level"] == "insufficient_evidence"  # nothing consulted: never "clean"
    providers = detail["result"]["providers"]
    assert all(p["status"] == "not_configured" for p in providers.values())
    assert detail["result"]["local"]["pivot"]["status"] == "unavailable"


def test_hash_search_is_normalised_to_lowercase(env):
    response = env["client"].post("/api/v1/indicators/search", headers=_h(env), json={"query": "A" * 64})
    detail = env["client"].get(f"/api/v1/analyses/{response.json()['id']}", headers=_h(env)).json()
    assert detail["indicator_type"] == "sha256" and detail["indicator_value"] == "a" * 64


# ---------------------------------------------------------------- history features

def test_history_filters_sorting_and_pagination(env):
    db = env["factory"]()
    user_id = env["ids"]["alice"]
    rows = [
        ("file", "report.pdf", "high", 60), ("url", "https://a.example/", "clean", 0),
        ("file", "tool.exe", "critical", 90), ("indicator", "8.8.8.8", "low", 10),
        ("url", "https://paypa1.example/", "medium", 35),
    ]
    for kind, name, level, score in rows:
        db.add(Analysis(owner_id=user_id, kind=kind, indicator_type=kind, indicator_value=name,
                        display_name=name, status="complete", risk_level=level, risk_score=score))
    db.commit()
    db.close()
    client, headers = env["client"], _h(env)

    assert client.get("/api/v1/analyses", headers=headers, params={"kind": "file"}).json()["total"] == 2
    assert client.get("/api/v1/analyses", headers=headers, params={"risk": "critical"}).json()["total"] == 1
    assert client.get("/api/v1/analyses", headers=headers, params={"q": "paypa1"}).json()["total"] == 1
    assert client.get("/api/v1/analyses", headers=headers, params={"risk": "bogus"}).status_code == 422
    by_score = client.get("/api/v1/analyses", headers=headers,
                          params={"sort": "risk_score", "order": "asc", "page_size": 2}).json()
    assert [i["risk_score"] for i in by_score["items"]] == [0, 10]
    assert by_score["pages"] == 3
    second = client.get("/api/v1/analyses", headers=headers,
                        params={"sort": "risk_score", "order": "asc", "page_size": 2, "page": 2}).json()
    assert [i["risk_score"] for i in second["items"]] == [35, 60]


# ---------------------------------------------------------------- notes, incidents, audit

def test_notes_incident_link_and_audit_trail(env):
    client, factory = env["client"], env["factory"]
    analysis_id = _upload(env, "d.pdf", PDF_JS).json()["id"]
    db = factory()
    incident = Incident(title="Phishing wave", severity=IncidentSeverity.high, status=IncidentStatus.open)
    db.add(incident)
    db.commit()
    incident_id = incident.id
    db.close()

    note = client.post(f"/api/v1/analyses/{analysis_id}/notes", headers=_h(env), json={"content": "Seen on two hosts"})
    assert note.status_code == 201 and note.json()["author"] == "alice"
    assert client.get(f"/api/v1/analyses/{analysis_id}/notes", headers=_h(env)).json()[0]["content"] == "Seen on two hosts"

    linked = client.post(f"/api/v1/analyses/{analysis_id}/incidents", headers=_h(env), json={"incident_id": incident_id})
    assert linked.status_code == 201
    assert client.get(f"/api/v1/analyses/{analysis_id}/incidents", headers=_h(env)).json()[0]["id"] == incident_id
    assert client.get(f"/api/v1/incidents/{incident_id}/analyses", headers=_h(env)).json()[0]["id"] == analysis_id

    created = client.post(f"/api/v1/analyses/{analysis_id}/incidents", headers=_h(env),
                          json={"create_incident": True, "title": "New case from file"})
    assert created.status_code == 201

    logs = client.get("/api/v1/audit-logs", headers=_h(env),
                      params={"entity_type": "analysis", "entity_id": analysis_id}).json()
    actions = {entry["to_status"] for entry in logs}
    assert {"uploaded", "note_added", "linked_incident", "incident_created"} <= actions


# ---------------------------------------------------------------- reports, providers, dashboard, logs

def test_json_and_pdf_reports_download_from_stored_data(env):
    analysis_id = _upload(env, "e.pdf", PDF_JS).json()["id"]
    client = env["client"]
    js = client.get(f"/api/v1/analyses/{analysis_id}/report.json", headers=_h(env))
    assert js.status_code == 200 and js.json()["analysis"]["id"] == analysis_id
    assert "attachment" in js.headers["content-disposition"]
    pdf = client.get(f"/api/v1/analyses/{analysis_id}/report.pdf", headers=_h(env))
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF-")


def test_incident_report_pdf_and_json(env):
    db = env["factory"]()
    incident = Incident(title="Case", severity=IncidentSeverity.low, status=IncidentStatus.open)
    db.add(incident)
    db.commit()
    incident_id = incident.id
    db.close()
    client = env["client"]
    assert client.get(f"/api/v1/reports/incidents/{incident_id}.pdf", headers=_h(env)).content.startswith(b"%PDF-")
    assert client.get(f"/api/v1/reports/incidents/{incident_id}.json", headers=_h(env)).json()["incident"]["id"] == incident_id
    assert client.get("/api/v1/reports/incidents/99999.pdf", headers=_h(env)).status_code == 404


def test_providers_endpoint_reports_status_and_never_returns_key_values(env, monkeypatch):
    monkeypatch.setattr(settings, "virustotal_api_key", "SECRET-VALUE-DO-NOT-LEAK-12345")
    response = env["client"].get("/api/v1/providers", headers=_h(env))
    assert response.status_code == 200
    vt = next(p for p in response.json() if p["id"] == "virustotal")
    assert vt["configured"] is True
    assert "SECRET-VALUE-DO-NOT-LEAK-12345" not in response.text


def test_dashboard_summary_reports_real_counts(env):
    _upload(env, "f.pdf", PDF_JS)
    summary = env["client"].get("/api/v1/dashboard/summary", headers=_h(env)).json()
    assert summary["analyses"]["total"] == 1
    assert summary["analyses"]["files"] == 1
    assert len(summary["trend"]) == 14
    assert summary["recent_analyses"][0]["kind"] == "file"


def test_log_search_reports_unavailable_as_503_not_as_empty(env, monkeypatch):
    class Down:
        def search(self, **kwargs):
            raise ConnectionError("down")

    monkeypatch.setattr("app.database.opensearch.opensearch_client", Down())
    response = env["client"].get("/api/v1/logs/search", headers=_h(env), params={"q": "203.0.113.5"})
    assert response.status_code == 503


def test_rate_limit_returns_429_after_the_window_quota(env, monkeypatch):
    monkeypatch.setattr(analysis_api, "submission_limiter", SlidingWindowLimiter(2, 60))
    client = env["client"]
    codes = [client.post("/api/v1/urls", headers=_h(env), json={"url": f"https://example{i}.com/"}).status_code
             for i in range(3)]
    assert codes == [202, 202, 429]
