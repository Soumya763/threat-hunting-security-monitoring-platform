"""Local pivots, report generation, and quarantine storage/retention."""

import asyncio
import io
import os
from datetime import datetime, timedelta, timezone

import pytest
from starlette.datastructures import UploadFile

from app.config import settings
from app.database.base import Base
from app.models.analysis import Analysis
from app.models.user import User
from app.services import pivot, quarantine, reports


class FakeES:
    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error
        self.bodies = []

    def search(self, index, body, request_timeout=None):
        self.bodies.append(body)
        if self.error:
            raise self.error
        return self.response


def test_pivot_escapes_quotes_and_reports_matches(monkeypatch):
    fake = FakeES({"hits": {"total": {"value": 2}, "hits": [
        {"_index": "events-firewall-2026", "_source": {"@timestamp": "t", "event_type": "firewall_connection_denied",
                                                        "source": {"ip": "203.0.113.9"}, "message": "DROP"}}]},
        "aggregations": {"event_types": {"buckets": [{"key": "firewall_connection_denied", "doc_count": 2}]},
                         "first_seen": {"value_as_string": "a"}, "last_seen": {"value_as_string": "b"}}})
    monkeypatch.setattr("app.database.elasticsearch.es_client", fake)
    result = pivot.search_local_context('evil"query')
    assert result["status"] == "ok" and result["total"] == 2
    assert result["samples"][0]["source_ip"] == "203.0.113.9"
    assert r'evil\"query' in fake.bodies[0]["query"]["bool"]["must"][0]["query_string"]["query"]


def test_pivot_unreachable_search_is_unavailable_never_no_events(monkeypatch):
    monkeypatch.setattr("app.database.elasticsearch.es_client", FakeES(error=ConnectionError("down")))
    result = pivot.search_local_context("8.8.8.8")
    assert result["status"] == "unavailable" and result["total"] is None
    assert "unavailable" in result["message"]


def test_pivot_zero_hits_says_no_matching_events(monkeypatch):
    monkeypatch.setattr("app.database.elasticsearch.es_client", FakeES({"hits": {"total": {"value": 0}, "hits": []},
                                                                        "aggregations": {}}))
    assert pivot.search_local_context("x.example")["message"].startswith("No matching events")


def _detail():
    return {
        "id": 7, "kind": "file", "display_name": "<b>evil</b>.pdf", "indicator_value": "a" * 64,
        "status": "complete", "risk_level": "medium", "risk_score": 30, "file_size": 12,
        "created_at": "2026-01-01T00:00:00+00:00", "completed_at": None, "retention_until": None,
        "sha256": "a" * 64, "indicator_type": "file", "result": {
            "classification_label": "Medium risk",
            "factors": [{"points": 15, "label": "PDF JavaScript", "reason": "uses <script> & ampersand"}],
            "caveats": ["caveat"], "recommendations": ["Verify with the sender."],
            "identification": {"detected_family": "pdf", "declared_extension": "pdf", "extension_matches": True},
            "providers": {"VirusTotal file": {"status": "not_configured", "detection": None, "message": "x"}},
        },
    }


def test_analysis_pdf_renders_and_escapes_untrusted_text():
    report = reports.analysis_report_json(_detail(), [{"author": "a", "content": "<img src=x>", "created_at": "t"}],
                                          [], generated_by="analyst")
    pdf = reports.analysis_report_pdf(report)
    assert pdf.startswith(b"%PDF-") and len(pdf) > 1000
    assert report["disclaimer"].startswith("This report summarises")
    assert report["risk"]["score"] == 30


def test_incident_pdf_renders_with_empty_sections():
    report = reports.incident_report_json({"id": 3, "title": "t", "severity": "high", "status": "open",
                                           "description": None, "assigned_username": None, "created_at": "t"},
                                          [], [], [], generated_by="analyst")
    assert reports.incident_report_pdf(report).startswith(b"%PDF-")


@pytest.fixture()
def qdir(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "quarantine_dir", str(tmp_path / "q"))
    return tmp_path / "q"


def test_quarantine_rejects_keys_that_could_escape_the_directory(qdir):
    for bad in ("../../etc/passwd", "a" * 32 + ".txt", "/abs/path", "x"):
        with pytest.raises(ValueError):
            quarantine._path_for(bad)


def test_user_file_names_are_reduced_to_a_safe_base_name():
    assert quarantine.sanitize_filename("../../etc/passwd") == "passwd"
    assert quarantine.sanitize_filename("C:\\temp\\bad\x00name.pdf") == "badname.pdf"
    assert quarantine.sanitize_filename("") == "upload"


class _Chunks:
    def __init__(self, data):
        self._stream = io.BytesIO(data)

    async def read(self, n):
        return self._stream.read(n)


def test_upload_is_stored_owner_only_and_hashed(qdir):
    upload = UploadFile(file=io.BytesIO(b"%PDF-1.4 hi"), filename="a.pdf")
    saved = asyncio.run(quarantine.save_upload(upload, max_bytes=1000))
    path = qdir / saved["quarantine_key"]
    assert path.exists()
    assert oct(os.stat(path).st_mode & 0o777) == "0o600"
    assert saved["size_bytes"] == len(b"%PDF-1.4 hi")
    assert quarantine.read_quarantined(saved["quarantine_key"]) == b"%PDF-1.4 hi"


def test_oversized_upload_is_rejected_and_partial_file_removed(qdir):
    upload = UploadFile(file=io.BytesIO(b"x" * 50), filename="big.pdf")
    with pytest.raises(quarantine.UploadRejected):
        asyncio.run(quarantine.save_upload(upload, max_bytes=10))
    assert list(qdir.iterdir()) == []


def test_empty_upload_is_rejected(qdir):
    with pytest.raises(quarantine.UploadRejected):
        asyncio.run(quarantine.save_upload(UploadFile(file=io.BytesIO(b""), filename="e.pdf"), max_bytes=10))


def test_retention_purge_removes_bytes_but_keeps_the_record(qdir, tmp_path):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    factory = sessionmaker(bind=engine)
    db = factory()
    user = User(username="ret", password_hash="x")
    db.add(user)
    db.flush()
    key = "b" * 32 + ".quarantine"
    (qdir).mkdir(parents=True, exist_ok=True)
    (qdir / key).write_bytes(b"data")
    db.add(Analysis(owner_id=user.id, kind="file", indicator_type="file", indicator_value="c" * 64,
                    status="complete", quarantine_key=key,
                    retention_until=datetime.now(timezone.utc) - timedelta(minutes=1)))
    db.commit()
    db.close()

    assert quarantine.purge_expired(session_factory=factory) == 1
    assert not (qdir / key).exists()
    check = factory()
    row = check.query(Analysis).one()
    assert row.quarantine_key is None and row.file_purged_at is not None
    check.close()
