"""Provider clients and gateway: configuration, normalisation, errors, caching, rate limits. No network."""

import pytest
import requests

from app.config import settings
from app.services import threat_intel
from app.services.intel import base, providers
from app.services.intel.gateway import IntelGateway


class Resp:
    def __init__(self, status=200, body=None):
        self.status_code = status
        self._body = body or {}

    def json(self):
        return self._body


@pytest.fixture(autouse=True)
def _no_real_keys_and_fast_limits(monkeypatch):
    for name in ("virustotal_api_key", "malwarebazaar_auth_key", "otx_api_key", "urlscan_api_key", "abuseipdb_api_key"):
        monkeypatch.setattr(settings, name, "")
    monkeypatch.setattr(providers.virustotal, "limiter", base.RateLimiter(0, 10_000))
    monkeypatch.setattr(providers.MalwareBazaarClient, "_limiter", base.RateLimiter(0, 10_000))
    monkeypatch.setattr(providers.OTXClient, "_limiter", base.RateLimiter(0, 10_000))
    monkeypatch.setattr(providers.UrlscanClient, "_limiter", base.RateLimiter(0, 10_000))
    monkeypatch.setattr(providers.time, "sleep", lambda s: None)

    def blocked(*a, **k):
        raise AssertionError("no network call expected")

    monkeypatch.setattr(providers.requests, "request", blocked)


def _set_requests(monkeypatch, *responses):
    queue = list(responses)

    def fake(method, url, **kwargs):
        item = queue.pop(0)
        if isinstance(item, BaseException):
            raise item
        fake.calls.append((method, url, kwargs))
        return item

    fake.calls = []
    monkeypatch.setattr(providers.requests, "request", fake)
    return fake


def test_unconfigured_provider_reports_not_configured_without_any_request():
    assert providers.virustotal.lookup("sha256", "a" * 64)["status"] == base.STATUS_NOT_CONFIGURED
    assert providers.malwarebazaar.lookup("sha256", "a" * 64)["status"] == base.STATUS_NOT_CONFIGURED
    assert providers.otx.lookup("ip", "8.8.8.8")["status"] == base.STATUS_NOT_CONFIGURED


def test_virustotal_file_stats_normalised_to_detection_counts(monkeypatch):
    monkeypatch.setattr(settings, "virustotal_api_key", "test-key")
    stats = {"malicious": 5, "suspicious": 1, "undetected": 58, "harmless": 6, "timeout": 0}
    fake = _set_requests(monkeypatch, Resp(200, {"data": {"attributes": {
        "last_analysis_stats": stats, "popular_threat_classification": {"suggested_threat_label": "trojan.x"}}}}))
    r = providers.virustotal.lookup("sha256", "b" * 64)
    assert r["status"] == base.STATUS_OK
    assert r["detection"] == {"positives": 6, "total": 70}
    assert r["summary"]["suggested_threat_label"] == "trojan.x"
    assert fake.calls[0][2]["headers"]["x-apikey"] == "test-key"


@pytest.mark.parametrize("status,expected", [
    (404, base.STATUS_NOT_FOUND), (401, base.STATUS_INVALID_KEY), (403, base.STATUS_INVALID_KEY),
    (429, base.STATUS_RATE_LIMITED), (418, base.STATUS_UNAVAILABLE),
])
def test_virustotal_http_errors_are_mapped(monkeypatch, status, expected):
    monkeypatch.setattr(settings, "virustotal_api_key", "k")
    _set_requests(monkeypatch, Resp(status))
    assert providers.virustotal.lookup("domain", "example.com")["status"] == expected


def test_server_errors_are_retried_once_then_reported_unavailable(monkeypatch):
    monkeypatch.setattr(settings, "virustotal_api_key", "k")
    fake = _set_requests(monkeypatch, Resp(500), Resp(503))
    assert providers.virustotal.lookup("domain", "example.com")["status"] == base.STATUS_UNAVAILABLE
    assert len(fake.calls) == 2


def test_timeout_is_reported_as_timeout_not_as_clean(monkeypatch):
    monkeypatch.setattr(settings, "virustotal_api_key", "k")
    _set_requests(monkeypatch, requests.Timeout(), requests.Timeout())
    r = providers.virustotal.lookup("ip", "8.8.8.8")
    assert r["status"] == base.STATUS_TIMEOUT
    assert r["detection"] is None


def test_virustotal_url_lookup_uses_unpadded_base64_identifier(monkeypatch):
    monkeypatch.setattr(settings, "virustotal_api_key", "k")
    fake = _set_requests(monkeypatch, Resp(404))
    providers.virustotal.lookup("url", "https://example.com/a")
    assert "/urls/" in fake.calls[0][1] and not fake.calls[0][1].endswith("=")


def test_malwarebazaar_ok_hash_not_found_and_bad_key(monkeypatch):
    monkeypatch.setattr(settings, "malwarebazaar_auth_key", "auth")
    _set_requests(monkeypatch, Resp(200, {"query_status": "ok", "data": [{"signature": "Fam", "tags": ["x"]}]}))
    ok = providers.malwarebazaar.lookup("sha256", "c" * 64)
    assert ok["status"] == base.STATUS_OK and ok["summary"]["known_malware_sample"] is True
    _set_requests(monkeypatch, Resp(200, {"query_status": "hash_not_found"}))
    assert providers.malwarebazaar.lookup("sha256", "d" * 64)["status"] == base.STATUS_NOT_FOUND
    _set_requests(monkeypatch, Resp(200, {"query_status": "illegal_auth_key"}))
    assert providers.malwarebazaar.lookup("sha256", "e" * 64)["status"] == base.STATUS_INVALID_KEY


def test_malwarebazaar_does_not_claim_to_support_domains(monkeypatch):
    monkeypatch.setattr(settings, "malwarebazaar_auth_key", "auth")
    assert providers.malwarebazaar.lookup("domain", "example.com")["status"] == base.STATUS_UNSUPPORTED


def test_otx_pulse_count_normalised(monkeypatch):
    monkeypatch.setattr(settings, "otx_api_key", "otx")
    _set_requests(monkeypatch, Resp(200, {"pulse_info": {"count": 3, "pulses": [{"name": "P1"}]}}))
    r = providers.otx.lookup("ip", "203.0.113.5")
    assert r["status"] == base.STATUS_OK and r["summary"]["pulse_count"] == 3


def test_urlscan_search_counts_malicious_scans_and_empty_results_are_not_found(monkeypatch):
    monkeypatch.setattr(settings, "urlscan_api_key", "us")
    _set_requests(monkeypatch, Resp(200, {"results": [
        {"verdicts": {"overall": {"malicious": True}}, "page": {"url": "https://a/"}, "task": {"time": "t1"}},
        {"verdicts": {"overall": {"malicious": False}}, "page": {"url": "https://b/"}, "task": {"time": "t2"}},
    ]}))
    r = providers.urlscan.lookup("domain", "example.com")
    assert r["summary"]["malicious_scans"] == 1
    _set_requests(monkeypatch, Resp(200, {"results": []}))
    assert providers.urlscan.lookup("domain", "nothing.example")["status"] == base.STATUS_NOT_FOUND


def test_urlscan_submission_uses_configured_visibility_not_public(monkeypatch):
    monkeypatch.setattr(settings, "urlscan_api_key", "us")
    fake = _set_requests(monkeypatch, Resp(200, {"uuid": "1234", "result": "https://urlscan.io/result/1234/"}))
    r = providers.urlscan.submit_url("https://example.com/")
    assert r["status"] == base.STATUS_SUBMITTED
    assert fake.calls[0][2]["json"]["visibility"] == "unlisted"


def test_gateway_caches_consulted_results_and_does_not_cache_errors(monkeypatch):
    monkeypatch.setattr(settings, "virustotal_api_key", "k")
    gw = IntelGateway()
    fake = _set_requests(monkeypatch, Resp(404), Resp(404))
    first = gw.lookup("virustotal", "domain", "cache.example")
    second = gw.lookup("virustotal", "domain", "cache.example")
    assert first["status"] == base.STATUS_NOT_FOUND
    assert second["cached"] is True
    assert len(fake.calls) == 1

    fake2 = _set_requests(monkeypatch, Resp(500), Resp(500), Resp(200, {"data": {"attributes": {}}}))
    gw.lookup("virustotal", "domain", "err.example")
    gw.lookup("virustotal", "domain", "err.example")
    assert len(fake2.calls) >= 2  # error results are not cached


def test_gateway_unknown_provider_is_reported_not_raised():
    assert IntelGateway().lookup("nope", "domain", "x")["status"] == base.STATUS_UNSUPPORTED


def test_rate_limiter_enforces_interval_and_daily_quota():
    limiter = base.RateLimiter(min_interval_seconds=1000, daily_quota=10)
    assert limiter.try_acquire() is None
    assert "retry" in limiter.try_acquire()
    quota = base.RateLimiter(min_interval_seconds=0, daily_quota=1)
    assert quota.try_acquire() is None
    assert "quota" in quota.try_acquire()


def test_abuseipdb_adapter_normalises_ok_and_refuses_private_ips(monkeypatch):
    gw = IntelGateway()
    monkeypatch.setattr(threat_intel, "get_ip_reputation", lambda ip: {
        "status": "ok", "detail": None, "reputation": {"abuse_confidence_score": 80, "total_reports": 4,
                                                       "country": "US", "isp": "ISP", "last_reported_at": "t"}})
    r = gw.lookup("abuseipdb", "ip", "203.0.113.9")
    assert r["status"] == base.STATUS_OK and r["summary"]["abuse_confidence_score"] == 80
    monkeypatch.setattr(threat_intel, "get_ip_reputation", lambda ip: {"status": "private_ip", "detail": None, "reputation": None})
    assert gw.lookup("abuseipdb", "ip", "10.0.0.1")["status"] == base.STATUS_UNSUPPORTED
