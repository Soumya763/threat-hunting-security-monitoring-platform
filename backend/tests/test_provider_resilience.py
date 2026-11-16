"""Provider failure isolation, on-demand checks and provider summaries. No network: requests is stubbed."""

import json

import pytest
import requests

from app.config import settings
from app.services import url_pipeline
from app.services.intel import base, providers
from app.services.intel.gateway import CHECK_TARGETS, IntelGateway, check_provider

SECRET = "super-secret-test-key-value-123"


class Resp:
    def __init__(self, status=200, body=None):
        self.status_code = status
        self._body = body or {}

    def json(self):
        return self._body


@pytest.fixture(autouse=True)
def _isolated(monkeypatch):
    for name in ("virustotal_api_key", "malwarebazaar_auth_key", "otx_api_key", "urlscan_api_key", "abuseipdb_api_key"):
        monkeypatch.setattr(settings, name, "")
    for cls in (providers.MalwareBazaarClient, providers.OTXClient, providers.UrlscanClient):
        monkeypatch.setattr(cls, "_limiter", base.RateLimiter(0, 10_000))
    monkeypatch.setattr(providers.virustotal, "limiter", base.RateLimiter(0, 10_000))
    monkeypatch.setattr(providers.time, "sleep", lambda s: None)

    def blocked(*a, **k):
        raise AssertionError("no network call expected")

    monkeypatch.setattr(providers.requests, "request", blocked)


def _fake_requests(monkeypatch, response):
    calls = []

    def fake(method, url, **kwargs):
        calls.append((method, url))
        if isinstance(response, BaseException):
            raise response
        return response

    monkeypatch.setattr(providers.requests, "request", fake)
    return calls


# ---------------------------------------------------------------- failure isolation

def test_unexpected_provider_exception_is_isolated_to_that_provider(monkeypatch):
    monkeypatch.setattr(settings, "virustotal_api_key", "k1")
    monkeypatch.setattr(settings, "otx_api_key", "k2")
    monkeypatch.setattr(providers.virustotal, "lookup", lambda *a: (_ for _ in ()).throw(ValueError("malformed JSON")))
    monkeypatch.setattr(providers.otx, "lookup", lambda t, v: base.result(
        "AlienVault OTX", t, v, base.STATUS_OK, summary={"pulse_count": 2}))

    gw = IntelGateway()
    vt = gw.lookup("virustotal", "domain", "example.com")
    otx = gw.lookup("otx", "domain", "example.com")

    assert vt["status"] == base.STATUS_UNAVAILABLE, "a crash must not be reported as clean or as a detection"
    assert vt["detection"] is None
    assert "Other providers were not affected" in vt["message"]
    assert otx["status"] == base.STATUS_OK and otx["summary"]["pulse_count"] == 2


def test_url_analysis_completes_when_a_provider_raises(monkeypatch):
    monkeypatch.setattr(settings, "virustotal_api_key", "k1")
    monkeypatch.setattr(settings, "otx_api_key", "k2")
    monkeypatch.setattr(providers.virustotal, "lookup", lambda *a: 1 / 0)
    monkeypatch.setattr(providers.otx, "lookup", lambda t, v: base.result(
        "AlienVault OTX", t, v, base.STATUS_NOT_FOUND))
    monkeypatch.setattr(url_pipeline, "lookup_addresses", lambda host: {
        "A": ["93.184.216.34"], "AAAA": [], "public": ["93.184.216.34"], "non_public": [], "error": None})
    monkeypatch.setattr(url_pipeline, "fetch_with_redirects", lambda u: {
        "hops": [{"url": "https://example.com/", "status": 200, "ip": "93.184.216.34"}],
        "final_url": "https://example.com/", "status": 200, "headers": {"content-type": "text/html"},
        "body": b"<title>Example</title>", "tls": None, "tls_problem": None, "redirect_count": 0,
        "blocked": None, "error": None})
    monkeypatch.setattr(url_pipeline, "lookup_domain", lambda d: {"status": "ok", "age_days": 9000})

    result = url_pipeline.analyze_url("https://example.com/", gateway=IntelGateway())

    assert result["providers"]["VirusTotal URL"]["status"] == base.STATUS_UNAVAILABLE
    assert result["providers"]["OTX URL"]["status"] == base.STATUS_NOT_FOUND
    assert result["analysis_status"] == "partial"
    assert result["classification"] != "clean", "one failed provider must not produce a clean verdict"
    # VirusTotal URL + domain raised; OTX URL + domain answered "not found"; urlscan and AbuseIPDB have no key.
    assert result["provider_summary"] == {"applicable": 6, "checked": 2, "failed": 2, "not_configured": 2}


# ---------------------------------------------------------------- summary

def test_provider_summary_counts_applicable_checked_failed_and_not_configured():
    results = {
        "VirusTotal URL": base.result("VirusTotal", "url", "u", base.STATUS_OK),
        "OTX URL": base.result("OTX", "url", "u", base.STATUS_TIMEOUT),
        "urlscan": base.result("urlscan.io", "domain", "d", base.STATUS_NOT_CONFIGURED),
        "VirusTotal domain": base.result("VirusTotal", "domain", "d", base.STATUS_UNSUPPORTED),
        "urlscan submission": base.result("urlscan.io", "url", "u", base.STATUS_SUBMITTED),
    }
    assert base.summarize_providers(results) == {"applicable": 3, "checked": 1, "failed": 1, "not_configured": 1}


# ---------------------------------------------------------------- on-demand check

def test_check_without_key_makes_no_request_and_says_how_to_configure(monkeypatch):
    out = check_provider("virustotal")
    assert out["configured"] is False
    assert out["operational"] is None
    assert out["status"] == base.STATUS_NOT_CONFIGURED
    assert "VIRUSTOTAL_API_KEY" in out["message"]


def test_check_with_accepted_key_reports_operational(monkeypatch):
    monkeypatch.setattr(settings, "virustotal_api_key", SECRET)
    _fake_requests(monkeypatch, Resp(200, {"data": {"attributes": {"last_analysis_stats": {
        "malicious": 0, "suspicious": 0, "undetected": 70, "harmless": 10}}}}))
    out = check_provider("virustotal")
    assert out["configured"] is True
    assert out["operational"] is True
    assert out["status"] == base.STATUS_OK


def test_check_with_rejected_key_reports_not_operational(monkeypatch):
    monkeypatch.setattr(settings, "otx_api_key", SECRET)
    _fake_requests(monkeypatch, Resp(403, {}))
    out = check_provider("otx")
    assert out["operational"] is False
    assert out["status"] == base.STATUS_INVALID_KEY
    assert "rejected" in out["message"]


def test_check_timeout_is_not_reported_as_operational(monkeypatch):
    monkeypatch.setattr(settings, "urlscan_api_key", SECRET)
    _fake_requests(monkeypatch, requests.Timeout("slow"))
    out = check_provider("urlscan")
    assert out["operational"] is False
    assert out["status"] == base.STATUS_TIMEOUT


def test_check_rate_limit_is_inconclusive(monkeypatch):
    monkeypatch.setattr(settings, "urlscan_api_key", SECRET)
    _fake_requests(monkeypatch, Resp(429, {}))
    out = check_provider("urlscan")
    assert out["operational"] is None
    assert out["status"] == base.STATUS_RATE_LIMITED


def test_check_never_returns_or_logs_the_key(monkeypatch):
    monkeypatch.setattr(settings, "otx_api_key", SECRET)
    _fake_requests(monkeypatch, Resp(401, {}))
    serialized = json.dumps(check_provider("otx"))
    assert SECRET not in serialized


def test_check_uses_only_benign_lookups_never_submissions(monkeypatch):
    monkeypatch.setattr(settings, "urlscan_api_key", SECRET)
    monkeypatch.setattr(settings, "virustotal_api_key", SECRET)
    calls = _fake_requests(monkeypatch, Resp(200, {"results": []}))
    check_provider("urlscan")
    assert calls and all(method == "GET" for method, _ in calls)
    assert all("/scan" not in url for _, url in calls)


def test_check_targets_are_documented_benign_indicators():
    assert CHECK_TARGETS["virustotal"] == ("domain", "example.com")
    assert CHECK_TARGETS["abuseipdb"] == ("ip", "8.8.8.8")
    assert len(CHECK_TARGETS["malwarebazaar"][1]) == 64


def test_unknown_provider_cannot_be_checked():
    assert check_provider("rdap")["status"] == base.STATUS_UNSUPPORTED
    assert check_provider("nope")["status"] == base.STATUS_UNSUPPORTED
