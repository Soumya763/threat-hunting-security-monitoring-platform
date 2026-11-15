"""URL analysis: lookalike detection, page inspection, and end-to-end scoring with stubbed I/O."""

import pytest

from app.analysis import page, urlrules
from app.services import url_pipeline
from app.services.intel import base
from app.analysis.ssrf import UnsafeURLError


class StubGateway:
    """Returns a configured result per (provider, type, value); otherwise 'not configured'."""

    def __init__(self, answers=None):
        self.answers = answers or {}

    def lookup(self, provider, indicator_type, value):
        key = (provider, indicator_type)
        if key in self.answers:
            return self.answers[key](value) if callable(self.answers[key]) else self.answers[key]
        return base.result(provider, indicator_type, value, base.STATUS_NOT_CONFIGURED,
                           message="not configured for test")


def _vt_ok(positives, total):
    return lambda v: base.result("VirusTotal", "url", v, base.STATUS_OK, detection=(positives, total))


@pytest.mark.parametrize("host,brand", [
    ("paypa1-secure.com", "paypal.com"),
    ("micros0ft-login.net", "microsoft.com"),
    ("google-accounts-verify.xyz", "google.com"),
    ("gogle.com", "google.com"),
])
def test_lookalike_domains_are_detected(host, brand):
    assert urlrules.lookalike_of(host) == brand


@pytest.mark.parametrize("host", ["paypal.com", "login.paypal.com", "google.com", "accounts.google.com", "example.org"])
def test_legitimate_or_unrelated_domains_are_not_flagged(host):
    assert urlrules.lookalike_of(host) is None


def test_registrable_domain_handles_common_second_level_suffixes():
    assert urlrules.registrable_domain("a.b.example.co.uk") == "example.co.uk"
    assert urlrules.registrable_domain("login.example.com") == "example.com"


def test_page_inspection_finds_password_form_cross_origin_post_and_meta_refresh():
    html = (b'<html><title> Sign in </title><form action="https://collector.example/x">'
            b'<input type="password"></form><meta http-equiv="refresh" content="0; url=https://next.example/">'
            b'<script>window.location.href="https://z.example"</script></html>')
    info = page.inspect_html(html, "https://paypa1-secure.com/login")
    assert info["title"] == "Sign in"
    assert info["password_field"] is True
    assert info["cross_origin_form_targets"] == ["collector.example"]
    assert info["meta_refresh_target"] == "https://next.example/"
    assert info["script_redirect"] is True


def _run(monkeypatch, *, url, dns, fetch, rdap, gateway):
    monkeypatch.setattr(url_pipeline, "lookup_addresses", lambda host: dns)
    monkeypatch.setattr(url_pipeline, "fetch_with_redirects", lambda u: fetch)
    monkeypatch.setattr(url_pipeline, "lookup_domain", lambda d: rdap)
    return url_pipeline.analyze_url(url, gateway=gateway)


def _dns(public):
    return {"A": public, "AAAA": [], "public": public, "non_public": [], "error": None}


def _fetch(body=b"", status=200, hops=None, blocked=None, final=None, headers=None, tls=None, tls_problem=None):
    return {
        "hops": hops or [{"url": final or "https://x/", "status": status, "ip": "93.184.216.34"}],
        "final_url": final, "status": status, "headers": headers or {"content-type": "text/html"},
        "body": body, "tls": tls, "tls_problem": tls_problem, "redirect_count": 0,
        "blocked": blocked, "error": None,
    }


def test_phishing_page_on_new_lookalike_domain_scores_high_and_explains_factors(monkeypatch):
    body = b'<title>PayPal</title><form action="https://collector.example/post"><input type="password"></form>'
    result = _run(
        monkeypatch,
        url="https://paypa1-secure.com/login",
        dns=_dns(["93.184.216.34"]),
        fetch=_fetch(body=body, final="https://paypa1-secure.com/login"),
        rdap={"status": "ok", "age_days": 3, "registrar": "Example", "registered_at": "x"},
        gateway=StubGateway({("virustotal", "url"): _vt_ok(9, 80)}),
    )
    codes = {f["code"] for f in result["factors"]}
    assert {"lookalike_domain", "login_form", "domain_very_new", "engine_detections"} <= codes
    assert result["score"] >= 50
    assert result["classification"] in ("high", "critical")
    assert "Do not enter credentials on this page." in result["recommendations"]
    assert result["lookalike_of"] == "paypal.com"


def test_established_domain_with_zero_detections_is_clean_only_with_a_consulted_source(monkeypatch):
    result = _run(
        monkeypatch,
        url="https://example.com/",
        dns=_dns(["93.184.216.34"]),
        fetch=_fetch(body=b"<html><title>Example</title></html>", final="https://example.com/"),
        rdap={"status": "ok", "age_days": 9000, "registrar": "x", "registered_at": "x"},
        gateway=StubGateway({("virustotal", "url"): _vt_ok(0, 80)}),
    )
    assert result["score"] == 0
    assert result["classification"] == "clean"
    assert "does not guarantee that it is safe" in result["caveats"][0]


def test_no_provider_configured_is_insufficient_evidence_not_clean(monkeypatch):
    result = _run(
        monkeypatch,
        url="https://example.com/",
        dns=_dns(["93.184.216.34"]),
        fetch=_fetch(body=b"<html></html>", final="https://example.com/"),
        rdap={"status": "unavailable", "message": "down"},
        gateway=StubGateway(),
    )
    assert result["classification"] == "insufficient_evidence"
    assert any("No external provider" in r for r in result["recommendations"])


def test_blocked_redirect_is_reported_as_a_factor(monkeypatch):
    hops = [
        {"url": "https://short.example/x", "status": 302, "location": "http://10.0.0.5/"},
        {"url": "http://10.0.0.5/", "status": None, "blocked": "The host resolves to a non-public address and was blocked."},
    ]
    result = _run(
        monkeypatch,
        url="https://short.example/x",
        dns=_dns(["93.184.216.34"]),
        fetch={**_fetch(hops=hops), "blocked": "The host resolves to a non-public address and was blocked.", "status": None, "body": b""},
        rdap={"status": "ok", "age_days": 4000, "registrar": "x", "registered_at": "x"},
        gateway=StubGateway(),
    )
    assert "redirect_to_non_public_address" in {f["code"] for f in result["factors"]}


def test_invalid_or_private_submission_never_reaches_the_network(monkeypatch):
    def boom(*_a, **_k):
        raise AssertionError("network must not be used for a rejected URL")

    monkeypatch.setattr(url_pipeline, "lookup_addresses", boom)
    monkeypatch.setattr(url_pipeline, "fetch_with_redirects", boom)
    monkeypatch.setattr(url_pipeline, "lookup_domain", boom)
    with pytest.raises(UnsafeURLError):
        url_pipeline.analyze_url("http://127.0.0.1/admin", gateway=StubGateway())


def test_unresolvable_host_marks_dns_step_failed_and_analysis_partial(monkeypatch):
    """Regression: a host with no public address was reported as a complete analysis."""
    result = _run(
        monkeypatch,
        url="https://nothing-here.invalid/",
        dns={"A": [], "AAAA": [], "public": [], "non_public": [], "error": None},
        fetch={**_fetch(), "blocked": "The host name could not be resolved.", "body": b"", "status": None,
               "final_url": None, "hops": [{"url": "https://nothing-here.invalid/", "status": None,
                                            "blocked": "The host name could not be resolved."}]},
        rdap={"status": "not_found", "message": "none"},
        gateway=StubGateway(),
    )
    dns_step = next(s for s in result["steps"] if s["name"] == "DNS lookup")
    assert dns_step["status"] == "failed"
    assert "public address" in dns_step["message"]
    assert result["analysis_status"] == "partial"
    assert result["local_checks_complete"] is False


def test_tls_problem_messages_describe_the_actual_failure():
    import ssl
    from app.analysis.fetch import _tls_problem_message

    class E(ssl.SSLError):
        def __init__(self, msg):
            super().__init__(msg)

    assert "self-signed" in _tls_problem_message(E("certificate verify failed: self-signed certificate in certificate chain"))
    assert "issuer is not trusted" in _tls_problem_message(E("unable to get local issuer certificate"))
    assert "expired" in _tls_problem_message(E("certificate has expired"))
    assert "does not match" in _tls_problem_message(E("Hostname mismatch, certificate is not valid for 'x'"))


def test_registration_data_alone_never_makes_an_indicator_clean():
    """Regression: RDAP (registration data) answered 'ok' and made an unconfigured domain 'clean'."""
    from app.services.indicator_search import threat_sources_consulted
    providers = {
        "VirusTotal": base.result("VirusTotal", "domain", "x", base.STATUS_NOT_CONFIGURED),
        "AlienVault OTX": base.result("OTX", "domain", "x", base.STATUS_NOT_CONFIGURED),
        "RDAP": base.result("RDAP", "domain", "x", base.STATUS_OK, summary={"age_days": 3000}),
    }
    assert threat_sources_consulted(providers) == 0
    providers["VirusTotal"] = base.result("VirusTotal", "domain", "x", base.STATUS_OK, detection=(0, 80))
    assert threat_sources_consulted(providers) == 1
