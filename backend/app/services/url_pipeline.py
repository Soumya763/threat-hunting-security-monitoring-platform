"""
URL analysis pipeline. Runs in a background task; the API returns immediately
with an analysis id and the client polls.

Order of work (each step records its own status, so the report shows what was
and was not completed):
  1. validate and normalise the URL (SSRF rules)
  2. DNS A/AAAA for the host; only public addresses are used further
  3. guarded fetch of the URL, following redirects with per-hop validation
  4. passive HTML inspection of the final page (no scripts run)
  5. RDAP registration data for the registrable domain
  6. threat-intelligence lookups (each optional; missing keys are reported)
  7. explainable scoring and classification
"""

import logging
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from app.analysis import scoring
from app.analysis.dnsinfo import lookup_addresses
from app.analysis.fetch import fetch_with_redirects
from app.analysis.page import inspect_html
from app.analysis.rdap import lookup_domain
from app.analysis.ssrf import UnsafeURLError, is_public_ip, validate_url
from app.analysis.urlrules import (
    is_ip_literal,
    is_punycode,
    is_suspicious_tld,
    is_deep,
    lookalike_of,
    looks_like_hostname,
    registrable_domain,
)
from app.services.intel import base, providers
from app.services.intel.gateway import get_gateway
from app.services.recommendations import recommend

logger = logging.getLogger(__name__)

PROVIDER_ERROR_STATUSES = frozenset({
    base.STATUS_UNAVAILABLE, base.STATUS_TIMEOUT, base.STATUS_INVALID_KEY, base.STATUS_RATE_LIMITED,
})


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _step(name: str, status: str, message: str | None = None) -> dict[str, Any]:
    return {"name": name, "status": status, "message": message}


def _days_until(date_text: str | None) -> int | None:
    if not date_text:
        return None
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            parsed = datetime.strptime(date_text, fmt).replace(tzinfo=timezone.utc)
            return (parsed - _now()).days
        except ValueError:
            continue
    return None


def analyze_url(raw_url: str, *, gateway=None, submit_to_urlscan: bool = False) -> dict[str, Any]:
    """Run the full URL analysis. Raises UnsafeURLError only for an invalid submitted URL."""
    gateway = gateway or get_gateway()
    steps: list[dict[str, Any]] = []
    caveats: list[str] = []

    checked = validate_url(raw_url)  # raises UnsafeURLError
    normalized, host = checked["url"], checked["host"]
    ip_host = is_ip_literal(host)
    steps.append(_step("Validate and normalise URL", "complete"))

    # 2. DNS
    if ip_host:
        dns = {"A": [host] if ":" not in host else [], "AAAA": [host] if ":" in host else [],
               "public": [host] if is_public_ip(host) else [], "non_public": [] if is_public_ip(host) else [host],
               "error": None}
        steps.append(_step("DNS lookup", "skipped", "Host is an IP address."))
    else:
        dns = lookup_addresses(host)
        steps.append(_step("DNS lookup", "failed" if dns["error"] else "complete", dns["error"]))

    # 3. Guarded fetch
    fetch = fetch_with_redirects(normalized)
    blocked_redirects = [h for h in fetch["hops"] if h.get("blocked") and h is not fetch["hops"][0]]
    if fetch["blocked"]:
        steps.append(_step("Guarded fetch", "blocked", fetch["blocked"]))
    elif fetch["error"]:
        steps.append(_step("Guarded fetch", "failed", fetch["error"]))
    else:
        steps.append(_step("Guarded fetch", "complete"))
    fetch_error = fetch["error"]
    non_public_redirect = None
    if blocked_redirects:
        non_public_redirect = ("A redirect pointed to a non-public or invalid address and was not followed: "
                               + blocked_redirects[0]["blocked"])
        caveats.append("A redirect was blocked by the SSRF guard; the analysis did not follow it.")

    final_url = fetch["final_url"]
    final_host = (urlsplit(final_url).hostname or host) if final_url else host

    # 4. Page inspection
    page = None
    content_type = (fetch["headers"].get("content-type") or "").lower()
    if fetch["body"] and ("html" in content_type or not content_type):
        page = inspect_html(fetch["body"], final_url or normalized)
        steps.append(_step("Page inspection", "complete"))
    elif fetch["body"]:
        steps.append(_step("Page inspection", "skipped", "Response is not HTML."))
    else:
        steps.append(_step("Page inspection", "skipped", "No page content was retrieved."))

    # 5. RDAP
    reg = registrable_domain(host) if not ip_host else host
    rdap = None
    if not ip_host and looks_like_hostname(host):
        rdap = lookup_domain(reg)
        steps.append(_step("Domain registration (RDAP)", "complete" if rdap["status"] in ("ok", "not_found") else "failed", rdap.get("message")))
    else:
        steps.append(_step("Domain registration (RDAP)", "skipped", "Not applicable to IP addresses."))

    # 6. Providers
    provider_results: dict[str, Any] = {}
    provider_results["VirusTotal URL"] = gateway.lookup("virustotal", "url", normalized)
    provider_results["VirusTotal domain"] = gateway.lookup("virustotal", "domain", host) if looks_like_hostname(host) else base.result(
        "VirusTotal", "domain", host, base.STATUS_UNSUPPORTED, message="Not a domain name.")
    provider_results["OTX URL"] = gateway.lookup("otx", "url", normalized)
    provider_results["OTX domain"] = gateway.lookup("otx", "domain", host) if looks_like_hostname(host) else base.result(
        "AlienVault OTX", "domain", host, base.STATUS_UNSUPPORTED, message="Not a domain name.")
    if looks_like_hostname(host):
        provider_results["urlscan"] = gateway.lookup("urlscan", "domain", host)
    else:
        provider_results["urlscan"] = base.result("urlscan.io", "domain", host, base.STATUS_UNSUPPORTED,
                                                  message="urlscan search needs a domain name.")

    abuse_ips = [ip for ip in dns["public"][:3]] if not ip_host else ([host] if is_public_ip(host) else [])
    abuse_results = [gateway.lookup("abuseipdb", "ip", ip) for ip in abuse_ips]
    for ip, res in zip(abuse_ips, abuse_results):
        provider_results[f"AbuseIPDB {ip}"] = res

    if submit_to_urlscan:
        provider_results["urlscan submission"] = providers.urlscan.submit_url(normalized)
    steps.append(_step("Threat-intelligence lookups", "complete"))

    consulted = sum(1 for r in provider_results.values() if r["status"] in base.CONSULTED_STATUSES)
    provider_failures = [name for name, r in provider_results.items() if r["status"] in PROVIDER_ERROR_STATUSES]
    if provider_failures:
        caveats.append("Some providers were unavailable or rate limited: " + ", ".join(provider_failures) + ".")

    # 7. Scoring
    detections = []
    for key in ("VirusTotal URL", "VirusTotal domain"):
        r = provider_results[key]
        if r["status"] == base.STATUS_OK and r["detection"]:
            detections.append((key, r["detection"]["positives"], r["detection"]["total"]))
    pulses = max(
        (provider_results[k]["summary"].get("pulse_count", 0) for k in ("OTX URL", "OTX domain")
         if provider_results[k]["status"] == base.STATUS_OK),
        default=0,
    )
    urlscan_malicious = (provider_results["urlscan"]["summary"].get("malicious_scans", 0)
                         if provider_results["urlscan"]["status"] == base.STATUS_OK else 0)
    abuse_scores = [
        (ip, res["summary"]["abuse_confidence_score"])
        for ip, res in zip(abuse_ips, abuse_results)
        if res["status"] == base.STATUS_OK and res["summary"].get("abuse_confidence_score") is not None
    ]
    tls = fetch.get("tls")
    tls_problem = fetch.get("tls_problem")
    days_remaining = _days_until(tls.get("not_after")) if tls else None
    if tls and days_remaining is not None and days_remaining < 0 and not tls_problem:
        tls_problem = "Certificate has expired."

    age = rdap.get("age_days") if rdap and rdap.get("status") == "ok" else None
    lookalike = lookalike_of(host) if not ip_host else None
    login_form = bool(page and page.get("password_field"))

    # Local checks are complete when DNS answered and the fetch either succeeded
    # or was deliberately blocked by the SSRF guard (a blocked hop is a finding).
    local_complete = (not dns["error"]) and (fetch_error is None)

    factor_inputs = dict(
        host=host,
        registrable_domain=reg,
        final_registrable_domain=registrable_domain(final_host) if final_url and not ip_host else None,
        redirect_count=fetch.get("redirect_count", 0),
        is_ip_literal=ip_host,
        is_punycode=is_punycode(host),
        suspicious_tld=is_suspicious_tld(host) if not ip_host else False,
        deep_subdomains=is_deep(host) if not ip_host else False,
        lookalike_of=lookalike,
        login_form=login_form,
        scheme=checked["scheme"],
        tls_problem=tls_problem,
        domain_age_days=age,
        non_public_redirect=non_public_redirect,
        provider_detections=detections,
        otx_pulses=pulses,
        urlscan_malicious=urlscan_malicious,
        abuseipdb=abuse_scores,
    )
    score = scoring.build_url_score(
        consulted_sources=consulted,
        local_complete=local_complete,
        extra_caveats=caveats,
        **factor_inputs,
    )

    level = score["level"]
    recommendations = recommend(level, providers_configured=any(
        r["status"] != base.STATUS_NOT_CONFIGURED for r in provider_results.values()),
        kind="url", consent_available=True)
    if login_form:
        recommendations.insert(0, "Do not enter credentials on this page.")

    status = "complete"
    if not local_complete or provider_failures or fetch_error:
        status = "partial"

    phishing = []
    if login_form:
        phishing.append("The page asks for a password.")
    if page and page.get("cross_origin_form_targets"):
        phishing.append("A form submits to another domain: " + ", ".join(page["cross_origin_form_targets"]) + ".")
    if page and page.get("meta_refresh_target"):
        phishing.append("The page redirects automatically via a meta refresh.")
    if page and page.get("script_redirect"):
        phishing.append("The page contains a script-based redirect (not followed).")
    if lookalike:
        phishing.append(f"The domain imitates '{lookalike}'.")

    return {
        "submitted_url": raw_url,
        "normalized_url": normalized,
        "final_url": final_url,
        "host": host,
        "registrable_domain": reg,
        "is_ip_address": ip_host,
        "dns": {
            "A": dns["A"], "AAAA": dns["AAAA"],
            "public_addresses": dns["public"], "non_public_addresses": dns["non_public"],
            "error": dns["error"],
        },
        "resolved_ips": dns["public"],
        "redirect_chain": fetch["hops"],
        "http_status": fetch.get("status"),
        "content_type": content_type or None,
        "server": fetch["headers"].get("server"),
        "tls": ({**tls, "days_remaining": days_remaining} if tls else None),
        "tls_problem": tls_problem,
        "page": page,
        "phishing_indicators": phishing,
        "lookalike_of": lookalike,
        "rdap": rdap,
        "providers": provider_results,
        "score": score["score"],
        "classification": level,
        "classification_label": score["level_label"],
        "factors": score["factors"],
        "caveats": score["caveats"],
        "recommendations": recommendations,
        "steps": steps,
        "analysis_status": status,
        "local_checks_complete": local_complete,
        "consulted_sources": consulted,
        "analysed_at": _now().isoformat(),
    }


def run_url_analysis(analysis_id: int, *, session_factory, gateway=None, submit_to_urlscan: bool = False) -> None:
    from app.models.analysis import Analysis

    db = session_factory()
    try:
        row = db.get(Analysis, analysis_id)
        if row is None:
            return
        row.status = "running"
        db.commit()
        try:
            result = analyze_url(row.indicator_value, gateway=gateway, submit_to_urlscan=submit_to_urlscan)
        except UnsafeURLError as exc:
            row.status = "failed"
            row.error = str(exc)
            row.completed_at = _now()
            db.commit()
            return
        except Exception:
            logger.exception("URL analysis %s failed", analysis_id)
            row.status = "failed"
            row.error = "The analysis stopped unexpectedly. Try again later."
            row.completed_at = _now()
            db.commit()
            return

        row.result = result
        row.risk_score = result["score"]
        row.risk_level = result["classification"]
        row.status = result["analysis_status"]
        row.completed_at = _now()
        db.commit()
    finally:
        db.close()
