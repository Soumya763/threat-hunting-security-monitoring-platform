"""
Unified threat-intelligence search. Accepts an IP address, domain, URL, or an
MD5, SHA-1 or SHA-256 hash, then combines:

  - this analyst's earlier analyses of the same indicator (PostgreSQL),
  - alerts whose source IP or entity matches the indicator (PostgreSQL),
  - local log events for the indicator (OpenSearch pivot),
  - configured external providers (each reports its own status).

Nothing here invents a verdict: a provider that is missing, unreachable or
rate limited is shown as such, and only consulted sources count toward the
"clean" classification.
"""

import ipaddress
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.analysis import scoring
from app.analysis.rdap import lookup_domain
from app.analysis.ssrf import UnsafeURLError, validate_url
from app.analysis.urlrules import looks_like_hostname, registrable_domain
from app.models.alert import Alert
from app.models.analysis import Analysis
from app.services import pivot
from app.services.intel import base
from app.services.intel.gateway import get_gateway
from app.services.recommendations import recommend

_HASH_RE = {
    "md5": re.compile(r"[a-fA-F0-9]{32}"),
    "sha1": re.compile(r"[a-fA-F0-9]{40}"),
    "sha256": re.compile(r"[a-fA-F0-9]{64}"),
}


class IndicatorError(ValueError):
    """Raised when the query is not a supported indicator. Message is user-safe."""


def detect_indicator(query: str) -> tuple[str, str]:
    value = (query or "").strip()
    if not value:
        raise IndicatorError("Enter an IP address, domain, URL, or file hash.")
    if len(value) > 2048:
        raise IndicatorError("The indicator is too long.")

    for kind, pattern in _HASH_RE.items():
        if pattern.fullmatch(value):
            return kind, value.lower()

    try:
        ipaddress.ip_address(value)
        return "ip", value
    except ValueError:
        pass

    if value.lower().startswith(("http://", "https://")):
        try:
            return "url", validate_url(value)["url"]
        except UnsafeURLError as exc:
            raise IndicatorError(str(exc)) from exc

    if looks_like_hostname(value):
        return "domain", value.lower().rstrip(".")

    raise IndicatorError(
        "Unsupported format. Use an IP address, a domain name, an http(s) URL, "
        "or an MD5, SHA-1 or SHA-256 hash."
    )


def _local_history(db: Session, owner_id: int, indicator_type: str, value: str, exclude_id: int) -> list[dict[str, Any]]:
    stmt = (
        select(Analysis)
        .where(Analysis.owner_id == owner_id, Analysis.id != exclude_id)
        .where(or_(Analysis.indicator_value == value, Analysis.sha256 == value))
        .order_by(Analysis.created_at.desc())
        .limit(20)
    )
    return [
        {"id": a.id, "kind": a.kind, "risk_level": a.risk_level, "risk_score": a.risk_score,
         "created_at": a.created_at.isoformat() if a.created_at else None}
        for a in db.scalars(stmt)
    ]


def _related_alerts(db: Session, indicator_type: str, value: str) -> list[dict[str, Any]]:
    conditions = []
    if indicator_type == "ip":
        conditions = [Alert.source_ip == value, (Alert.entity_type == "ip") & (Alert.entity_key == value)]
    elif indicator_type in ("domain", "url"):
        host = urlsplit(value).hostname if indicator_type == "url" else value
        if host:
            conditions = [(Alert.entity_type == "domain") & (Alert.entity_key == host)]
    if not conditions:
        return []
    stmt = select(Alert).where(or_(*conditions)).order_by(Alert.created_at.desc()).limit(20)
    return [
        {"id": a.id, "event_type": a.event_type, "severity": a.severity.value, "status": a.status.value,
         "incident_id": a.incident_id, "created_at": a.created_at.isoformat() if a.created_at else None}
        for a in db.scalars(stmt)
    ]


def _provider_plan(indicator_type: str, value: str, gateway) -> dict[str, Any]:
    results: dict[str, Any] = {}
    if indicator_type == "ip":
        results["VirusTotal"] = gateway.lookup("virustotal", "ip", value)
        results["AlienVault OTX"] = gateway.lookup("otx", "ip", value)
        results["AbuseIPDB"] = gateway.lookup("abuseipdb", "ip", value)
    elif indicator_type == "domain":
        results["VirusTotal"] = gateway.lookup("virustotal", "domain", value)
        results["AlienVault OTX"] = gateway.lookup("otx", "domain", value)
        results["urlscan.io"] = gateway.lookup("urlscan", "domain", value)
    elif indicator_type == "url":
        host = urlsplit(value).hostname or ""
        results["VirusTotal"] = gateway.lookup("virustotal", "url", value)
        results["AlienVault OTX"] = gateway.lookup("otx", "url", value)
        results["urlscan.io"] = gateway.lookup("urlscan", "domain", host) if looks_like_hostname(host) else base.result(
            "urlscan.io", "domain", host, base.STATUS_UNSUPPORTED, message="urlscan search needs a domain name.")
    else:  # hashes
        results["VirusTotal"] = gateway.lookup("virustotal", indicator_type, value)
        results["MalwareBazaar"] = gateway.lookup("malwarebazaar", indicator_type, value)
        results["AlienVault OTX"] = gateway.lookup("otx", indicator_type, value)
    return results


def run_indicator_search(analysis_id: int, *, session_factory, gateway=None) -> None:
    from app.models.analysis import Analysis as AnalysisModel

    db = session_factory()
    try:
        row = db.get(AnalysisModel, analysis_id)
        if row is None:
            return
        row.status = "running"
        db.commit()

        indicator_type, value = row.indicator_type, row.indicator_value
        gateway = gateway or get_gateway()
        steps: list[dict[str, Any]] = []
        caveats: list[str] = []

        providers_out = _provider_plan(indicator_type, value, gateway)
        steps.append({"name": "External providers", "status": "complete", "message": None})

        history = _local_history(db, row.owner_id, indicator_type, value, row.id)
        related = _related_alerts(db, indicator_type, value)
        pivot_value = urlsplit(value).hostname if indicator_type == "url" else value
        local_pivot = pivot.search_local_context(pivot_value or value)
        steps.append({"name": "Local history, alerts and logs", "status": "complete"
                      if local_pivot["status"] == "ok" else "failed",
                      "message": local_pivot.get("message")})

        rdap = None
        if indicator_type in ("domain", "url"):
            host = value if indicator_type == "domain" else (urlsplit(value).hostname or "")
            if looks_like_hostname(host):
                rdap = lookup_domain(registrable_domain(host))
                providers_out["RDAP"] = {
                    "provider": "RDAP", "indicator_type": "domain", "indicator": registrable_domain(host),
                    "status": rdap["status"] if rdap["status"] in ("ok", "not_found") else rdap["status"],
                    "detection": None,
                    "summary": {k: rdap.get(k) for k in ("registered_at", "age_days", "registrar", "nameservers")}
                    if rdap["status"] == "ok" else {},
                    "message": rdap.get("message"), "fetched_at": datetime.now(timezone.utc).isoformat(),
                    "cached": False,
                }

        consulted = sum(1 for r in providers_out.values() if r["status"] in base.CONSULTED_STATUSES)
        detections = []
        for name, r in providers_out.items():
            if r["status"] == base.STATUS_OK and r.get("detection"):
                detections.append((f"{name}", r["detection"]["positives"], r["detection"]["total"]))

        mb = providers_out.get("MalwareBazaar")
        mb_hit = bool(mb and mb["status"] == base.STATUS_OK)
        otx_pulses = max((r["summary"].get("pulse_count", 0) for r in providers_out.values()
                          if r["provider"].startswith("AlienVault") and r["status"] == base.STATUS_OK), default=0)
        abuse = providers_out.get("AbuseIPDB")
        abuse_score = abuse["summary"].get("abuse_confidence_score") if abuse and abuse["status"] == base.STATUS_OK else None
        urlscan_bad = 0
        for name in ("urlscan.io",):
            r = providers_out.get(name)
            if r and r["status"] == base.STATUS_OK:
                urlscan_bad = r["summary"].get("malicious_scans", 0)

        failures = [n for n, r in providers_out.items() if r["status"] in
                    ("unavailable", "timeout", "invalid_key", "rate_limited")]
        if failures:
            caveats.append("Some providers were unavailable or rate limited: " + ", ".join(failures) + ".")
        if local_pivot["status"] != "ok":
            caveats.append("Local log search did not run, so local activity is unknown.")

        score = scoring.indicator_score(
            detections=detections,
            malwarebazaar_hit=mb_hit,
            otx_pulses=otx_pulses,
            abuseipdb_score=abuse_score,
            abuseipdb_ip=value if indicator_type == "ip" else None,
            urlscan_malicious=urlscan_bad,
            consulted_sources=consulted,
            local_complete=local_pivot["status"] == "ok",
            extra_caveats=caveats,
        )
        level = score["level"]
        if related or (local_pivot.get("total") or 0) > 0:
            score["caveats"].insert(0, "This indicator appears in local alerts or logs. Review those records before deciding.")
        recommendations = recommend(
            level,
            providers_configured=any(r["status"] != base.STATUS_NOT_CONFIGURED for r in providers_out.values()),
            kind="indicator",
        )
        if (local_pivot.get("total") or 0) > 0:
            recommendations.insert(0, "Open the matching local events and check which hosts or users were involved.")

        row.result = {
            "indicator_type": indicator_type,
            "indicator": value,
            "providers": providers_out,
            "local": {"history": history, "related_alerts": related, "pivot": local_pivot},
            "rdap": rdap,
            "score": score["score"],
            "classification": level,
            "classification_label": score["level_label"],
            "factors": score["factors"],
            "caveats": score["caveats"],
            "recommendations": recommendations,
            "steps": steps,
            "consulted_sources": consulted,
            "analysed_at": datetime.now(timezone.utc).isoformat(),
        }
        row.risk_score = score["score"]
        row.risk_level = level
        row.status = "complete" if not failures and local_pivot["status"] == "ok" else "partial"
        row.completed_at = datetime.now(timezone.utc)
        db.commit()
    except Exception:
        db.rollback()
        row = db.get(Analysis, analysis_id)
        if row is not None:
            row.status = "failed"
            row.error = "The search stopped unexpectedly. Try again later."
            row.completed_at = datetime.now(timezone.utc)
            db.commit()
    finally:
        db.close()
