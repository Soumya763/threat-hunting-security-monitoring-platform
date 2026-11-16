"""
Domain registration data via RDAP (the JSON successor to WHOIS).

Queries the configured RDAP bootstrap service (default rdap.org), which
redirects to the authoritative registry. The request is a fixed, server-side
call that carries only the registrable domain. Only a few summary fields are
kept; the full response is not stored.
"""

from datetime import datetime, timezone
from typing import Any

import requests

from app.config import settings


def _parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _registrar(entities: list[dict[str, Any]]) -> str | None:
    for entity in entities or []:
        if "registrar" in (entity.get("roles") or []):
            vcard = entity.get("vcardArray")
            if isinstance(vcard, list) and len(vcard) == 2:
                for field in vcard[1]:
                    if field and field[0] == "fn":
                        return str(field[3])[:200]
    return None


def lookup_domain(domain: str, now: datetime | None = None) -> dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    url = f"{settings.rdap_base_url.rstrip('/')}/domain/{domain}"
    try:
        response = requests.get(
            url,
            headers={"Accept": "application/rdap+json, application/json;q=0.5"},
            timeout=settings.provider_timeout_seconds,
        )
    except requests.Timeout:
        return {"status": "timeout", "message": "RDAP lookup timed out."}
    except requests.RequestException:
        return {"status": "unavailable", "message": "RDAP service could not be reached."}

    if response.status_code == 404:
        return {"status": "not_found", "message": "No RDAP record for this domain."}
    if response.status_code == 429:
        return {"status": "rate_limited", "message": "RDAP service rate limit reached."}
    if response.status_code != 200:
        return {"status": "unavailable", "message": f"RDAP returned HTTP {response.status_code}."}

    try:
        body = response.json()
    except ValueError:
        return {"status": "unavailable", "message": "RDAP returned an unreadable response."}

    events = {e.get("eventAction"): _parse_date(e.get("eventDate")) for e in body.get("events", []) or []}
    registered = events.get("registration")
    age_days = (now - registered).days if registered else None
    return {
        "status": "ok",
        "message": None,
        "registered_at": registered.isoformat() if registered else None,
        "expires_at": events["expiration"].isoformat() if events.get("expiration") else None,
        "age_days": age_days,
        "registrar": _registrar(body.get("entities", [])),
        "nameservers": [ns.get("ldhName") for ns in body.get("nameservers", []) or [] if ns.get("ldhName")][:10],
        "statuses": list(body.get("status", []) or [])[:10],
    }
