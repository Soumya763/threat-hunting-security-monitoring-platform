"""
IP reputation enrichment via AbuseIPDB (Phase 4: Threat Intelligence).

This module is the ONLY place in the codebase that talks to AbuseIPDB.
It is called from exactly one place - the
`POST /api/v1/alerts/{alert_id}/reputation` endpoint in api/alerts.py -
never from detection, correlation, the scheduler, or anywhere else, so a
provider outage can never affect anything but that one on-demand lookup.

Configuration: set ABUSEIPDB_API_KEY in backend/.env (see
backend/.env.example for the full list of ABUSEIPDB_* settings and how
to obtain a free key at https://www.abuseipdb.com/account/api). Leaving
the key blank is a supported, valid state - `get_ip_reputation()` simply
returns status "not_configured" without attempting any network call, and
the rest of the platform is completely unaffected.

What happens when AbuseIPDB is unavailable: `get_ip_reputation()` never
raises. Timeouts, connection failures, unexpected HTTP statuses, and
malformed response bodies are all caught here and mapped to a `status`
string the caller can render directly (see the module-level docstring on
`get_ip_reputation` for the full list). Nothing above this module ever
needs to catch an exception from it.

Design notes:
- Fetched on demand, not persisted: a reputation score is a point-in-time
  signal from a third party, not part of this platform's own detection
  data, so it is never written to the `alerts` table. See the Phase 4
  plan for the full rationale.
- Only a small, non-durable, in-process TTL cache (keyed by IP address)
  sits in front of the provider, purely to avoid hammering AbuseIPDB when
  the same IP is checked repeatedly (shared source IPs across alerts, or
  an analyst clicking the button more than once). It is cleared on
  restart and is not a system of record - nothing depends on it
  surviving. This mirrors the existing `_LoginRateLimiter` in
  api/auth.py: a small `threading.Lock`-guarded dict, appropriate for
  this single-process application.
- Only a minimal, analyst-useful subset of the raw AbuseIPDB response is
  ever kept or returned - never the full provider payload, and never the
  API key.
"""

from __future__ import annotations

import ipaddress
import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any

import requests

from app.config import settings

logger = logging.getLogger(__name__)

# Cache entry: (expires_at_monotonic, result_dict). Successful lookups
# and provider-side failures both get cached (with different TTLs, see
# config.py) so that neither a normal repeat-click nor a down/misconfigured
# provider results in unbounded outbound calls.
_CACHEABLE_STATUSES = {"ok", "unavailable", "rate_limited", "invalid_api_key"}


class _ReputationCache:
    """In-process, single-worker-appropriate TTL cache keyed by IP string."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: dict[str, tuple[float, dict]] = {}

    def get(self, ip: str) -> dict | None:
        with self._lock:
            entry = self._entries.get(ip)
            if entry is None:
                return None
            expires_at, result = entry
            if expires_at <= time.monotonic():
                del self._entries[ip]
                return None
            return result

    def set(self, ip: str, result: dict, ttl_seconds: float) -> None:
        with self._lock:
            self._entries[ip] = (time.monotonic() + ttl_seconds, result)


_cache = _ReputationCache()


def _result(status: str, detail: str | None = None, reputation: dict | None = None) -> dict:
    return {"status": status, "detail": detail, "reputation": reputation}


def _classify_ip(ip: str) -> str | None:
    """
    Returns "invalid_ip" or "private_ip" if `ip` shouldn't be sent to
    AbuseIPDB, otherwise None (meaning: proceed with a lookup).
    """
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid_ip"

    if (
        parsed.is_private
        or parsed.is_loopback
        or parsed.is_link_local
        or parsed.is_reserved
        or parsed.is_multicast
        or parsed.is_unspecified
    ):
        return "private_ip"

    return None


def _query_abuseipdb(ip: str) -> dict:
    """
    Performs the actual HTTP call and maps every outcome to a result
    dict. Never raises - every `requests` exception and every
    unexpected/malformed response is caught here.
    """
    headers = {"Key": settings.abuseipdb_api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": settings.abuseipdb_max_age_days}

    try:
        response = requests.get(
            settings.abuseipdb_api_url,
            headers=headers,
            params=params,
            timeout=settings.abuseipdb_timeout_seconds,
        )
    except requests.Timeout:
        logger.warning("AbuseIPDB request timed out for IP %s", ip)
        return _result("unavailable", detail="AbuseIPDB request timed out.")
    except requests.ConnectionError:
        logger.warning("AbuseIPDB connection failed for IP %s", ip)
        return _result("unavailable", detail="Could not connect to AbuseIPDB.")
    except requests.RequestException as exc:
        logger.warning("AbuseIPDB request failed for IP %s: %s", ip, exc)
        return _result("unavailable", detail="AbuseIPDB request failed.")

    if response.status_code == 429:
        return _result("rate_limited", detail="AbuseIPDB rate limit reached.")
    if response.status_code in (401, 403):
        logger.warning(
            "AbuseIPDB rejected the configured API key (HTTP %s)", response.status_code
        )
        return _result("invalid_api_key", detail="AbuseIPDB rejected the configured API key.")
    if response.status_code != 200:
        logger.warning(
            "AbuseIPDB returned unexpected status %s for IP %s", response.status_code, ip
        )
        return _result("unavailable", detail=f"AbuseIPDB returned HTTP {response.status_code}.")

    try:
        body = response.json()
        data = body["data"]
        reputation = {
            "ip_address": data.get("ipAddress", ip),
            "abuse_confidence_score": data["abuseConfidenceScore"],
            "country": data.get("countryName") or data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "total_reports": data.get("totalReports"),
            "last_reported_at": data.get("lastReportedAt"),
            "provider": "AbuseIPDB",
            "queried_at": datetime.now(timezone.utc).isoformat(),
        }
    except (ValueError, KeyError, TypeError) as exc:
        logger.warning("AbuseIPDB returned an unexpected response shape for IP %s: %s", ip, exc)
        return _result("unavailable", detail="AbuseIPDB returned an unexpected response.")

    return _result("ok", reputation=reputation)


def get_ip_reputation(ip: str) -> dict[str, Any]:
    """
    Look up `ip` in AbuseIPDB (or return a cached result). Always
    returns a dict shaped `{"status": str, "detail": str | None,
    "reputation": dict | None}` and never raises.

    `status` is one of:
      - "invalid_ip"      - not a parseable IPv4/IPv6 address.
      - "private_ip"      - a private/loopback/link-local/reserved/
                             multicast address; never sent to AbuseIPDB.
      - "not_configured"  - no ABUSEIPDB_API_KEY is set.
      - "rate_limited"    - AbuseIPDB returned HTTP 429.
      - "invalid_api_key" - AbuseIPDB returned HTTP 401/403.
      - "unavailable"     - timeout, connection failure, any other
                             non-2xx status, or a malformed response body.
      - "ok"              - success; `reputation` is populated.
    """
    classification = _classify_ip(ip)
    if classification is not None:
        return _result(classification)

    if not settings.abuseipdb_api_key:
        return _result("not_configured", detail="AbuseIPDB is not configured on this server.")

    cached = _cache.get(ip)
    if cached is not None:
        return cached

    result = _query_abuseipdb(ip)

    if result["status"] in _CACHEABLE_STATUSES:
        ttl = (
            settings.abuseipdb_cache_ttl_seconds
            if result["status"] == "ok"
            else settings.abuseipdb_error_cache_ttl_seconds
        )
        _cache.set(ip, result, ttl)

    return result
