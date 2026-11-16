"""
Single entry point for every threat-intelligence lookup.

lookup(provider, indicator_type, value) applies, in order:
  1. provider configuration check (missing key -> "not_configured", no network);
  2. cache lookup (successful and not-found results only, TTL from settings);
  3. provider client call (rate limit and timeouts are inside the client);
  4. cache store for consulted results.

Errors never propagate: the gateway returns a normalised result with a status.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from app.config import settings
from app.services import threat_intel
from app.services.intel import base, providers

logger = logging.getLogger(__name__)

_PROVIDERS = {
    "virustotal": providers.virustotal,
    "malwarebazaar": providers.malwarebazaar,
    "otx": providers.otx,
    "urlscan": providers.urlscan,
}


class DbCache:
    """Cache backed by the intel_cache table. Session is created per call."""

    def __init__(self, session_factory):
        self._factory = session_factory

    def get(self, provider: str, indicator_type: str, indicator: str) -> dict[str, Any] | None:
        from app.models.analysis import IntelCache

        db = self._factory()
        try:
            row = (
                db.query(IntelCache)
                .filter_by(provider=provider, indicator_type=indicator_type, indicator=indicator)
                .first()
            )
            if row is None:
                return None
            expires = row.expires_at if row.expires_at.tzinfo else row.expires_at.replace(tzinfo=timezone.utc)
            if expires <= datetime.now(timezone.utc):
                return None
            return dict(row.payload)
        finally:
            db.close()

    def set(self, provider: str, indicator_type: str, indicator: str, payload: dict[str, Any], ttl_seconds: float) -> None:
        from app.models.analysis import IntelCache

        now = datetime.now(timezone.utc)
        db = self._factory()
        try:
            row = (
                db.query(IntelCache)
                .filter_by(provider=provider, indicator_type=indicator_type, indicator=indicator)
                .first()
            )
            if row is None:
                row = IntelCache(provider=provider, indicator_type=indicator_type, indicator=indicator)
                db.add(row)
            row.payload = payload
            row.fetched_at = now
            row.expires_at = now + timedelta(seconds=ttl_seconds)
            db.commit()
        except Exception:
            db.rollback()
            logger.exception("Could not write intel cache entry")
        finally:
            db.close()


class IntelGateway:
    def __init__(self, cache=None):
        self._cache = cache or base.MemoryCache()

    def _ttl(self) -> float:
        return settings.provider_cache_ttl_hours * 3600

    def _cached(self, name: str, indicator_type: str, value: str) -> dict[str, Any] | None:
        try:
            hit = self._cache.get(name, indicator_type, value)
        except Exception:
            logger.exception("Intel cache read failed; continuing without cache")
            return None
        if hit is not None:
            hit = dict(hit)
            hit["cached"] = True
        return hit

    def _store(self, name: str, indicator_type: str, value: str, payload: dict[str, Any]) -> None:
        if payload["status"] not in base.CONSULTED_STATUSES:
            return
        try:
            self._cache.set(name, indicator_type, value, payload, self._ttl())
        except Exception:
            logger.exception("Intel cache write failed; result returned uncached")

    def lookup(self, provider: str, indicator_type: str, value: str) -> dict[str, Any]:
        """Never raises. An unexpected failure in one provider becomes that provider's result only."""
        try:
            return self._lookup(provider, indicator_type, value)
        except Exception as exc:  # noqa: BLE001 - isolate providers from each other
            # Log the exception type only: messages may echo request details.
            logger.error("Provider %s failed unexpectedly (%s)", provider, type(exc).__name__)
            return base.result(provider, indicator_type, value, base.STATUS_UNAVAILABLE,
                               message="The provider check failed unexpectedly. Other providers were not affected.")

    def _lookup(self, provider: str, indicator_type: str, value: str) -> dict[str, Any]:
        if provider == "abuseipdb":
            return self._abuseipdb(value)
        client = _PROVIDERS.get(provider)
        if client is None:
            return base.result(provider, indicator_type, value, base.STATUS_UNSUPPORTED,
                               message="Unknown provider.")
        if not client.configured:
            return client.lookup(indicator_type, value)  # returns not_configured without I/O

        hit = self._cached(provider, indicator_type, value)
        if hit is not None:
            return hit
        payload = client.lookup(indicator_type, value)
        self._store(provider, indicator_type, value, payload)
        return payload

    def _abuseipdb(self, ip: str) -> dict[str, Any]:
        """Adapter over the existing AbuseIPDB module (which already caches and never raises)."""
        mapping = {
            "ok": base.STATUS_OK,
            "not_configured": base.STATUS_NOT_CONFIGURED,
            "rate_limited": base.STATUS_RATE_LIMITED,
            "invalid_api_key": base.STATUS_INVALID_KEY,
            "unavailable": base.STATUS_UNAVAILABLE,
            "private_ip": base.STATUS_UNSUPPORTED,
            "invalid_ip": base.STATUS_UNSUPPORTED,
        }
        raw = threat_intel.get_ip_reputation(ip)
        status = mapping.get(raw["status"], base.STATUS_UNAVAILABLE)
        summary: dict[str, Any] = {}
        if status == base.STATUS_OK and raw.get("reputation"):
            rep = raw["reputation"]
            summary = {
                "abuse_confidence_score": rep.get("abuse_confidence_score"),
                "total_reports": rep.get("total_reports"),
                "last_reported_at": rep.get("last_reported_at"),
                "country": rep.get("country"),
                "isp": rep.get("isp"),
            }
        message = raw.get("detail")
        if status == base.STATUS_UNSUPPORTED:
            message = "Not a public IP address; not sent to AbuseIPDB."
        return base.result("AbuseIPDB", "ip", ip, status, summary=summary, message=message)


_gateway: IntelGateway | None = None


def get_gateway() -> IntelGateway:
    """Process-wide gateway using the database cache."""
    global _gateway
    if _gateway is None:
        from app.database.postgres import SessionLocal

        _gateway = IntelGateway(cache=DbCache(SessionLocal))
    return _gateway


# ------------------------------------------------------- on-demand provider check

# Benign, well-known indicators used only to test that a configured key works.
# These are lookups. The check never submits a URL or file to any service.
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
CHECK_TARGETS = {
    "virustotal": ("domain", "example.com"),
    "otx": ("domain", "example.com"),
    "urlscan": ("domain", "example.com"),
    "malwarebazaar": ("sha256", EICAR_SHA256),
    "abuseipdb": ("ip", "8.8.8.8"),
}

_CHECK_MESSAGES = {
    base.STATUS_OK: "The key was accepted and the provider answered.",
    base.STATUS_NOT_FOUND: "The key was accepted. The provider answered; the test indicator has no record.",
    base.STATUS_INVALID_KEY: "The provider rejected the configured key.",
    base.STATUS_RATE_LIMITED: "The check was rate limited. Try again later.",
    base.STATUS_TIMEOUT: "The provider did not respond in time.",
    base.STATUS_UNAVAILABLE: "The provider could not be reached or returned an error.",
}


def check_provider(provider_id: str) -> dict[str, Any]:
    """Test one provider with a benign indicator. Returns status only, never the key."""
    from datetime import datetime as _dt

    from app.services.intel.providers import PROVIDER_CATALOG

    catalog = {p["id"]: p for p in PROVIDER_CATALOG}
    now = _dt.now(timezone.utc).isoformat()
    entry = catalog.get(provider_id)
    if entry is None or provider_id not in CHECK_TARGETS:
        return {"id": provider_id, "configured": False, "operational": None, "status": base.STATUS_UNSUPPORTED,
                "message": "This provider cannot be checked.", "checked_at": now}
    base_info = {"id": provider_id, "name": entry["name"], "environment_variable": entry["env"]}
    if not entry["configured"]():
        return {**base_info, "configured": False, "operational": None, "status": base.STATUS_NOT_CONFIGURED,
                "message": f"Not configured. Set {entry['env']} in the backend environment.", "checked_at": now}

    indicator_type, value = CHECK_TARGETS[provider_id]
    gateway = IntelGateway()
    if provider_id == "abuseipdb":
        outcome = gateway._abuseipdb(value)
    else:
        outcome = _PROVIDERS[provider_id].lookup(indicator_type, value)  # client call, no cache

    status = outcome["status"]
    if status in base.CONSULTED_STATUSES:
        operational: bool | None = True
    elif status == base.STATUS_RATE_LIMITED:
        operational = None  # inconclusive
    else:
        operational = False
    return {**base_info, "configured": True, "operational": operational, "status": status,
            "message": _CHECK_MESSAGES.get(status, "The check did not complete."), "checked_at": now}
