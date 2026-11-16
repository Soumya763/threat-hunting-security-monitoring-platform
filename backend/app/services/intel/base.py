"""Shared types for the provider layer."""

import threading
import time
from datetime import datetime, timezone
from typing import Any

# Normalised statuses. Only "ok" and "not_found" count as a consulted source.
STATUS_OK = "ok"
STATUS_NOT_FOUND = "not_found"
STATUS_NOT_CONFIGURED = "not_configured"
STATUS_UNAVAILABLE = "unavailable"
STATUS_TIMEOUT = "timeout"
STATUS_INVALID_KEY = "invalid_key"
STATUS_RATE_LIMITED = "rate_limited"
STATUS_UNSUPPORTED = "unsupported"
STATUS_SUBMITTED = "submitted"

CONSULTED_STATUSES = frozenset({STATUS_OK, STATUS_NOT_FOUND})


def result(
    provider: str,
    indicator_type: str,
    indicator: str,
    status: str,
    *,
    detection: tuple[int, int] | None = None,
    summary: dict[str, Any] | None = None,
    message: str | None = None,
) -> dict[str, Any]:
    """Build the normalised provider result stored in analyses and cached."""
    return {
        "provider": provider,
        "indicator_type": indicator_type,
        "indicator": indicator,
        "status": status,
        "detection": (
            {"positives": detection[0], "total": detection[1]} if detection is not None else None
        ),
        "summary": summary or {},
        "message": message,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "cached": False,
    }


class RateLimiter:
    """
    In-process limiter: a minimum interval between requests and a daily cap.
    State is per process and resets on restart. It protects provider quotas
    for a single backend instance; it is not a distributed limiter.
    """

    def __init__(self, min_interval_seconds: float, daily_quota: int):
        self._min_interval = min_interval_seconds
        self._daily_quota = daily_quota
        self._lock = threading.Lock()
        self._last = 0.0
        self._day = datetime.now(timezone.utc).date()
        self._used_today = 0

    def try_acquire(self) -> str | None:
        """Return None if the request may proceed, else a reason string."""
        with self._lock:
            today = datetime.now(timezone.utc).date()
            if today != self._day:
                self._day, self._used_today = today, 0
            if self._used_today >= self._daily_quota:
                return "Daily request quota for this provider is used up."
            now = time.monotonic()
            wait = self._min_interval - (now - self._last)
            if self._last and wait > 0:
                return f"Provider rate limit: retry in about {int(wait) + 1} second(s)."
            self._last = now
            self._used_today += 1
            return None


class MemoryCache:
    """Process-local cache used when no database session is supplied (tests, scripts)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._items: dict[tuple[str, str, str], tuple[float, dict[str, Any]]] = {}

    def get(self, provider: str, indicator_type: str, indicator: str) -> dict[str, Any] | None:
        key = (provider, indicator_type, indicator)
        with self._lock:
            entry = self._items.get(key)
            if entry is None:
                return None
            expires, payload = entry
            if expires <= time.time():
                self._items.pop(key, None)
                return None
            return payload

    def set(self, provider: str, indicator_type: str, indicator: str, payload: dict[str, Any], ttl_seconds: float) -> None:
        with self._lock:
            self._items[(provider, indicator_type, indicator)] = (time.time() + ttl_seconds, payload)


FAILURE_STATUSES = frozenset({STATUS_UNAVAILABLE, STATUS_TIMEOUT, STATUS_INVALID_KEY, STATUS_RATE_LIMITED})
NOT_APPLICABLE_STATUSES = frozenset({STATUS_UNSUPPORTED, STATUS_SUBMITTED})


def summarize_providers(results: dict[str, dict[str, Any]]) -> dict[str, int]:
    """Counts shown to the analyst: how many providers answered, failed, or were not set up.

    "applicable" excludes providers that do not support the indicator type, so a
    domain is not counted as a failed IP lookup.
    """
    values = list(results.values())
    return {
        "applicable": sum(1 for r in values if r["status"] not in NOT_APPLICABLE_STATUSES),
        "checked": sum(1 for r in values if r["status"] in CONSULTED_STATUSES),
        "failed": sum(1 for r in values if r["status"] in FAILURE_STATUSES),
        "not_configured": sum(1 for r in values if r["status"] == STATUS_NOT_CONFIGURED),
    }
