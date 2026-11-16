"""
Provider clients. Each client:
  - reads its key from settings (never from the request, never returned to the caller),
  - reports STATUS_NOT_CONFIGURED when its key is missing,
  - applies a timeout and at most one retry on connection errors / HTTP 5xx,
  - maps every response to a normalised result (base.result),
  - never raises.

Client-side limits for MalwareBazaar, OTX and urlscan.io below are deliberately
conservative placeholders, not published quotas. Verify each provider's current
terms before relying on them; see docs/PROVIDERS.md.
"""

import base64
import logging
import time
from typing import Any
from urllib.parse import quote

import requests

from app.config import settings
from app.services.intel import base
from app.services.intel.base import RateLimiter

logger = logging.getLogger(__name__)

_FILE_HASH_TYPES = {"md5": "md5", "sha1": "sha1", "sha256": "sha256"}


def _get_or_post(method: str, url: str, **kwargs) -> requests.Response:
    """One retry on connection error or 5xx; the caller maps the final outcome."""
    timeout = settings.provider_timeout_seconds
    last_exc: Exception | None = None
    for attempt in range(2):
        try:
            response = requests.request(method, url, timeout=timeout, **kwargs)
            if response.status_code < 500 or attempt == 1:
                return response
        except requests.RequestException as exc:
            last_exc = exc
            if attempt == 1:
                raise
        time.sleep(1.0)
    raise last_exc or RuntimeError("unreachable")


def _map_http_error(provider: str, indicator_type: str, indicator: str, response: requests.Response) -> dict[str, Any] | None:
    if response.status_code in (401, 403):
        return base.result(provider, indicator_type, indicator, base.STATUS_INVALID_KEY,
                           message=f"{provider} rejected the configured API key.")
    if response.status_code == 429:
        return base.result(provider, indicator_type, indicator, base.STATUS_RATE_LIMITED,
                           message=f"{provider} rate limit reached.")
    if response.status_code == 404:
        return base.result(provider, indicator_type, indicator, base.STATUS_NOT_FOUND,
                           message=f"{provider} has no record for this indicator.")
    if response.status_code != 200:
        return base.result(provider, indicator_type, indicator, base.STATUS_UNAVAILABLE,
                           message=f"{provider} returned HTTP {response.status_code}.")
    return None


def _transport_error(provider: str, indicator_type: str, indicator: str, exc: Exception) -> dict[str, Any]:
    status = base.STATUS_TIMEOUT if isinstance(exc, requests.Timeout) else base.STATUS_UNAVAILABLE
    message = "The provider did not respond in time." if status == base.STATUS_TIMEOUT else f"{provider} could not be reached."
    return base.result(provider, indicator_type, indicator, status, message=message)


# ---------------------------------------------------------------- VirusTotal

class VirusTotalClient:
    name = "VirusTotal"
    limiter = None  # created lazily from settings

    @property
    def configured(self) -> bool:
        return bool(settings.virustotal_api_key)

    def _limiter(self) -> RateLimiter:
        if self.limiter is None:
            type(self).limiter = RateLimiter(
                settings.virustotal_min_interval_seconds, settings.virustotal_daily_quota
            )
        return self.limiter

    def _headers(self) -> dict[str, str]:
        return {"x-apikey": settings.virustotal_api_key, "Accept": "application/json"}

    @staticmethod
    def _stats(attributes: dict[str, Any]) -> tuple[int, int]:
        stats = attributes.get("last_analysis_stats") or {}
        positives = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
        total = sum(int(stats.get(k, 0)) for k in ("malicious", "suspicious", "undetected", "harmless"))
        return positives, total

    def lookup(self, indicator_type: str, value: str) -> dict[str, Any]:
        if not self.configured:
            return base.result(self.name, indicator_type, value, base.STATUS_NOT_CONFIGURED,
                               message="VirusTotal is not configured (VIRUSTOTAL_API_KEY).")
        if indicator_type in _FILE_HASH_TYPES:
            endpoint, path = "file", f"/files/{value}"
        elif indicator_type == "url":
            encoded = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
            endpoint, path = "url", f"/urls/{encoded}"
        elif indicator_type == "domain":
            endpoint, path = "domain", f"/domains/{quote(value, safe='')}"
        elif indicator_type == "ip":
            endpoint, path = "ip", f"/ip_addresses/{quote(value, safe='')}"
        else:
            return base.result(self.name, indicator_type, value, base.STATUS_UNSUPPORTED,
                               message="VirusTotal does not support this indicator type here.")

        wait = self._limiter().try_acquire()
        if wait:
            return base.result(self.name, indicator_type, value, base.STATUS_RATE_LIMITED, message=wait)

        try:
            response = _get_or_post("GET", settings.virustotal_api_url + path, headers=self._headers())
        except requests.RequestException as exc:
            return _transport_error(self.name, indicator_type, value, exc)

        mapped = _map_http_error(self.name, indicator_type, value, response)
        if mapped:
            return mapped

        data = response.json().get("data", {})
        attributes = data.get("attributes", {})
        positives, total = self._stats(attributes)
        classification = (attributes.get("popular_threat_classification") or {}).get("suggested_threat_label")
        summary = {
            "endpoint": endpoint,
            "reputation": attributes.get("reputation"),
            "suggested_threat_label": classification,
            "names": (attributes.get("names") or [])[:5],
            "tags": (attributes.get("tags") or [])[:10],
            "last_analysis_date": attributes.get("last_analysis_date"),
            "first_submission_date": attributes.get("first_submission_date"),
            "last_final_url": attributes.get("last_final_url"),
            "categories": attributes.get("categories") if isinstance(attributes.get("categories"), dict) else None,
            "country": attributes.get("country"),
            "as_owner": attributes.get("as_owner"),
            "permalink": f"https://www.virustotal.com/gui/{endpoint}/{value}" if endpoint != "url" else None,
        }
        return base.result(self.name, indicator_type, value, base.STATUS_OK,
                           detection=(positives, total), summary=summary)

    def submit_file(self, data: bytes, filename: str) -> dict[str, Any]:
        """Upload a file (explicit consent is enforced by the caller)."""
        if not self.configured:
            return base.result(self.name, "file", filename, base.STATUS_NOT_CONFIGURED,
                               message="VirusTotal is not configured (VIRUSTOTAL_API_KEY).")
        wait = self._limiter().try_acquire()
        if wait:
            return base.result(self.name, "file", filename, base.STATUS_RATE_LIMITED, message=wait)
        try:
            response = _get_or_post(
                "POST", settings.virustotal_api_url + "/files",
                headers=self._headers(), files={"file": (filename, data)},
            )
        except requests.RequestException as exc:
            return _transport_error(self.name, "file", filename, exc)
        if response.status_code not in (200, 201):
            mapped = _map_http_error(self.name, "file", filename, response)
            return mapped or base.result(self.name, "file", filename, base.STATUS_UNAVAILABLE,
                                         message=f"Upload failed with HTTP {response.status_code}.")
        analysis_id = (response.json().get("data") or {}).get("id")
        return base.result(self.name, "file", filename, base.STATUS_SUBMITTED,
                           summary={"analysis_id": analysis_id},
                           message="Uploaded. Results usually appear within minutes.")


# ---------------------------------------------------------------- MalwareBazaar

class MalwareBazaarClient:
    name = "MalwareBazaar"
    _limiter = RateLimiter(min_interval_seconds=1.0, daily_quota=1000)

    @property
    def configured(self) -> bool:
        return bool(settings.malwarebazaar_auth_key)

    def lookup(self, indicator_type: str, value: str) -> dict[str, Any]:
        if indicator_type not in _FILE_HASH_TYPES:
            return base.result(self.name, indicator_type, value, base.STATUS_UNSUPPORTED,
                               message="MalwareBazaar only indexes file hashes.")
        if not self.configured:
            return base.result(self.name, indicator_type, value, base.STATUS_NOT_CONFIGURED,
                               message="MalwareBazaar is not configured (MALWAREBAZAAR_AUTH_KEY).")
        wait = self._limiter.try_acquire()
        if wait:
            return base.result(self.name, indicator_type, value, base.STATUS_RATE_LIMITED, message=wait)
        try:
            response = _get_or_post(
                "POST", settings.malwarebazaar_api_url,
                headers={"Auth-Key": settings.malwarebazaar_auth_key},
                data={"query": "get_info", "hash": value},
            )
        except requests.RequestException as exc:
            return _transport_error(self.name, indicator_type, value, exc)

        if response.status_code in (401, 403):
            return base.result(self.name, indicator_type, value, base.STATUS_INVALID_KEY,
                               message="MalwareBazaar rejected the configured Auth-Key.")
        if response.status_code != 200:
            return base.result(self.name, indicator_type, value, base.STATUS_UNAVAILABLE,
                               message=f"MalwareBazaar returned HTTP {response.status_code}.")
        body = response.json()
        query_status = body.get("query_status", "")
        if query_status == "ok":
            sample = (body.get("data") or [{}])[0]
            return base.result(self.name, indicator_type, value, base.STATUS_OK, summary={
                "known_malware_sample": True,
                "signature": sample.get("signature"),
                "file_type": sample.get("file_type"),
                "tags": (sample.get("tags") or [])[:10],
                "first_seen": sample.get("first_seen"),
                "last_seen": sample.get("last_seen"),
            })
        if query_status == "hash_not_found":
            return base.result(self.name, indicator_type, value, base.STATUS_NOT_FOUND,
                               message="Not listed in MalwareBazaar.")
        if query_status in ("no_api_key", "illegal_auth_key"):
            return base.result(self.name, indicator_type, value, base.STATUS_INVALID_KEY,
                               message="MalwareBazaar rejected the configured Auth-Key.")
        return base.result(self.name, indicator_type, value, base.STATUS_UNAVAILABLE,
                           message=f"MalwareBazaar returned status '{query_status or 'unknown'}'.")


# ---------------------------------------------------------------- AlienVault OTX

_OTX_TYPES = {"ip": "IPv4", "domain": "domain", "url": "url"} | {k: "file" for k in _FILE_HASH_TYPES}


class OTXClient:
    name = "AlienVault OTX"
    _limiter = RateLimiter(min_interval_seconds=1.0, daily_quota=1000)

    @property
    def configured(self) -> bool:
        return bool(settings.otx_api_key)

    def lookup(self, indicator_type: str, value: str) -> dict[str, Any]:
        otx_type = _OTX_TYPES.get(indicator_type)
        if otx_type is None:
            return base.result(self.name, indicator_type, value, base.STATUS_UNSUPPORTED,
                               message="OTX does not support this indicator type here.")
        if not self.configured:
            return base.result(self.name, indicator_type, value, base.STATUS_NOT_CONFIGURED,
                               message="AlienVault OTX is not configured (OTX_API_KEY).")
        wait = self._limiter.try_acquire()
        if wait:
            return base.result(self.name, indicator_type, value, base.STATUS_RATE_LIMITED, message=wait)

        url = f"{settings.otx_api_url}/indicators/{otx_type}/{quote(value, safe='')}/general"
        try:
            response = _get_or_post("GET", url, headers={"X-OTX-API-KEY": settings.otx_api_key})
        except requests.RequestException as exc:
            return _transport_error(self.name, indicator_type, value, exc)

        mapped = _map_http_error(self.name, indicator_type, value, response)
        if mapped:
            return mapped
        body = response.json()
        pulse_info = body.get("pulse_info") or {}
        pulses = pulse_info.get("pulses") or []
        return base.result(self.name, indicator_type, value, base.STATUS_OK, summary={
            "pulse_count": int(pulse_info.get("count", 0)),
            "pulses": [
                {"name": p.get("name"), "modified": p.get("modified"), "tags": (p.get("tags") or [])[:8]}
                for p in pulses[:5]
            ],
            "validation_messages": [v.get("message") for v in (body.get("validation") or [])][:5],
        })


    def validate_key(self) -> dict[str, Any]:
        """Check the key against /user/me. Public indicator endpoints answer anonymous
        requests, so they cannot prove that a key is valid."""
        if not self.configured:
            return base.result(self.name, "account", "", base.STATUS_NOT_CONFIGURED,
                               message="AlienVault OTX is not configured (OTX_API_KEY).")
        try:
            response = _get_or_post("GET", f"{settings.otx_api_url}/user/me",
                                    headers={"X-OTX-API-KEY": settings.otx_api_key})
        except requests.RequestException as exc:
            return _transport_error(self.name, "account", "", exc)
        if response.status_code in (401, 403):
            return base.result(self.name, "account", "", base.STATUS_INVALID_KEY,
                               message="AlienVault OTX rejected the configured API key.")
        mapped = _map_http_error(self.name, "account", "", response)
        if mapped:
            return mapped
        return base.result(self.name, "account", "", base.STATUS_OK,
                           message="The key was accepted by AlienVault OTX.")


# ---------------------------------------------------------------- urlscan.io

class UrlscanClient:
    name = "urlscan.io"
    _limiter = RateLimiter(min_interval_seconds=2.0, daily_quota=200)

    @property
    def configured(self) -> bool:
        return bool(settings.urlscan_api_key)

    def _headers(self) -> dict[str, str]:
        return {"API-Key": settings.urlscan_api_key, "Content-Type": "application/json"}

    def lookup(self, indicator_type: str, value: str) -> dict[str, Any]:
        """Gateway entry point. urlscan.io is searched by domain only."""
        if indicator_type != "domain":
            return base.result(self.name, indicator_type, value, base.STATUS_UNSUPPORTED,
                               message="urlscan.io search is used for domain names here.")
        return self.search_domain(value)

    def search_domain(self, domain: str) -> dict[str, Any]:
        """Search prior scans of a domain (no submission, no new scan)."""
        if not self.configured:
            return base.result(self.name, "domain", domain, base.STATUS_NOT_CONFIGURED,
                               message="urlscan.io is not configured (URLSCAN_API_KEY).")
        wait = self._limiter.try_acquire()
        if wait:
            return base.result(self.name, "domain", domain, base.STATUS_RATE_LIMITED, message=wait)
        try:
            response = _get_or_post(
                "GET", f"{settings.urlscan_api_url}/search/",
                headers=self._headers(), params={"q": f"domain:{domain}", "size": 10},
            )
        except requests.RequestException as exc:
            return _transport_error(self.name, "domain", domain, exc)

        if response.status_code == 400 and "api key" in response.text.lower():
            return base.result(self.name, "domain", domain, base.STATUS_INVALID_KEY,
                               message="urlscan.io rejected the configured API key format.")
        mapped = _map_http_error(self.name, "domain", domain, response)
        if mapped:
            return mapped
        body = response.json()
        results = body.get("results") or []
        if not results:
            return base.result(self.name, "domain", domain, base.STATUS_NOT_FOUND,
                               message="No prior scans of this domain in urlscan.io.")
        malicious = sum(1 for r in results if (r.get("verdicts") or {}).get("overall", {}).get("malicious"))
        return base.result(self.name, "domain", domain, base.STATUS_OK, summary={
            "scan_count_returned": len(results),
            "malicious_scans": malicious,
            "latest_scan": (results[0].get("task") or {}).get("time"),
            "sample_urls": [(r.get("page") or {}).get("url") for r in results[:5]],
            "result_pages": [(r.get("task") or {}).get("reportURL") for r in results[:5]],
        })

    def submit_url(self, url: str) -> dict[str, Any]:
        """Submit a URL for scanning with the configured visibility. Caller enforces consent."""
        if not self.configured:
            return base.result(self.name, "url", url, base.STATUS_NOT_CONFIGURED,
                               message="urlscan.io is not configured (URLSCAN_API_KEY).")
        wait = self._limiter.try_acquire()
        if wait:
            return base.result(self.name, "url", url, base.STATUS_RATE_LIMITED, message=wait)
        try:
            response = _get_or_post(
                "POST", f"{settings.urlscan_api_url}/scan/",
                headers=self._headers(),
                json={"url": url, "visibility": settings.urlscan_visibility},
            )
        except requests.RequestException as exc:
            return _transport_error(self.name, "url", url, exc)
        if response.status_code not in (200, 201):
            mapped = _map_http_error(self.name, "url", url, response)
            return mapped or base.result(self.name, "url", url, base.STATUS_UNAVAILABLE,
                                         message=f"Submission failed with HTTP {response.status_code}.")
        body = response.json()
        return base.result(self.name, "url", url, base.STATUS_SUBMITTED, summary={
            "scan_uuid": body.get("uuid"),
            "visibility": settings.urlscan_visibility,
            "result_page": body.get("result"),
        }, message=f"Submitted with '{settings.urlscan_visibility}' visibility.")


virustotal = VirusTotalClient()
malwarebazaar = MalwareBazaarClient()
otx = OTXClient()
urlscan = UrlscanClient()

PROVIDER_CATALOG = [
    {"id": "virustotal", "name": "VirusTotal", "configured": lambda: bool(settings.virustotal_api_key),
     "env": "VIRUSTOTAL_API_KEY", "supports": ["file hash", "url", "domain", "ip", "file upload (consent)"],
     "limits": "Public API is for non-commercial use; about 4 requests/minute and a daily quota (configurable)."},
    {"id": "malwarebazaar", "name": "MalwareBazaar (abuse.ch)", "configured": lambda: bool(settings.malwarebazaar_auth_key),
     "env": "MALWAREBAZAAR_AUTH_KEY", "supports": ["file hash (MD5/SHA-1/SHA-256)"],
     "limits": "Free Auth-Key required on every request; fair-use limits apply."},
    {"id": "otx", "name": "AlienVault OTX", "configured": lambda: bool(settings.otx_api_key),
     "env": "OTX_API_KEY", "supports": ["ip", "domain", "url", "file hash"],
     "limits": "Free account and API key; the platform calls it only when a key is configured."},
    {"id": "urlscan", "name": "urlscan.io", "configured": lambda: bool(settings.urlscan_api_key),
     "env": "URLSCAN_API_KEY", "supports": ["domain search", "URL submission (consent)"],
     "limits": "Per-minute, hourly and daily quotas; submissions default to the configured visibility (unlisted)."},
    {"id": "abuseipdb", "name": "AbuseIPDB", "configured": lambda: bool(settings.abuseipdb_api_key),
     "env": "ABUSEIPDB_API_KEY", "supports": ["ip reputation"],
     "limits": "Free plan has a daily check limit; public IPs only."},
    {"id": "rdap", "name": "RDAP (registration data)", "configured": lambda: True,
     "env": "RDAP_BASE_URL (optional)", "supports": ["domain registration"],
     "limits": "No key. Registry-specific rate limits apply."},
]
