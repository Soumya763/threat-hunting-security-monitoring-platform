"""
SSRF-hardened, single-purpose HTTP fetcher for URL analysis.

Security properties (each is covered by tests in tests/test_url_ssrf.py):
  - Every hop is validated by app.analysis.ssrf BEFORE any connection:
    scheme, credentials, port, host, and the full set of resolved addresses.
  - The connection is made to a PINNED, already-validated IP address. The
    hostname is re-used only for the Host header and TLS SNI/verification, so
    a DNS answer that changes between check and connect cannot redirect the
    connection to an internal address (DNS rebinding).
  - Every redirect Location is resolved against the current URL and then
    validated again, so a public host cannot bounce the fetcher to a private one.
  - GET only, no cookies, no credentials, no JavaScript execution, no
    browser. The response body is read up to a byte limit and never executed.
  - Connect/read timeouts per hop and an overall deadline for the chain.
  - Redirect count is capped.

This is not a browser and not a general proxy: it returns status, headers,
a bounded body snippet and TLS details for a single analysis.
"""

import http.client
import socket
import ssl
import time
from typing import Any, Callable
from urllib.parse import urljoin, urlsplit

from app.analysis.ssrf import UnsafeURLError, validate_and_resolve
from app.config import settings

USER_AGENT = "ThreatHuntingPlatform-UrlAnalyzer/1.0 (static inspection; no execution)"
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
MAX_ADDRESS_ATTEMPTS = 3
_KEEP_HEADERS = ("content-type", "content-length", "server", "location", "x-frame-options",
                 "strict-transport-security", "content-security-policy")


class PinnedHTTPConnection(http.client.HTTPConnection):
    """Plain HTTP connection that dials a pinned IP but keeps the hostname for Host."""

    def __init__(self, pinned_ip: str, host: str, port: int, timeout: float):
        super().__init__(host, port, timeout=timeout)
        self._pinned_ip = pinned_ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """TLS connection to a pinned IP; certificate is verified against the hostname."""

    def __init__(self, pinned_ip: str, host: str, port: int, timeout: float, context: ssl.SSLContext):
        super().__init__(host, port, timeout=timeout, context=context)
        self._pinned_ip = pinned_ip
        self.peer_certificate: dict = {}

    def connect(self) -> None:
        raw = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        # Keep the verified certificate now: with "Connection: close" http.client
        # discards the socket once the response is read, so it is no longer available later.
        self.peer_certificate = self.sock.getpeercert() or {}


def _host_header(host: str, port: int, scheme: str) -> str:
    default = 443 if scheme == "https" else 80
    bracketed = f"[{host}]" if ":" in host else host
    return bracketed if port == default else f"{bracketed}:{port}"


def _describe_certificate(cert: dict[str, Any]) -> dict[str, Any]:
    def name_of(parts) -> str:
        flat = {}
        for rdn in parts or ():
            for key, value in rdn:
                flat[key] = value
        return flat.get("commonName") or ", ".join(f"{k}={v}" for k, v in flat.items())

    san = [value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"][:20]
    return {
        "verified": True,
        "subject": name_of(cert.get("subject")),
        "issuer": name_of(cert.get("issuer")),
        "not_before": cert.get("notBefore"),
        "not_after": cert.get("notAfter"),
        "san": san,
    }


def fetch_one(info: dict[str, Any], ip: str, *, timeout: float, max_body: int) -> dict[str, Any]:
    """Perform one GET to a validated, pinned address. Raises on transport errors."""
    host, port, scheme = info["host"], info["port"], info["scheme"]
    parts = urlsplit(info["url"])
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    headers = {
        "Host": _host_header(host, port, scheme),
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5",
        "Accept-Encoding": "identity",
        "Connection": "close",
    }

    if scheme == "https":
        conn: http.client.HTTPConnection = PinnedHTTPSConnection(
            ip, host, port, timeout, ssl.create_default_context()
        )
    else:
        conn = PinnedHTTPConnection(ip, host, port, timeout)

    try:
        conn.request("GET", path, headers=headers)
        response = conn.getresponse()
        resp_headers = {k.lower(): v for k, v in response.getheaders() if k.lower() in _KEEP_HEADERS}

        body = b""
        if response.status not in REDIRECT_STATUSES:
            body = response.read(max_body)

        tls = None
        if scheme == "https" and conn.peer_certificate:
            tls = _describe_certificate(conn.peer_certificate)
        return {"status": response.status, "headers": resp_headers, "body": body, "tls": tls}
    finally:
        conn.close()


def _tls_problem_message(exc: ssl.SSLError) -> str:
    detail = getattr(exc, "verify_message", None) or str(exc)
    lowered = detail.lower()
    if "hostname" in lowered or "doesn't match" in lowered:
        return "Certificate does not match the host name."
    if "expired" in lowered:
        return "Certificate has expired."
    if "self-signed" in lowered or "self signed" in lowered:
        return "The certificate chain is not trusted: a self-signed certificate is in the chain."
    if "unable to get local issuer" in lowered or "unknown ca" in lowered or "issuer" in lowered:
        return "The certificate issuer is not trusted by this server."
    return "TLS certificate verification failed."


def fetch_with_redirects(
    raw_url: str,
    *,
    resolver: Callable[[str, int], list[str]] | None = None,
    fetcher: Callable[..., dict[str, Any]] = fetch_one,
    max_redirects: int | None = None,
    total_seconds: float | None = None,
    per_hop_seconds: float | None = None,
    max_body: int | None = None,
) -> dict[str, Any]:
    """
    Follow up to `max_redirects` hops, validating each one. Never raises.

    Returns a dict with: hops (list), final_url, status, headers, body (bytes),
    tls (dict|None), tls_problem (str|None), redirect_count, blocked (str|None),
    error (str|None).
    """
    max_redirects = settings.url_max_redirects if max_redirects is None else max_redirects
    total_seconds = settings.url_fetch_total_seconds if total_seconds is None else total_seconds
    per_hop = settings.url_fetch_timeout_seconds if per_hop_seconds is None else per_hop_seconds
    max_body = settings.url_max_body_bytes if max_body is None else max_body
    resolver_fn = resolver or _default_resolver

    outcome: dict[str, Any] = {
        "hops": [], "final_url": None, "status": None, "headers": {}, "body": b"",
        "tls": None, "tls_problem": None, "redirect_count": 0, "blocked": None, "error": None,
    }
    started = time.monotonic()
    current = raw_url

    for hop_index in range(max_redirects + 1):
        try:
            info = validate_and_resolve(current, resolver_fn)
        except UnsafeURLError as exc:
            outcome["hops"].append({"url": current, "status": None, "blocked": str(exc)})
            outcome["blocked"] = str(exc)
            if hop_index > 0:
                outcome["redirect_count"] = hop_index
            return outcome

        remaining = total_seconds - (time.monotonic() - started)
        if remaining <= 0:
            outcome["error"] = "Analysis time limit reached while following redirects."
            return outcome

        response = None
        last_error: str | None = None
        for ip in info["addresses"][:MAX_ADDRESS_ATTEMPTS]:
            try:
                response = fetcher(info, ip, timeout=min(per_hop, remaining), max_body=max_body)
                break
            except ssl.SSLError as exc:
                outcome["tls_problem"] = _tls_problem_message(exc)
                last_error = "TLS handshake failed."
            except socket.timeout:
                last_error = "The site did not respond in time."
            except (OSError, http.client.HTTPException) as exc:
                last_error = f"Connection failed ({type(exc).__name__})."

        if response is None:
            outcome["hops"].append({"url": info["url"], "ip": info["addresses"][0], "status": None, "error": last_error})
            outcome["error"] = last_error
            outcome["redirect_count"] = hop_index
            return outcome

        location = response["headers"].get("location")
        outcome["hops"].append({
            "url": info["url"],
            "ip": ip,
            "status": response["status"],
            "server": response["headers"].get("server"),
            "content_type": response["headers"].get("content-type"),
            "location": location,
        })
        if response["tls"]:
            outcome["tls"] = response["tls"]

        if response["status"] in REDIRECT_STATUSES and location:
            if hop_index == max_redirects:
                outcome["error"] = f"Too many redirects (limit {max_redirects})."
                outcome["redirect_count"] = hop_index + 1
                return outcome
            current = urljoin(info["url"], location)
            continue

        outcome.update({
            "final_url": info["url"],
            "status": response["status"],
            "headers": response["headers"],
            "body": response["body"],
            "redirect_count": hop_index,
        })
        return outcome

    return outcome


def _default_resolver(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    return [info[4][0] for info in infos]
