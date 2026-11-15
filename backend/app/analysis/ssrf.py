"""
URL validation and SSRF guard for the URL-analysis module.

Rules enforced here, all before any network connection is opened:
  - scheme must be http or https;
  - no embedded credentials, no fragments-as-hosts tricks, bounded length;
  - only the default ports 80 and 443 are allowed;
  - the host must resolve, and EVERY resolved address must be a public
    unicast address. Private, loopback, link-local, multicast, reserved,
    unspecified and CGNAT/shared ranges are all rejected.

`resolve_public_addresses` returns the validated addresses. A fetcher must
connect to one of those addresses (not re-resolve the hostname), which
prevents DNS rebinding between the check and the connection. Every redirect
hop must be passed through `validate_url` again.

This module performs no HTTP requests itself.
"""

import ipaddress
import socket
from typing import Callable
from urllib.parse import urlsplit

MAX_URL_LENGTH = 2048
ALLOWED_SCHEMES = frozenset({"http", "https"})
ALLOWED_PORTS = frozenset({80, 443})

# Ranges not covered by ipaddress's is_private / is_global flags on every
# Python version, and CGNAT which is not "private" in the stdlib sense.
_EXTRA_BLOCKED_V4 = [
    ipaddress.ip_network("100.64.0.0/10"),  # carrier-grade NAT
    ipaddress.ip_network("192.0.0.0/24"),  # IETF protocol assignments
    ipaddress.ip_network("198.18.0.0/15"),  # benchmarking
    ipaddress.ip_network("240.0.0.0/4"),  # reserved
]
_EXTRA_BLOCKED_V6 = [
    ipaddress.ip_network("64:ff9b:1::/48"),  # local-use NAT64
    ipaddress.ip_network("2001:db8::/32"),  # documentation
]

_BLOCKED_HOSTNAME_SUFFIXES = (".localhost", ".local", ".internal", ".lan", ".home.arpa")


class UnsafeURLError(ValueError):
    """Raised when a URL or its resolved addresses must not be fetched."""


def is_public_ip(address: str) -> bool:
    """True only for a globally routable unicast address."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False

    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped

    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or not ip.is_global
    ):
        return False

    extra = _EXTRA_BLOCKED_V4 if ip.version == 4 else _EXTRA_BLOCKED_V6
    return not any(ip in net for net in extra)


def validate_url(raw: str) -> dict:
    """
    Normalise and syntactically validate a URL. Does not resolve DNS.

    Returns {"url": normalised, "scheme", "host", "port"}. Raises
    UnsafeURLError with a user-safe message on any violation.
    """
    if not isinstance(raw, str):
        raise UnsafeURLError("URL must be a string.")

    candidate = raw.strip()
    if not candidate:
        raise UnsafeURLError("URL is empty.")
    if len(candidate) > MAX_URL_LENGTH:
        raise UnsafeURLError(f"URL is longer than {MAX_URL_LENGTH} characters.")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F or ch.isspace() for ch in candidate):
        raise UnsafeURLError("URL contains whitespace or control characters.")

    try:
        parts = urlsplit(candidate)
    except ValueError as exc:
        raise UnsafeURLError("URL could not be parsed.") from exc

    scheme = (parts.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        raise UnsafeURLError("Only http and https URLs are supported.")

    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise UnsafeURLError("URLs containing credentials are not accepted.")

    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        raise UnsafeURLError("URL has no host name.")

    try:
        port = parts.port
    except ValueError as exc:
        raise UnsafeURLError("URL has an invalid port.") from exc
    effective_port = port or (443 if scheme == "https" else 80)
    if effective_port not in ALLOWED_PORTS:
        raise UnsafeURLError("Only the standard HTTP and HTTPS ports (80, 443) are allowed.")

    if host == "localhost" or host.endswith(_BLOCKED_HOSTNAME_SUFFIXES):
        raise UnsafeURLError("Internal host names are not allowed.")

    # IP literals are checked immediately; DNS names are checked after resolution.
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        if not is_public_ip(host):
            raise UnsafeURLError("The URL points at a non-public IP address.")

    normalised = parts._replace(scheme=scheme, netloc=_netloc(host, port, scheme), fragment="")
    return {
        "url": normalised.geturl(),
        "scheme": scheme,
        "host": host,
        "port": effective_port,
    }


def _netloc(host: str, port: int | None, scheme: str) -> str:
    bracketed = f"[{host}]" if ":" in host else host
    if port is None or port == (443 if scheme == "https" else 80):
        return bracketed
    return f"{bracketed}:{port}"


def _default_resolver(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    return [info[4][0] for info in infos]


def resolve_public_addresses(
    host: str,
    port: int,
    resolver: Callable[[str, int], list[str]] = _default_resolver,
) -> list[str]:
    """
    Resolve `host` and return its addresses, but only if every one is public.
    Raises UnsafeURLError if resolution fails, returns nothing, or any
    address is non-public (a single private record is enough to refuse).
    """
    try:
        addresses = resolver(host, port)
    except OSError as exc:
        raise UnsafeURLError("The host name could not be resolved.") from exc

    unique = list(dict.fromkeys(addresses))
    if not unique:
        raise UnsafeURLError("The host name did not resolve to any address.")

    for address in unique:
        if not is_public_ip(address):
            raise UnsafeURLError("The host resolves to a non-public address and was blocked.")

    return unique


def validate_and_resolve(
    raw: str,
    resolver: Callable[[str, int], list[str]] = _default_resolver,
) -> dict:
    """Full pre-connection check: syntax, then DNS, then address policy."""
    info = validate_url(raw)
    info["addresses"] = resolve_public_addresses(info["host"], info["port"], resolver)
    return info
