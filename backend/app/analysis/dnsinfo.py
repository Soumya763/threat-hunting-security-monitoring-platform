"""DNS A/AAAA lookups for URL analysis (dnspython, system resolver)."""

from typing import Any

import dns.exception
import dns.resolver

from app.analysis.ssrf import is_public_ip

LIFETIME_SECONDS = 5.0


def lookup_addresses(host: str) -> dict[str, Any]:
    result: dict[str, Any] = {"A": [], "AAAA": [], "public": [], "non_public": [], "error": None}
    resolver = dns.resolver.Resolver()
    resolver.lifetime = LIFETIME_SECONDS

    for rdtype in ("A", "AAAA"):
        try:
            answers = resolver.resolve(host, rdtype, lifetime=LIFETIME_SECONDS)
            result[rdtype] = [rdata.to_text() for rdata in answers][:20]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            result[rdtype] = []
        except dns.exception.DNSException as exc:
            result["error"] = f"DNS {rdtype} lookup failed ({type(exc).__name__})."

    for address in result["A"] + result["AAAA"]:
        (result["public"] if is_public_ip(address) else result["non_public"]).append(address)
    return result
