"""
Domain-name heuristics: registrable domain, look-alike (brand impersonation)
detection, suspicious labels. Heuristics only; they are explained as evidence,
never as a verdict on their own.

BRAND_DOMAINS is a short, illustrative list of commonly impersonated brands
and their own domains. It is not exhaustive and should be extended by the team.
"""

import ipaddress
import re

BRAND_DOMAINS: dict[str, tuple[str, ...]] = {
    "paypal": ("paypal.com",),
    "microsoft": ("microsoft.com", "live.com", "office.com", "outlook.com", "microsoftonline.com"),
    "google": ("google.com", "gmail.com", "googleapis.com", "youtube.com"),
    "apple": ("apple.com", "icloud.com"),
    "amazon": ("amazon.com", "amazon.co.uk", "amazonaws.com"),
    "facebook": ("facebook.com", "fb.com", "meta.com"),
    "instagram": ("instagram.com",),
    "netflix": ("netflix.com",),
    "dropbox": ("dropbox.com",),
    "linkedin": ("linkedin.com",),
    "github": ("github.com",),
    "dhl": ("dhl.com",),
    "docusign": ("docusign.com", "docusign.net"),
}

SUSPICIOUS_TLDS = frozenset({
    "zip", "mov", "top", "xyz", "tk", "ml", "ga", "cf", "gq", "click", "country", "kim", "work", "shop",
})
_SECOND_LEVEL = frozenset({"co", "com", "net", "org", "gov", "edu", "ac"})
_DIGIT_SUBS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s"})


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def registrable_domain(host: str) -> str:
    labels = host.lower().rstrip(".").split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else host.lower()


def is_punycode(host: str) -> bool:
    return any(label.startswith("xn--") for label in host.lower().split("."))


def _edit_distance(a: str, b: str) -> int:
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


def lookalike_of(host: str) -> str | None:
    """
    Return the legitimate brand domain this host imitates, or None.
    A host imitates a brand when, after normalising digit substitutions and
    hyphens, its first label contains the brand name or is within two edits
    of it, and the host is not the brand's own domain or a subdomain of it.
    """
    host = host.lower().rstrip(".")
    reg = registrable_domain(host)
    for brand, legit in BRAND_DOMAINS.items():
        if any(reg == d or host.endswith("." + d) for d in legit):
            return None

    first_label = reg.split(".")[0]
    normalised = first_label.translate(_DIGIT_SUBS).replace("-", "")
    for brand, legit in BRAND_DOMAINS.items():
        if brand in normalised and len(brand) >= 4:
            return legit[0]
        if len(normalised) >= 4 and abs(len(normalised) - len(brand)) <= 2 and _edit_distance(normalised, brand) <= 2:
            return legit[0]
    return None


def is_suspicious_tld(host: str) -> bool:
    return host.lower().rstrip(".").rsplit(".", 1)[-1] in SUSPICIOUS_TLDS


def is_deep(host: str) -> bool:
    return len(host.rstrip(".").split(".")) >= 5


def looks_like_hostname(value: str) -> bool:
    return bool(re.fullmatch(r"(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}", value.lower()))
