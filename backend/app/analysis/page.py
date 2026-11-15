"""
Passive HTML inspection for phishing indicators. The body is parsed as text
with regular expressions only; no script is executed and no resource is
loaded. Limits: the caller passes at most `url_max_body_bytes` of HTML.
"""

import re
from typing import Any
from urllib.parse import urljoin, urlsplit

_TITLE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)
_PASSWORD = re.compile(rb"<input[^>]+type\s*=\s*[\"']?password", re.I)
_FORM_ACTION = re.compile(rb"<form[^>]*action\s*=\s*[\"']([^\"']+)[\"']", re.I)
_FORM = re.compile(rb"<form\b", re.I)
_META_REFRESH = re.compile(rb"<meta[^>]+http-equiv\s*=\s*[\"']?refresh[^>]*content\s*=\s*[\"'][^\"']*url\s*=\s*([^\"'>]+)", re.I)
_SCRIPT_REDIRECT = re.compile(rb"(window\.location(\.href)?\s*=|location\.replace\s*\(|document\.location\s*=)", re.I)
_IFRAME = re.compile(rb"<iframe\b", re.I)


def _decode(value: bytes) -> str:
    return value.decode("utf-8", errors="replace").strip()[:200]


def inspect_html(body: bytes, page_url: str) -> dict[str, Any]:
    title_match = _TITLE.search(body)
    title = re.sub(r"\s+", " ", _decode(title_match.group(1))) if title_match else None

    actions = []
    page_host = (urlsplit(page_url).hostname or "").lower()
    cross_origin_forms = []
    for match in _FORM_ACTION.finditer(body):
        absolute = urljoin(page_url, _decode(match.group(1)))
        actions.append(absolute[:300])
        target_host = (urlsplit(absolute).hostname or "").lower()
        if target_host and target_host != page_host:
            cross_origin_forms.append(target_host)

    refresh = _META_REFRESH.search(body)
    return {
        "title": title,
        "form_count": len(_FORM.findall(body)),
        "password_field": bool(_PASSWORD.search(body)),
        "form_actions": sorted(set(actions))[:10],
        "cross_origin_form_targets": sorted(set(cross_origin_forms))[:10],
        "meta_refresh_target": urljoin(page_url, _decode(refresh.group(1))) if refresh else None,
        "script_redirect": bool(_SCRIPT_REDIRECT.search(body)),
        "iframe_count": len(_IFRAME.findall(body)),
    }
