"""
Explainable risk scoring and classification for file, URL and indicator analysis.

Every point is a named Factor with a reason and evidence, so a report can show
exactly why a score was produced. The total is capped at 100.

Classification levels:
  critical / high / medium / low  - score bands (75 / 50 / 25 / 1)
  clean                           - score 0, AND at least one external source was
                                    consulted without a detection, AND all local
                                    checks completed. Displayed as
                                    "Clean - no known threat detected". This is
                                    NOT a safety guarantee.
  insufficient_evidence           - score 0 but the evidence needed to call it clean
                                    is missing (no provider configured or reachable,
                                    or local analysis incomplete).

Weights are starting values, not tuned on a labelled dataset; the README says so.
"""

from dataclasses import asdict, dataclass, field
from typing import Any

SCORE_CAP = 100

NO_DETECTION_CAVEAT = (
    "No consulted source flagged this item at the time of the check. "
    "This does not guarantee that it is safe."
)
GENERAL_CAVEAT = "A detection or a low score is a triage aid, not proof of maliciousness."

LEVEL_LABELS = {
    "critical": "Critical risk",
    "high": "High risk",
    "medium": "Medium risk",
    "low": "Low risk",
    "clean": "Clean - no known threat detected",
    "insufficient_evidence": "Unknown - insufficient evidence",
}


@dataclass(frozen=True)
class Factor:
    code: str
    label: str
    points: int
    reason: str
    evidence: dict[str, Any] = field(default_factory=dict)


def band_for_score(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def classify(score: int, *, consulted_sources: int, local_complete: bool, provider_failures: int = 0) -> str:
    if score > 0:
        return band_for_score(score)
    # A clean verdict needs a consulted source AND no failed provider. A provider that
    # crashed, timed out or rejected its key could have held the detection, so its
    # failure is never read as "nothing found".
    if local_complete and consulted_sources > 0 and provider_failures == 0:
        return "clean"
    return "insufficient_evidence"


def build_score(
    factors: list[Factor],
    *,
    consulted_sources: int,
    local_complete: bool,
    extra_caveats: list[str] | None = None,
    provider_failures: int = 0,
) -> dict[str, Any]:
    raw_total = sum(f.points for f in factors)
    total = min(SCORE_CAP, max(0, raw_total))
    level = classify(total, consulted_sources=consulted_sources, local_complete=local_complete,
                     provider_failures=provider_failures)
    caveats = [GENERAL_CAVEAT] + list(extra_caveats or [])
    if total == 0 and level != "insufficient_evidence":
        caveats.insert(0, NO_DETECTION_CAVEAT)
    if total == 0 and provider_failures and level == "insufficient_evidence":
        caveats.insert(0, "No score was given because one or more providers failed. "
                          "A missing answer is not evidence that the item is safe.")
    return {
        "score": total,
        "raw_total": raw_total,
        "level": level,
        "level_label": LEVEL_LABELS[level],
        "factors": [asdict(f) for f in factors],
        "caveats": caveats,
    }


# ---------- provider-derived factors (shared by file, URL and indicator analysis) ----------

def engine_detection_factor(positives: int, total: int, *, source: str, code: str = "engine_detections", max_points: int = 40) -> Factor | None:
    if total <= 0 or positives <= 0:
        return None
    points = min(max_points, round(max_points * positives / total))
    return Factor(
        code=code,
        label=f"{source}: engines flagging the item",
        points=points,
        reason=f"{positives} of {total} engines flagged it ({source}).",
        evidence={"source": source, "positives": positives, "total": total},
    )


def otx_factor(pulses: int, *, subject: str) -> Factor | None:
    if pulses <= 0:
        return None
    return Factor(
        code="otx_pulses",
        label="AlienVault OTX pulses",
        points=min(10, 2 * pulses),
        reason=f"{pulses} OTX pulse(s) reference this {subject}.",
        evidence={"pulses": pulses},
    )


def abuseipdb_factor(score: int, ip: str) -> Factor | None:
    if score <= 0:
        return None
    return Factor(
        code="abuseipdb_confidence",
        label="AbuseIPDB abuse confidence",
        points=min(20, round(score * 0.2)),
        reason=f"AbuseIPDB reports an abuse confidence score of {score}% for {ip}.",
        evidence={"ip": ip, "abuse_confidence_score": score},
    )


# ---------- file factors ----------

# PDF indicator code -> (factor code, label, points). Several indicators can map to one factor.
_PDF_FACTORS = {
    "pdf_javascript": ("pdf_javascript", "PDF JavaScript", 15),
    "pdf_js": ("pdf_javascript", "PDF JavaScript", 15),
    "pdf_open_action": ("pdf_automatic_action", "PDF automatic action", 10),
    "pdf_aa": ("pdf_automatic_action", "PDF automatic action", 10),
    "pdf_launch": ("pdf_launch_action", "PDF launch action", 10),
    "pdf_embedded_file": ("pdf_embedded_content", "PDF embedded content", 5),
    "pdf_xfa": ("pdf_embedded_content", "PDF embedded content", 5),
}


def file_factors(
    identification: dict[str, Any],
    static: dict[str, Any] | None,
    yara: dict[str, Any] | None,
    strings: dict[str, Any] | None,
    *,
    malwarebazaar_hit: bool = False,
    detections: list[tuple[str, int, int]] | None = None,
    otx_pulses: int = 0,
) -> list[Factor]:
    factors: list[Factor] = []

    for source, positives, total in detections or []:
        f = engine_detection_factor(positives, total, source=source)
        if f:
            factors.append(f)

    if malwarebazaar_hit:
        factors.append(Factor(
            code="known_malicious_hash",
            label="Known-malicious hash",
            points=30,
            reason="MalwareBazaar lists this SHA-256 as a known malware sample.",
        ))

    if otx_pulses:
        f = otx_factor(otx_pulses, subject="file hash")
        if f:
            factors.append(f)

    if identification.get("extension_matches") is False:
        factors.append(Factor(
            code="extension_mismatch",
            label="Extension does not match content",
            points=10,
            reason=identification["warnings"][-1] if identification.get("warnings") else "Declared extension differs from the detected content type.",
            evidence={"declared": identification.get("declared_extension"), "detected": identification.get("detected_family")},
        ))

    if identification.get("detected_family") == "pe_executable":
        factors.append(Factor(
            code="native_executable",
            label="Windows executable",
            points=5,
            reason="The file is a Windows PE executable, which can run code when opened.",
        ))

    if static:
        kind = static.get("kind")
        if kind == "pdf":
            merged: dict[str, Factor] = {}
            for ind in static.get("indicators", []):
                if ind["code"] not in _PDF_FACTORS:
                    continue
                code, label, points = _PDF_FACTORS[ind["code"]]
                prev = merged.get(code)
                count = ind["count"] + (prev.evidence["count"] if prev else 0)
                merged[code] = Factor(
                    code=code,
                    label=label,
                    points=points,
                    reason=ind["description"] if prev is None else prev.reason,
                    evidence={"count": count},
                )
            factors.extend(merged.values())

        if kind == "zip":
            if static.get("executables"):
                factors.append(Factor(
                    code="archive_executable",
                    label="Executable inside archive",
                    points=10,
                    reason="The archive contains executable or script entries.",
                    evidence={"entries": static["executables"][:10]},
                ))
            if static.get("path_traversal_entries"):
                factors.append(Factor(
                    code="archive_path_traversal",
                    label="Unsafe archive entry names",
                    points=15,
                    reason="Entry names contain path traversal or absolute paths.",
                    evidence={"entries": static["path_traversal_entries"][:10]},
                ))
            if static.get("is_suspicious_bomb") or static.get("limit_exceeded") in ("too_many_entries", "uncompressed_size"):
                factors.append(Factor(
                    code="archive_bomb_limits",
                    label="Archive exceeds safe inspection limits",
                    points=10,
                    reason="The archive exceeded entry, size or compression-ratio limits.",
                    evidence={"limit": static.get("limit_exceeded"), "max_ratio": static.get("max_compression_ratio")},
                ))
            # Container evidence: a vbaProject.bin entry counts even when the VBA
            # parser cannot read it, so a macro container is never scored as clean.
            if static.get("has_vba_macro"):
                factors.append(Factor(
                    code="office_macro_present",
                    label="Office macro project present",
                    points=10,
                    reason="The container holds a VBA macro project (vbaProject.bin).",
                ))
            office_part = static.get("office")
            if office_part:
                factors.extend(_office_factors(office_part, include_macro=False))

        if kind == "office":
            factors.extend(_office_factors(static))

        if kind == "pe":
            dangerous = static.get("suspicious_imports") or []
            if dangerous:
                factors.append(Factor(
                    code="pe_dangerous_imports",
                    label="Process-injection or download imports",
                    points=min(20, 5 * len(dangerous)),
                    reason=f"{len(dangerous)} high-signal import(s) present.",
                    evidence={"imports": [d["function"] for d in dangerous]},
                ))
            if static.get("packing_hints"):
                factors.append(Factor(
                    code="pe_packed_or_high_entropy",
                    label="Packed or high-entropy executable section",
                    points=10,
                    reason="; ".join(static["packing_hints"][:3]),
                ))

        if kind == "image":
            if static.get("trailing_bytes", 0) > 0:
                factors.append(Factor(
                    code="image_trailing_data",
                    label="Data appended after image end",
                    points=15,
                    reason=f"{static['trailing_bytes']} byte(s) follow the image end marker.",
                ))
            if static.get("embedded_signatures"):
                factors.append(Factor(
                    code="image_embedded_file",
                    label="Embedded file signature inside an image",
                    points=15,
                    reason="; ".join(static["embedded_signatures"][:3]),
                ))

    if yara and yara.get("matches"):
        weights = {"high": 15, "medium": 8, "low": 2}
        points = sum(weights.get(m["severity"], 2) for m in yara["matches"])
        factors.append(Factor(
            code="yara_matches",
            label="YARA indicator rules matched",
            points=min(30, points),
            reason=f"{len(yara['matches'])} indicator rule(s) matched: "
                   + ", ".join(m["rule"] for m in yara["matches"][:5]) + ".",
            evidence={"rules": [m["rule"] for m in yara["matches"]]},
        ))

    if strings and strings.get("categories"):
        weights = {
            "powershell_usage": 8, "download_cradle": 8,
            "shell_execution": 5, "autorun_persistence": 8,
        }
        points = sum(weights.get(c["category"], 3) for c in strings["categories"])
        factors.append(Factor(
            code="suspicious_strings",
            label="Suspicious strings",
            points=min(20, points),
            reason="; ".join(c["description"] for c in strings["categories"][:4]) + ".",
            evidence={"categories": [c["category"] for c in strings["categories"]]},
        ))

    return factors


def _office_factors(office_part: dict[str, Any], include_macro: bool = True) -> list[Factor]:
    out = []
    if include_macro and office_part.get("has_macros"):
        out.append(Factor(
            code="office_macro_present",
            label="Office macro project present",
            points=10,
            reason="The document contains VBA macros.",
            evidence={"modules": office_part.get("macro_module_count", 0)},
        ))
    if office_part.get("auto_exec_keywords"):
        out.append(Factor(
            code="office_auto_exec",
            label="Macro runs automatically",
            points=15,
            reason="Auto-execution trigger(s) found: " + ", ".join(office_part["auto_exec_keywords"][:5]) + ".",
            evidence={"keywords": office_part["auto_exec_keywords"][:10]},
        ))
    if office_part.get("suspicious_keywords"):
        out.append(Factor(
            code="office_suspicious_keywords",
            label="Suspicious macro functions",
            points=10,
            reason="Suspicious VBA keywords: " + ", ".join(office_part["suspicious_keywords"][:6]) + ".",
            evidence={"keywords": office_part["suspicious_keywords"][:10]},
        ))
    return out


def build_file_score(
    identification: dict[str, Any],
    static: dict[str, Any] | None,
    yara: dict[str, Any] | None,
    strings: dict[str, Any] | None,
    *,
    malwarebazaar_hit: bool,
    detections: list[tuple[str, int, int]],
    otx_pulses: int,
    consulted_sources: int,
    local_complete: bool,
    extra_caveats: list[str] | None = None,
    provider_failures: int = 0,
) -> dict[str, Any]:
    factors = file_factors(
        identification, static, yara, strings,
        malwarebazaar_hit=malwarebazaar_hit,
        detections=detections,
        otx_pulses=otx_pulses,
    )
    any_detection = malwarebazaar_hit or any(p > 0 for _, p, _ in detections)
    caveats = list(extra_caveats or [])
    if not any_detection and not factors:
        pass  # NO_DETECTION_CAVEAT is added by build_score when score is 0
    return build_score(
        factors,
        consulted_sources=consulted_sources,
        local_complete=local_complete,
        extra_caveats=caveats,
        provider_failures=provider_failures,
    )


# ---------- URL factors ----------

def url_factors(
    *,
    host: str,
    registrable_domain: str,
    final_registrable_domain: str | None,
    redirect_count: int,
    is_ip_literal: bool,
    is_punycode: bool,
    suspicious_tld: bool,
    deep_subdomains: bool,
    lookalike_of: str | None,
    login_form: bool,
    scheme: str,
    tls_problem: str | None,
    domain_age_days: int | None,
    non_public_redirect: str | None,
    provider_detections: list[tuple[str, int, int]],
    otx_pulses: int,
    urlscan_malicious: int,
    abuseipdb: list[tuple[str, int]],
) -> list[Factor]:
    factors: list[Factor] = []

    for source, positives, total in provider_detections:
        code = "domain_engine_detections" if source.startswith("VirusTotal domain") else "engine_detections"
        max_points = 25 if code == "domain_engine_detections" else 40
        f = engine_detection_factor(positives, total, source=source, code=code, max_points=max_points)
        if f:
            factors.append(f)

    if urlscan_malicious:
        factors.append(Factor(
            code="urlscan_malicious_verdict",
            label="urlscan.io verdict: malicious",
            points=20 if urlscan_malicious >= 3 else 15,
            reason=f"{urlscan_malicious} prior urlscan.io scan(s) of this domain were marked malicious.",
            evidence={"malicious_scans": urlscan_malicious},
        ))

    if otx_pulses:
        f = otx_factor(otx_pulses, subject="indicator")
        if f:
            factors.append(f)

    for ip, score in abuseipdb:
        f = abuseipdb_factor(score, ip)
        if f:
            factors.append(f)

    if domain_age_days is not None:
        if domain_age_days < 30:
            factors.append(Factor(
                code="domain_very_new",
                label="Domain registered very recently",
                points=15,
                reason=f"The domain was registered {domain_age_days} day(s) ago.",
                evidence={"age_days": domain_age_days},
            ))
        elif domain_age_days < 180:
            factors.append(Factor(
                code="domain_new",
                label="Domain registered recently",
                points=5,
                reason=f"The domain was registered {domain_age_days} day(s) ago.",
                evidence={"age_days": domain_age_days},
            ))

    if lookalike_of:
        factors.append(Factor(
            code="lookalike_domain",
            label="Possible brand lookalike domain",
            points=20,
            reason=f"The domain closely resembles '{lookalike_of}' but is not that brand's domain.",
            evidence={"brand_domain": lookalike_of},
        ))
    if is_punycode:
        factors.append(Factor(
            code="punycode_domain",
            label="Internationalised (punycode) domain",
            points=10,
            reason="The host uses punycode (xn--), which can hide look-alike characters.",
        ))
    if is_ip_literal:
        factors.append(Factor(
            code="ip_literal_host",
            label="Address used instead of a domain name",
            points=10,
            reason="The URL points directly at an IP address.",
        ))
    if suspicious_tld:
        factors.append(Factor(
            code="suspicious_tld",
            label="Frequently abused top-level domain",
            points=5,
            reason="The top-level domain is one commonly used for abuse in public reports.",
        ))
    if deep_subdomains:
        factors.append(Factor(
            code="deep_subdomains",
            label="Many subdomain levels",
            points=5,
            reason="The host has five or more labels, which is common in generated phishing hosts.",
            evidence={"host": host},
        ))
    if login_form:
        factors.append(Factor(
            code="login_form",
            label="Password field on the page",
            points=15 if (lookalike_of or (domain_age_days is not None and domain_age_days < 180)) else 10,
            reason="The page asks for a password" + (" on a new or look-alike domain." if (lookalike_of or (domain_age_days is not None and domain_age_days < 180)) else "."),
        ))
    if scheme == "http" and login_form:
        factors.append(Factor(
            code="login_over_http",
            label="Password field over plain HTTP",
            points=10,
            reason="Credentials would be sent without encryption.",
        ))
    if tls_problem:
        factors.append(Factor(
            code="tls_problem",
            label="TLS certificate problem",
            points=10,
            reason=tls_problem,
        ))
    if final_registrable_domain and registrable_domain and final_registrable_domain != registrable_domain:
        factors.append(Factor(
            code="cross_domain_redirect",
            label="Redirects to a different domain",
            points=5,
            reason=f"The link ends on '{final_registrable_domain}' instead of '{registrable_domain}'.",
            evidence={"final_domain": final_registrable_domain},
        ))
    if redirect_count >= 3:
        factors.append(Factor(
            code="long_redirect_chain",
            label="Long redirect chain",
            points=5,
            reason=f"The link redirects {redirect_count} times before its final page.",
            evidence={"redirects": redirect_count},
        ))
    if non_public_redirect:
        factors.append(Factor(
            code="redirect_to_non_public_address",
            label="Redirect to a non-public address (blocked)",
            points=15,
            reason=non_public_redirect,
        ))

    return factors


def build_url_score(
    *,
    consulted_sources: int,
    local_complete: bool,
    extra_caveats: list[str] | None = None,
    provider_failures: int = 0,
    **factor_inputs: Any,
) -> dict[str, Any]:
    factors = url_factors(**factor_inputs)
    return build_score(
        factors,
        consulted_sources=consulted_sources,
        local_complete=local_complete,
        extra_caveats=extra_caveats,
        provider_failures=provider_failures,
    )


def indicator_score(
    *,
    detections: list[tuple[str, int, int]],
    malwarebazaar_hit: bool,
    otx_pulses: int,
    abuseipdb_score: int | None,
    abuseipdb_ip: str | None,
    urlscan_malicious: int,
    consulted_sources: int,
    local_complete: bool,
    extra_caveats: list[str] | None = None,
    provider_failures: int = 0,
) -> dict[str, Any]:
    factors: list[Factor] = []
    for source, positives, total in detections:
        code = "engine_detections"
        f = engine_detection_factor(positives, total, source=source, code=code)
        if f:
            factors.append(f)
    if malwarebazaar_hit:
        factors.append(Factor(
            code="known_malicious_hash",
            label="Known-malicious hash",
            points=30,
            reason="MalwareBazaar lists this hash as a known malware sample.",
        ))
    if otx_pulses:
        f = otx_factor(otx_pulses, subject="indicator")
        if f:
            factors.append(f)
    if abuseipdb_score and abuseipdb_ip:
        f = abuseipdb_factor(abuseipdb_score, abuseipdb_ip)
        if f:
            factors.append(f)
    if urlscan_malicious:
        factors.append(Factor(
            code="urlscan_malicious_verdict",
            label="urlscan.io verdict: malicious",
            points=20 if urlscan_malicious >= 3 else 15,
            reason=f"{urlscan_malicious} prior urlscan.io scan(s) were marked malicious.",
            evidence={"malicious_scans": urlscan_malicious},
        ))
    return build_score(
        factors,
        consulted_sources=consulted_sources,
        local_complete=local_complete,
        extra_caveats=extra_caveats,
        provider_failures=provider_failures,
    )
