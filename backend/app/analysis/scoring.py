"""
Explainable risk scoring for file and URL analysis.

Every point awarded is a named Factor with its own reason and evidence, so
the report can show exactly why a score was produced. The total is capped
at 100. Weights are starting values and must be tuned on a labelled test
set before being quoted as accurate.

Scores express triage priority, not proof of maliciousness, and the result
never says a file or URL is "safe". No detection is reported as "no listed
source flagged this item at the time of the check".
"""

from dataclasses import asdict, dataclass, field
from typing import Any

SCORE_CAP = 100

NO_DETECTION_CAVEAT = (
    "No listed source flagged this item at the time of the check. "
    "This does not guarantee that it is safe."
)
GENERAL_CAVEAT = "A detection or a low score is a triage aid, not proof."


@dataclass(frozen=True)
class Factor:
    code: str
    label: str
    points: int
    reason: str
    evidence: dict[str, Any] = field(default_factory=dict)


def band_for(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def build_score(factors: list[Factor]) -> dict[str, Any]:
    raw_total = sum(f.points for f in factors)
    total = min(SCORE_CAP, max(0, raw_total))
    return {
        "score": total,
        "raw_total": raw_total,
        "level": band_for(total),
        "factors": [asdict(f) for f in factors],
        "caveats": [GENERAL_CAVEAT],
    }


def provider_detection_factor(positives: int, total_engines: int) -> Factor | None:
    """Share of engines flagging the item, up to 40 points."""
    if total_engines <= 0 or positives <= 0:
        return None
    points = round(40 * positives / total_engines)
    return Factor(
        code="engine_detections",
        label="Engines flagging the item",
        points=points,
        reason=f"{positives} of {total_engines} engines flagged it.",
        evidence={"positives": positives, "total": total_engines},
    )


def file_factors(
    identification: dict[str, Any],
    static: dict[str, Any] | None,
    *,
    known_malicious_hash: bool = False,
    detection: tuple[int, int] | None = None,
) -> list[Factor]:
    factors: list[Factor] = []

    if detection is not None:
        f = provider_detection_factor(*detection)
        if f:
            factors.append(f)

    if known_malicious_hash:
        factors.append(
            Factor(
                code="known_malicious_hash",
                label="Known-malicious hash",
                points=30,
                reason="A threat-intelligence source lists this hash as malware.",
            )
        )

    if identification.get("extension_matches") is False:
        factors.append(
            Factor(
                code="extension_mismatch",
                label="Extension does not match content",
                points=10,
                reason=identification["warnings"][-1]
                if identification.get("warnings")
                else "Declared extension differs from detected content type.",
                evidence={
                    "declared": identification.get("declared_extension"),
                    "detected": identification.get("detected_family"),
                },
            )
        )

    if identification.get("detected_family") == "pe_executable":
        factors.append(
            Factor(
                code="native_executable",
                label="Windows executable",
                points=5,
                reason="The file is a Windows PE executable, which can run code when opened.",
            )
        )

    if static:
        if static.get("kind") == "pdf":
            for ind in static.get("indicators", []):
                if ind["code"] in ("pdf_javascript", "pdf_js"):
                    factors.append(
                        Factor(
                            code=ind["code"],
                            label="PDF JavaScript",
                            points=15,
                            reason=ind["description"],
                            evidence={"count": ind["count"]},
                        )
                    )
                elif ind["code"] in ("pdf_open_action", "pdf_aa", "pdf_launch"):
                    factors.append(
                        Factor(
                            code=ind["code"],
                            label="PDF automatic action",
                            points=10,
                            reason=ind["description"],
                            evidence={"count": ind["count"]},
                        )
                    )
                elif ind["code"] in ("pdf_embedded_file", "pdf_xfa"):
                    factors.append(
                        Factor(
                            code=ind["code"],
                            label="PDF embedded content",
                            points=5,
                            reason=ind["description"],
                            evidence={"count": ind["count"]},
                        )
                    )

        if static.get("kind") == "zip":
            if static.get("executables"):
                factors.append(
                    Factor(
                        code="archive_executable",
                        label="Executable inside archive",
                        points=10,
                        reason="The archive contains executable or script entries.",
                        evidence={"entries": static["executables"][:10]},
                    )
                )
            if static.get("has_vba_macro"):
                factors.append(
                    Factor(
                        code="office_macro_present",
                        label="Office macro project present",
                        points=10,
                        reason="The document contains a VBA macro project. Auto-execution was not verified.",
                    )
                )
            if static.get("path_traversal_entries"):
                factors.append(
                    Factor(
                        code="archive_path_traversal",
                        label="Unsafe archive entry names",
                        points=15,
                        reason="Entry names contain path traversal or absolute paths.",
                        evidence={"entries": static["path_traversal_entries"][:10]},
                    )
                )
            if static.get("is_suspicious_bomb") or static.get("limit_exceeded"):
                factors.append(
                    Factor(
                        code="archive_bomb_limits",
                        label="Archive exceeds safe inspection limits",
                        points=10,
                        reason="The archive exceeded entry, size or compression-ratio limits.",
                        evidence={"limit": static.get("limit_exceeded")},
                    )
                )

    return factors


def build_file_report_score(
    identification: dict[str, Any],
    static: dict[str, Any] | None,
    *,
    known_malicious_hash: bool = False,
    detection: tuple[int, int] | None = None,
) -> dict[str, Any]:
    factors = file_factors(
        identification,
        static,
        known_malicious_hash=known_malicious_hash,
        detection=detection,
    )
    result = build_score(factors)
    if detection is None or detection[0] == 0:
        result["caveats"].insert(0, NO_DETECTION_CAVEAT)
    return result
