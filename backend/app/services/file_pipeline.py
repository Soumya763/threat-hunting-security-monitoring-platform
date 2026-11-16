"""
File analysis pipeline (background task). The uploaded bytes are read from
quarantine and are only parsed, never executed, extracted or written out.

Steps (each recorded with its own status):
  1. identify type from magic bytes and check the extension
  2. format-specific static analysis (PE, PDF, Office/VBA, ZIP, PNG/JPEG)
  3. suspicious-string extraction and YARA indicator rules
  4. reputation: MalwareBazaar (hash), VirusTotal (hash), OTX (hash), and
     this owner's earlier analyses of the same SHA-256
  5. explainable scoring and classification

Each step runs under a timeout. A timed-out or crashing step marks the
analysis "partial" or "failed" without failing the whole request.
"""

import concurrent.futures
import logging
from datetime import datetime, timezone
from typing import Any, Callable

from app.analysis import filetype, scoring, static, strings_scan, yara_scan
from app.analysis.hashing import hash_bytes
from app.config import settings
from app.services import quarantine
from app.services.intel import base
from app.services.intel.gateway import get_gateway
from app.services.recommendations import recommend

logger = logging.getLogger(__name__)

_executor = concurrent.futures.ThreadPoolExecutor(max_workers=4, thread_name_prefix="file-analysis")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _with_timeout(name: str, fn: Callable[[], Any], steps: list[dict[str, Any]]) -> Any:
    """Run one analysis step with a timeout. Returns None on timeout or error."""
    future = _executor.submit(fn)
    try:
        value = future.result(timeout=settings.analysis_step_timeout_seconds)
        steps.append({"name": name, "status": "complete", "message": None})
        return value
    except concurrent.futures.TimeoutError:
        steps.append({"name": name, "status": "timeout",
                      "message": f"Stopped after {int(settings.analysis_step_timeout_seconds)} seconds."})
        return None
    except Exception as exc:
        logger.exception("File analysis step %s failed", name)
        steps.append({"name": name, "status": "failed", "message": f"Step failed ({type(exc).__name__})."})
        return None


def analyze_file(data: bytes, *, filename: str, sha256: str, owner_id: int | None,
                 session_factory, gateway=None, history_count: int = 0) -> dict[str, Any]:
    gateway = gateway or get_gateway()
    steps: list[dict[str, Any]] = []
    caveats: list[str] = []

    hashes = hash_bytes(data, max_bytes=len(data) or 1)
    identification = filetype.identify(filename, data[:8192])
    steps.append({"name": "Identify file type", "status": "complete", "message": None})

    family = identification["detected_family"]
    static_result = _with_timeout("Static analysis", lambda: static.analyze_static(family, data, filename), steps)
    strings_result = _with_timeout("Suspicious strings", lambda: strings_scan.scan_strings(data), steps)
    yara_result = _with_timeout("YARA indicator rules", lambda: yara_scan.scan_bytes(data), steps)
    if yara_result and yara_result["status"] in ("unavailable", "error"):
        caveats.append(f"YARA rules were not applied: {yara_result['detail']}.")

    if static_result and static_result.get("parse_error"):
        caveats.append(f"Format parser reported: {static_result['parse_error']}.")
    if static_result and static_result.get("limitations"):
        caveats.extend(static_result["limitations"][:2])

    # Reputation
    providers_out: dict[str, Any] = {}
    detections: list[tuple[str, int, int]] = []
    mb_hit = False
    otx_pulses = 0
    if settings.provider_hash_lookup_enabled:
        providers_out["MalwareBazaar"] = gateway.lookup("malwarebazaar", "sha256", sha256)
        providers_out["VirusTotal file"] = gateway.lookup("virustotal", "sha256", sha256)
        providers_out["OTX file"] = gateway.lookup("otx", "sha256", sha256)
        mb = providers_out["MalwareBazaar"]
        mb_hit = mb["status"] == base.STATUS_OK
        vt = providers_out["VirusTotal file"]
        if vt["status"] == base.STATUS_OK and vt["detection"]:
            detections.append(("VirusTotal", vt["detection"]["positives"], vt["detection"]["total"]))
        otx = providers_out["OTX file"]
        if otx["status"] == base.STATUS_OK:
            otx_pulses = otx["summary"].get("pulse_count", 0)
    else:
        caveats.append("Provider hash lookups are disabled (PROVIDER_HASH_LOOKUP_ENABLED=false).")

    consulted = sum(1 for r in providers_out.values() if r["status"] in base.CONSULTED_STATUSES)
    provider_errors = [k for k, r in providers_out.items() if r["status"] in
                       ("unavailable", "timeout", "invalid_key", "rate_limited")]
    if provider_errors:
        caveats.append("Some providers were unavailable or rate limited: " + ", ".join(provider_errors) + ".")
    if history_count:
        caveats.append(f"You have analysed this exact file {history_count} time(s) before.")

    local_ok = all(s["status"] in ("complete", "skipped") for s in steps)
    score = scoring.build_file_score(
        identification, static_result, yara_result, strings_result,
        malwarebazaar_hit=mb_hit,
        detections=detections,
        otx_pulses=otx_pulses,
        consulted_sources=consulted,
        local_complete=local_ok,
        extra_caveats=caveats,
    )
    level = score["level"]
    configured = any(r["status"] != base.STATUS_NOT_CONFIGURED for r in providers_out.values())
    recommendations = recommend(
        level,
        providers_configured=configured,
        extension_mismatch=identification.get("extension_matches") is False,
        detected_family=family,
        consent_available=True,
        kind="file",
    )

    status = "complete" if local_ok and not provider_errors else "partial"
    return {
        "file": {
            "name": quarantine.sanitize_filename(filename),
            "size_bytes": len(data),
            "md5": hashes["md5"],
            "sha1": hashes["sha1"],
            "sha256": hashes["sha256"],
        },
        "identification": identification,
        "static": static_result,
        "strings": strings_result,
        "yara": yara_result,
        "providers": providers_out,
        "detections": {
            "engines_flagging": sum(p for _, p, _ in detections),
            "engines_total": max((t for _, _, t in detections), default=0),
            "providers_flagging": sum(1 for _, p, _ in detections if p > 0) + (1 if mb_hit else 0),
            "known_malware_sample": mb_hit,
        },
        "score": score["score"],
        "classification": level,
        "classification_label": score["level_label"],
        "factors": score["factors"],
        "caveats": score["caveats"],
        "recommendations": recommendations,
        "steps": steps,
        "analysis_status": status,
        "consulted_sources": consulted,
        "analysed_at": _now().isoformat(),
    }


def run_file_analysis(analysis_id: int, *, session_factory, gateway=None) -> None:
    from app.models.analysis import Analysis

    db = session_factory()
    try:
        row = db.get(Analysis, analysis_id)
        if row is None:
            return
        if not row.quarantine_key:
            row.status = "failed"
            row.error = "The file has been removed by the retention policy."
            row.completed_at = _now()
            db.commit()
            return
        row.status = "running"
        db.commit()

        try:
            data = quarantine.read_quarantined(row.quarantine_key)
            history = (
                db.query(Analysis)
                .filter(Analysis.owner_id == row.owner_id)
                .filter(Analysis.sha256 == row.sha256)
                .filter(Analysis.id != row.id)
                .count()
            )
            result = analyze_file(
                data, filename=row.display_name or "upload", sha256=row.sha256,
                owner_id=row.owner_id, session_factory=session_factory,
                gateway=gateway, history_count=history,
            )
        except Exception:
            logger.exception("File analysis %s failed", analysis_id)
            row.status = "failed"
            row.error = "The analysis stopped unexpectedly. Try again later."
            row.completed_at = _now()
            db.commit()
            return

        row.result = result
        row.risk_score = result["score"]
        row.risk_level = result["classification"]
        row.detected_type = (result["identification"] or {}).get("detected_family")
        row.status = result["analysis_status"]
        row.completed_at = _now()
        db.commit()
    finally:
        db.close()
