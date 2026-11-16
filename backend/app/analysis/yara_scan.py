"""
YARA scanning with the rules bundled in app/analysis/yara_rules (or the
directory set by YARA_RULES_DIR). Rules are compiled once per process.

If yara-python is not installed or a rule file fails to compile, the result
says so explicitly (status "unavailable" / "error") and nothing is reported
as a clean scan.
"""

import logging
from pathlib import Path
from typing import Any

from app.config import settings

logger = logging.getLogger(__name__)

_compiled = None
_compile_error: str | None = None
_compiled_dir: Path | None = None


def _compile(rules_dir: Path):
    global _compiled, _compile_error, _compiled_dir
    if _compiled is not None and _compiled_dir == rules_dir:
        return _compiled
    try:
        import yara
    except ImportError:
        _compile_error = "yara-python is not installed"
        return None
    files = {p.stem: str(p) for p in sorted(rules_dir.glob("*.yar"))}
    if not files:
        _compile_error = "no .yar rule files found"
        return None
    try:
        _compiled = yara.compile(filepaths=files)
        _compiled_dir = rules_dir
        _compile_error = None
        return _compiled
    except yara.Error as exc:
        _compile_error = f"rule compilation failed: {exc}"
        logger.error("YARA compile failed: %s", exc)
        return None


def scan_bytes(data: bytes) -> dict[str, Any]:
    rules = _compile(settings.yara_rules_path)
    if rules is None:
        return {"status": "unavailable", "detail": _compile_error, "matches": []}
    try:
        raw = rules.match(data=data, timeout=10)
    except Exception as exc:  # yara timeout or internal error
        return {"status": "error", "detail": f"scan failed ({type(exc).__name__})", "matches": []}

    matches = []
    for m in raw:
        meta = dict(m.meta) if m.meta else {}
        matches.append({
            "rule": m.rule,
            "severity": str(meta.get("severity", "low")),
            "description": str(meta.get("description", "")),
            "tags": list(m.tags),
        })
    return {"status": "scanned", "detail": None, "matches": matches}
