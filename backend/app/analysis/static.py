"""
Static inspection of untrusted files. Nothing here executes or extracts
the file; all checks read bytes or ZIP metadata only.

Limits are enforced before parsing so hostile input cannot exhaust memory
or time:
  - PDF: the byte scan is capped at MAX_SCAN_BYTES.
  - ZIP/OOXML: entry count, total uncompressed size and per-entry
    compression ratio are capped; entry names are checked for path
    traversal and absolute paths; nothing is written to disk.

Limitations (reported to the user, not hidden):
  - PDF objects inside compressed object streams are not visible to a
    byte scan, so indicators can be missed.
  - VBA macro presence is detected from the OOXML container; whether a
    macro auto-executes is NOT checked in this version.
  - PE header parsing (pefile) is not implemented yet.
"""

import io
import re
import zipfile
from typing import Any

MAX_SCAN_BYTES = 32 * 1024 * 1024
MAX_ZIP_ENTRIES = 2000
MAX_ZIP_UNCOMPRESSED_BYTES = 256 * 1024 * 1024
MAX_ZIP_RATIO = 100

_PDF_INDICATORS: list[tuple[str, bytes, str]] = [
    # (code, byte pattern, description)
    ("pdf_javascript", rb"/JavaScript\b", "PDF contains a /JavaScript action or object."),
    ("pdf_js", rb"/JS\b", "PDF contains a /JS entry (JavaScript code)."),
    ("pdf_open_action", rb"/OpenAction\b", "PDF runs an action automatically when opened."),
    ("pdf_aa", rb"/AA\b", "PDF contains an additional-actions trigger."),
    ("pdf_launch", rb"/Launch\b", "PDF contains a /Launch action (can start an external program)."),
    ("pdf_embedded_file", rb"/EmbeddedFile\b", "PDF embeds another file."),
    ("pdf_xfa", rb"/XFA\b", "PDF uses XFA forms (a known abuse vector)."),
    ("pdf_uri", rb"/URI\b", "PDF contains an outbound link action."),
]

_EXECUTABLE_EXTENSIONS = frozenset(
    {"exe", "dll", "scr", "com", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse",
     "wsf", "hta", "lnk", "msi", "jar", "cpl", "reg"}
)
_OOXML_MARKERS = ("[Content_Types].xml",)
_OOXML_PREFIXES = ("word/", "xl/", "ppt/")


def analyze_pdf(data: bytes) -> dict[str, Any]:
    scanned = data[:MAX_SCAN_BYTES]
    truncated = len(data) > MAX_SCAN_BYTES
    indicators = []
    for code, pattern, description in _PDF_INDICATORS:
        matches = len(re.findall(pattern, scanned))
        if matches:
            indicators.append(
                {"code": code, "description": description, "count": matches}
            )
    return {
        "kind": "pdf",
        "indicators": indicators,
        "truncated": truncated,
        "limitations": [
            "Objects inside compressed object streams are not inspected.",
        ],
    }


def analyze_zip(data: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {
        "kind": "zip",
        "entry_count": 0,
        "is_ooxml": False,
        "has_vba_macro": False,
        "executables": [],
        "path_traversal_entries": [],
        "nested_archives": [],
        "limit_exceeded": None,
        "is_suspicious_bomb": False,
        "limitations": [
            "Macro auto-execution is not verified; only macro presence is reported.",
        ],
    }

    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        result["limit_exceeded"] = "invalid_zip"
        return result

    with archive:
        infos = archive.infolist()
        result["entry_count"] = len(infos)

        if len(infos) > MAX_ZIP_ENTRIES:
            result["limit_exceeded"] = "too_many_entries"
            return result

        total_uncompressed = sum(i.file_size for i in infos)
        if total_uncompressed > MAX_ZIP_UNCOMPRESSED_BYTES:
            result["limit_exceeded"] = "uncompressed_size"
            result["is_suspicious_bomb"] = True
            return result

        names = [i.filename for i in infos]
        result["is_ooxml"] = any(n in names for n in _OOXML_MARKERS) and any(
            n.startswith(_OOXML_PREFIXES) for n in names
        )
        result["has_vba_macro"] = any(n.endswith("vbaProject.bin") for n in names)

        for info in infos:
            name = info.filename
            normalised = name.replace("\\", "/")
            if normalised.startswith("/") or re.match(r"^[A-Za-z]:", normalised) or ".." in normalised.split("/"):
                result["path_traversal_entries"].append(name)

            ext = name.rsplit(".", 1)[-1].lower() if "." in name.rsplit("/", 1)[-1] else ""
            if ext in _EXECUTABLE_EXTENSIONS:
                result["executables"].append(name)
            if ext in ("zip", "rar", "7z", "gz", "tar", "iso", "img"):
                result["nested_archives"].append(name)

            if info.compress_size > 0:
                ratio = info.file_size / info.compress_size
                if ratio > MAX_ZIP_RATIO:
                    result["is_suspicious_bomb"] = True
            elif info.file_size > 0:
                result["is_suspicious_bomb"] = True

    return result


def analyze_static(family: str | None, data: bytes) -> dict[str, Any] | None:
    """Dispatch to the right static analyser, or None if not applicable."""
    if family == "pdf":
        return analyze_pdf(data)
    if family == "zip_container":
        return analyze_zip(data)
    return None
