"""
Static inspection dispatcher and the PDF / ZIP analysers.

Everything here reads bytes or container metadata only. Nothing is executed
and no archive entry is extracted to disk.

Limits are enforced before parsing:
  - PDF: the byte scan is capped at MAX_SCAN_BYTES.
  - ZIP/OOXML: entry count, total uncompressed size and per-entry
    compression ratio are capped; names are checked for traversal.

Known limitation: PDF objects inside compressed object streams are not
visible to a byte scan, so some indicators can be missed.
"""

import io
import re
import zipfile
from typing import Any

from app.analysis import image_scan, office, pe

MAX_SCAN_BYTES = 32 * 1024 * 1024
MAX_ZIP_ENTRIES = 2000
MAX_ZIP_UNCOMPRESSED_BYTES = 256 * 1024 * 1024
MAX_ZIP_RATIO = 100
MAX_LISTED = 20

_PDF_INDICATORS: list[tuple[str, bytes, str]] = [
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
_ARCHIVE_EXTENSIONS = frozenset({"zip", "rar", "7z", "gz", "tar", "iso", "img"})
_OOXML_MARKERS = ("[Content_Types].xml",)
_OOXML_PREFIXES = ("word/", "xl/", "ppt/")

_PDF_URL = re.compile(rb"https?://[\x21-\x7e]{4,300}")


def analyze_pdf(data: bytes) -> dict[str, Any]:
    scanned = data[:MAX_SCAN_BYTES]
    indicators = []
    for code, pattern, description in _PDF_INDICATORS:
        count = len(re.findall(pattern, scanned))
        if count:
            indicators.append({"code": code, "description": description, "count": count})

    urls = sorted({u.decode("ascii", "replace") for u in _PDF_URL.findall(scanned)})[:MAX_LISTED]
    return {
        "kind": "pdf",
        "indicators": indicators,
        "urls": urls,
        "truncated": len(data) > MAX_SCAN_BYTES,
        "limitations": ["Objects inside compressed object streams are not inspected."],
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
        "max_compression_ratio": 0.0,
        "limitations": ["Entries are inspected by name and metadata only; nothing is extracted."],
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

        total = sum(i.file_size for i in infos)
        if total > MAX_ZIP_UNCOMPRESSED_BYTES:
            result["limit_exceeded"] = "uncompressed_size"
            result["is_suspicious_bomb"] = True
            return result

        names = [i.filename for i in infos]
        result["is_ooxml"] = any(n in names for n in _OOXML_MARKERS) and any(
            n.startswith(_OOXML_PREFIXES) for n in names
        )
        result["has_vba_macro"] = any(n.endswith("vbaProject.bin") for n in names)

        max_ratio = 0.0
        for info in infos:
            name = info.filename
            normalised = name.replace("\\", "/")
            if normalised.startswith("/") or re.match(r"^[A-Za-z]:", normalised) or ".." in normalised.split("/"):
                result["path_traversal_entries"].append(name)

            basename = name.rsplit("/", 1)[-1]
            ext = basename.rsplit(".", 1)[-1].lower() if "." in basename else ""
            if ext in _EXECUTABLE_EXTENSIONS:
                result["executables"].append(name)
            if ext in _ARCHIVE_EXTENSIONS:
                result["nested_archives"].append(name)

            if info.compress_size > 0:
                ratio = info.file_size / info.compress_size
                max_ratio = max(max_ratio, ratio)
                if ratio > MAX_ZIP_RATIO:
                    result["is_suspicious_bomb"] = True
            elif info.file_size > 0:
                result["is_suspicious_bomb"] = True
                max_ratio = float("inf")

        result["max_compression_ratio"] = round(max_ratio, 1) if max_ratio != float("inf") else None
        for key in ("executables", "path_traversal_entries", "nested_archives"):
            result[key] = result[key][:MAX_LISTED]
    return result


def analyze_static(family: str | None, data: bytes, filename: str = "") -> dict[str, Any] | None:
    """Dispatch to the format-specific analyser. None when no analyser applies."""
    if family == "pdf":
        return analyze_pdf(data)
    if family == "zip_container":
        zip_result = analyze_zip(data)
        if zip_result.get("is_ooxml") and zip_result.get("has_vba_macro"):
            zip_result["office"] = office.analyze_office(data, filename)
        return zip_result
    if family == "ole_compound":
        return office.analyze_office(data, filename)
    if family == "pe_executable":
        return pe.analyze_pe(data)
    if family in ("png", "jpeg"):
        return image_scan.analyze_image(data, family)
    if family == "dos_mz":
        return {"kind": "dos", "parse_error": "MZ header without a PE header", "indicators": []}
    return None


__all__ = ["analyze_static", "analyze_pdf", "analyze_zip"]
