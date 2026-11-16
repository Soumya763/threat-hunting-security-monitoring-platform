"""
PNG / JPEG structural checks. Detects bytes after the image end marker and
embedded file signatures (polyglot files: an image that also contains an
executable, PDF or archive). Dimensions are read for PNG only.
"""

import struct
from typing import Any

_EMBEDDED = {
    b"MZ": "Windows executable header",
    b"%PDF-": "PDF header",
    b"PK\x03\x04": "ZIP archive header",
}


def _embedded_signatures(data: bytes, start: int) -> list[str]:
    found = []
    for sig, label in _EMBEDDED.items():
        idx = data.find(sig, start)
        if idx != -1:
            found.append(f"{label} at offset {idx}")
    return found


def analyze_image(data: bytes, family: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "kind": "image",
        "format": family,
        "trailing_bytes": 0,
        "embedded_signatures": [],
        "width": None,
        "height": None,
        "parse_error": None,
    }
    if family == "png":
        if len(data) >= 24 and data[12:16] == b"IHDR":
            result["width"], result["height"] = struct.unpack(">II", data[16:24])
        end = data.rfind(b"IEND\xaeB`\x82")
        if end == -1:
            result["parse_error"] = "PNG end chunk not found"
            return result
        end += 8
    elif family == "jpeg":
        end = data.rfind(b"\xff\xd9")
        if end == -1:
            result["parse_error"] = "JPEG end marker not found"
            return result
        end += 2
    else:
        return result

    trailing = len(data) - end
    result["trailing_bytes"] = max(0, trailing)
    result["embedded_signatures"] = _embedded_signatures(data, 8)
    return result
