"""
Suspicious string extraction. Reads ASCII and UTF-16LE runs (common in
Windows binaries and Office files), then flags indicator categories.
Only the first STRING_SCAN_BYTES are scanned to bound time and memory.
"""

import re
from typing import Any

STRING_SCAN_BYTES = 8 * 1024 * 1024
MAX_SAMPLES = 20

_URL = re.compile(rb"https?://[\x21-\x7e]{4,300}")
_IPV4 = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RUN_KEY = re.compile(rb"(?i)\\?(software\\microsoft\\windows\\currentversion\\run(once)?)")

PATTERNS: dict[str, tuple[str, list[bytes]]] = {
    "powershell_usage": (
        "PowerShell invocation or encoded command option",
        [b"powershell", b"-encodedcommand", b"-enc ", b"Invoke-Expression", b"IEX("],
    ),
    "download_cradle": (
        "Network download helper (possible payload retrieval)",
        [b"DownloadString", b"DownloadFile", b"Net.WebClient", b"Invoke-WebRequest", b"bitsadmin"],
    ),
    "shell_execution": (
        "Command shell or script host execution",
        [b"cmd.exe", b"WScript.Shell", b"rundll32", b"regsvr32", b"mshta"],
    ),
}


def _runs(data: bytes) -> list[bytes]:
    ascii_runs = re.findall(rb"[\x20-\x7e]{6,}", data)
    wide_runs = []
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){6,}", data):
        wide_runs.append(m.group(0).replace(b"\x00", b""))
    return ascii_runs + wide_runs


def scan_strings(data: bytes) -> dict[str, Any]:
    window = data[:STRING_SCAN_BYTES]
    runs = _runs(window)
    blob = b"\n".join(runs)
    lower = blob.lower()

    categories = []
    for key, (description, needles) in PATTERNS.items():
        hits = sorted({n.decode("ascii", "replace") for n in needles if n.lower() in lower})
        if hits:
            categories.append({"category": key, "description": description, "matched": hits})

    urls = sorted({u.decode("ascii", "replace") for u in _URL.findall(blob)})[:MAX_SAMPLES]
    ips = sorted({i.decode("ascii", "replace") for i in _IPV4.findall(blob)})[:MAX_SAMPLES]
    run_keys = bool(_RUN_KEY.search(blob))
    if run_keys:
        categories.append({
            "category": "autorun_persistence",
            "description": "References a Run registry key (common persistence location)",
            "matched": ["CurrentVersion\\Run"],
        })

    return {
        "scanned_bytes": len(window),
        "truncated": len(data) > STRING_SCAN_BYTES,
        "string_count": len(runs),
        "categories": categories,
        "urls": urls,
        "ipv4": ips,
    }
