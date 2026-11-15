"""
Windows PE (EXE/DLL) static analysis with pefile. Parses headers only:
the file is never loaded, mapped or executed.
"""

import datetime as _dt
from typing import Any

import pefile

# High-signal imports often used for process injection, downloading payloads,
# anti-analysis, or persistence. Presence is a triage indicator, not proof.
DANGEROUS_IMPORTS: dict[str, str] = {
    "VirtualAllocEx": "allocates memory in another process (injection)",
    "WriteProcessMemory": "writes into another process's memory (injection)",
    "CreateRemoteThread": "starts a thread in another process (injection)",
    "NtUnmapViewOfSection": "unmaps a section, often used in process hollowing",
    "SetWindowsHookExA": "installs a system-wide hook (possible keylogging)",
    "SetWindowsHookExW": "installs a system-wide hook (possible keylogging)",
    "URLDownloadToFileA": "downloads content from a URL",
    "URLDownloadToFileW": "downloads content from a URL",
    "WinExec": "launches a program",
    "ShellExecuteA": "launches a program or URL",
    "ShellExecuteW": "launches a program or URL",
    "IsDebuggerPresent": "checks for a debugger (anti-analysis)",
    "CheckRemoteDebuggerPresent": "checks for a debugger (anti-analysis)",
    "InternetOpenUrlA": "opens a network URL",
    "InternetOpenUrlW": "opens a network URL",
}

PACKER_SECTION_NAMES = ("upx", "themida", ".vmp", "aspack", "mpress", ".petite")
HIGH_ENTROPY = 7.2


def _entropy(section) -> float:
    try:
        return round(section.get_entropy(), 3)
    except Exception:  # pragma: no cover - defensive, pefile quirk
        return 0.0


def analyze_pe(data: bytes) -> dict[str, Any]:
    try:
        pe = pefile.PE(data=data, fast_load=False)
    except pefile.PEFormatError as exc:
        return {"kind": "pe", "parse_error": str(exc)[:200], "indicators": []}
    except Exception as exc:  # malformed input must never crash the pipeline
        return {"kind": "pe", "parse_error": f"unexpected parse error: {type(exc).__name__}", "indicators": []}

    try:
        result: dict[str, Any] = {"kind": "pe", "parse_error": None}
        fh = pe.FILE_HEADER
        result["machine"] = pefile.MACHINE_TYPE.get(fh.Machine, hex(fh.Machine))
        result["is_dll"] = bool(fh.Characteristics & 0x2000)
        result["subsystem"] = pefile.SUBSYSTEM_TYPE.get(pe.OPTIONAL_HEADER.Subsystem, str(pe.OPTIONAL_HEADER.Subsystem))

        ts = fh.TimeDateStamp
        if ts:
            try:
                compiled = _dt.datetime.fromtimestamp(ts, _dt.timezone.utc)
                result["compile_time"] = compiled.isoformat()
                result["compile_time_in_future"] = compiled > _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=1)
            except (OverflowError, OSError, ValueError):
                result["compile_time"] = None
        else:
            result["compile_time"] = None

        sig_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4] if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 4 else None
        result["has_embedded_signature"] = bool(sig_dir and sig_dir.Size > 0)

        sections = []
        packed_hints = []
        for s in pe.sections:
            name = s.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
            ent = _entropy(s)
            executable = bool(s.Characteristics & 0x20000000)
            sections.append({
                "name": name,
                "raw_size": s.SizeOfRawData,
                "virtual_size": s.Misc_VirtualSize,
                "entropy": ent,
                "executable": executable,
            })
            if executable and ent >= HIGH_ENTROPY:
                packed_hints.append(f"section {name or '<unnamed>'} is executable with entropy {ent}")
            if any(p in name.lower() for p in PACKER_SECTION_NAMES):
                packed_hints.append(f"section name '{name}' is typical of a packer")
        result["sections"] = sections[:30]
        result["packing_hints"] = packed_hints

        imports: list[str] = []
        dangerous: list[dict[str, str]] = []
        dlls: list[str] = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode("utf-8", errors="replace") if entry.dll else ""
                dlls.append(dll)
                for imp in entry.imports:
                    if not imp.name:
                        continue
                    fn = imp.name.decode("utf-8", errors="replace")
                    imports.append(f"{dll}!{fn}")
                    if fn in DANGEROUS_IMPORTS:
                        dangerous.append({"function": fn, "dll": dll, "meaning": DANGEROUS_IMPORTS[fn]})
        result["imported_dlls"] = dlls[:100]
        result["import_count"] = len(imports)
        result["suspicious_imports"] = dangerous
        try:
            result["imphash"] = pe.get_imphash()
        except Exception:
            result["imphash"] = None

        overlay_offset = pe.get_overlay_data_start_offset()
        overlay_size = len(data) - overlay_offset if overlay_offset is not None else 0
        result["overlay_bytes"] = max(0, overlay_size)
        result["indicators"] = []
        return result
    finally:
        pe.close()


def high_entropy_packed(pe_result: dict[str, Any]) -> bool:
    return bool(pe_result.get("packing_hints"))


__all__ = ["analyze_pe", "DANGEROUS_IMPORTS", "high_entropy_packed"]
