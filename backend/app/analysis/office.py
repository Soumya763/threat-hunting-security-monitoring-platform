"""
Office document macro and VBA indicator analysis with oletools (olevba).

Works on OLE (DOC, XLS, PPT) and OOXML (DOCX, XLSX, PPTX, which are ZIP
containers with a vbaProject.bin). Only VBA source is parsed; no macro is run.
Embedded OLE objects are not extracted in this version (see limitations).
"""

from typing import Any

from oletools.olevba import VBA_Parser

MAX_LISTED = 50


def analyze_office(data: bytes, filename: str = "document") -> dict[str, Any]:
    result: dict[str, Any] = {
        "kind": "office",
        "parse_error": None,
        "has_macros": False,
        "auto_exec_keywords": [],
        "suspicious_keywords": [],
        "iocs": [],
        "macro_module_count": 0,
        "limitations": [
            "Embedded OLE objects are not extracted; only VBA-level indicators are checked.",
        ],
    }
    try:
        vba = VBA_Parser(filename or "document", data=data)
    except Exception as exc:
        result["parse_error"] = f"not a readable Office document ({type(exc).__name__})"
        return result

    try:
        result["has_macros"] = bool(vba.detect_vba_macros())
        if not result["has_macros"]:
            return result

        modules = 0
        for _ in vba.extract_macros():
            modules += 1
        result["macro_module_count"] = modules

        auto, susp, iocs = set(), set(), []
        for kw_type, keyword, _description in vba.analyze_macros():
            if kw_type == "AutoExec":
                auto.add(str(keyword))
            elif kw_type == "Suspicious":
                susp.add(str(keyword))
            elif kw_type == "IOC" and len(iocs) < MAX_LISTED:
                iocs.append(str(keyword))
        result["auto_exec_keywords"] = sorted(auto)[:MAX_LISTED]
        result["suspicious_keywords"] = sorted(susp)[:MAX_LISTED]
        result["iocs"] = iocs
    except Exception as exc:
        result["parse_error"] = f"macro analysis failed ({type(exc).__name__})"
    finally:
        try:
            vba.close()
        except Exception:
            pass
    return result
