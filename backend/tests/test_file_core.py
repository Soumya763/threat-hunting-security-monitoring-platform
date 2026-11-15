"""File-analysis core: hashing, magic-byte identification, static parsers, YARA, scoring."""

import io
import struct
import zipfile

import pytest

from app.analysis import filetype, hashing, pe, scoring, static, strings_scan, yara_scan
from app.analysis import image_scan


def test_hashes_match_known_vectors():
    r = hashing.hash_bytes(b"abc", max_bytes=1024)
    assert r["size_bytes"] == 3
    assert r["md5"] == "900150983cd24fb0d6963f7d28e17f72"
    assert r["sha1"] == "a9993e364706816aba3e25717850c26c9cd0d89d"
    assert r["sha256"] == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_hash_stream_rejects_oversized_input():
    with pytest.raises(hashing.FileTooLargeError):
        hashing.hash_stream(io.BytesIO(b"x" * 2048), max_bytes=1024)


PE_HEAD = b"MZ" + b"\x00" * 58 + (0x40).to_bytes(4, "little") + b"PE\x00\x00" + b"\x00" * 64


def test_pe_content_with_pdf_extension_is_a_mismatch():
    result = filetype.identify("invoice.pdf", PE_HEAD)
    assert result["detected_family"] == "pe_executable"
    assert result["extension_matches"] is False


def test_matching_pdf_has_no_mismatch():
    result = filetype.identify("report.pdf", b"%PDF-1.7\n")
    assert result["detected_family"] == "pdf" and result["extension_matches"] is True


def test_unknown_bytes_yield_no_family_and_unsupported_extension_is_flagged():
    assert filetype.identify("data.png", b"plain text")["detected_family"] is None
    assert filetype.identify("script.sh", b"%PDF-1.4")["extension_allowed"] is False


def test_pdf_javascript_and_auto_action_detected():
    data = b"%PDF-1.4\n1 0 obj << /OpenAction 2 0 R /JS (app.alert(1)) >> endobj\n%%EOF"
    codes = {i["code"] for i in static.analyze_pdf(data)["indicators"]}
    assert {"pdf_open_action", "pdf_js"} <= codes


def test_clean_pdf_has_no_indicators():
    assert static.analyze_pdf(b"%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\n%%EOF")["indicators"] == []


def _zip(entries, compress=zipfile.ZIP_DEFLATED):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=compress) as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
    return buf.getvalue()


def test_archive_with_executable_and_traversal_entries():
    data = _zip({"readme.txt": b"hi", "setup/invoice.exe": b"MZ", "../../etc/cron.d/x": b"owned"})
    result = static.analyze_zip(data)
    assert result["executables"] == ["setup/invoice.exe"]
    assert result["path_traversal_entries"] == ["../../etc/cron.d/x"]


def test_docx_like_archive_with_macro_project_is_recognised():
    data = _zip({"[Content_Types].xml": b"<Types/>", "word/document.xml": b"<w/>",
                 "word/vbaProject.bin": b"\x00" * 16})
    result = static.analyze_zip(data)
    assert result["is_ooxml"] and result["has_vba_macro"]


def test_zip_bomb_like_ratio_is_flagged_and_corrupt_zip_reported():
    assert static.analyze_zip(_zip({"big.txt": b"A" * 5_000_000}))["is_suspicious_bomb"] is True
    assert static.analyze_zip(b"PK\x03\x04 truncated")["limit_exceeded"] == "invalid_zip"


def test_malformed_pe_is_reported_not_raised():
    assert pe.analyze_pe(b"MZ" + b"\x00" * 100)["parse_error"]
    assert static.analyze_static("dos_mz", b"MZ" + b"\x00" * 100)["kind"] == "dos"


def _png_with_trailer(trailer: bytes) -> bytes:
    ihdr = struct.pack(">II", 4, 4) + b"\x08\x06\x00\x00\x00"
    body = b"\x89PNG\r\n\x1a\n" + struct.pack(">I", 13) + b"IHDR" + ihdr + b"\x00\x00\x00\x00"
    return body + b"IDAT\x00\x00\x00\x00" + b"IEND\xaeB`\x82" + trailer


def test_png_with_appended_archive_is_flagged():
    data = _png_with_trailer(b"PK\x03\x04" + b"\x00" * 20)
    result = image_scan.analyze_image(data, "png")
    assert result["trailing_bytes"] > 0
    assert any("ZIP" in s for s in result["embedded_signatures"])
    assert (result["width"], result["height"]) == (4, 4)


def test_clean_png_has_no_trailing_data():
    assert image_scan.analyze_image(_png_with_trailer(b""), "png")["trailing_bytes"] == 0


def test_eicar_test_string_matches_yara_rule_and_is_marked_low():
    r = yara_scan.scan_bytes(b"X EICAR-STANDARD-ANTIVIRUS-TEST-FILE X")
    assert r["status"] == "scanned"
    assert [m["rule"] for m in r["matches"]] == ["eicar_test_file"]
    assert r["matches"][0]["severity"] == "low"


def test_encoded_powershell_yara_match():
    r = yara_scan.scan_bytes(b"powershell.exe -enc SQBFAFgA")
    assert "encoded_powershell_command" in [m["rule"] for m in r["matches"]]


def test_suspicious_strings_detected_in_ascii_and_utf16():
    wide = "powershell -enc AAAA".encode("utf-16-le")
    result = strings_scan.scan_strings(b"http://203.0.113.50/payload.bin " + wide)
    cats = {c["category"] for c in result["categories"]}
    assert {"powershell_usage"} <= cats
    assert any(u.startswith("http://203.0.113.50") for u in result["urls"])


def test_scoring_is_capped_and_explained():
    factors = [scoring.Factor("a", "A", 60, "ra"), scoring.Factor("b", "B", 60, "rb")]
    r = scoring.build_score(factors, consulted_sources=1, local_complete=True)
    assert r["score"] == 100 and r["raw_total"] == 120 and r["level"] == "critical"
    assert all(f["reason"] for f in r["factors"])


@pytest.mark.parametrize("score,expected", [(0, "low"), (24, "low"), (25, "medium"), (50, "high"), (75, "critical")])
def test_band_thresholds(score, expected):
    assert scoring.band_for_score(score) == expected


def test_classification_distinguishes_clean_from_insufficient_evidence():
    assert scoring.classify(0, consulted_sources=2, local_complete=True) == "clean"
    assert scoring.classify(0, consulted_sources=0, local_complete=True) == "insufficient_evidence"
    assert scoring.classify(0, consulted_sources=2, local_complete=False) == "insufficient_evidence"


def test_clean_result_still_carries_the_no_guarantee_caveat():
    r = scoring.build_score([], consulted_sources=1, local_complete=True)
    assert r["level"] == "clean"
    assert "does not guarantee that it is safe" in r["caveats"][0]


def test_known_malicious_hash_and_detections_score_high():
    ident = filetype.identify("tool.exe", PE_HEAD)
    r = scoring.build_file_score(ident, None, None, None, malwarebazaar_hit=True,
                                 detections=[("VirusTotal", 35, 70)], otx_pulses=0,
                                 consulted_sources=2, local_complete=True)
    codes = {f["code"] for f in r["factors"]}
    assert {"known_malicious_hash", "engine_detections", "native_executable"} <= codes
    assert r["score"] >= 50


def test_macro_container_is_scored_even_when_vba_parser_cannot_read_it():
    """Regression: a DOCX with a vbaProject.bin the parser cannot read scored 0 before."""
    from app.analysis import static as static_mod
    data = _zip({"[Content_Types].xml": b"<Types/>", "word/document.xml": b"<w/>",
                 "word/vbaProject.bin": b"\x00" * 64})
    static_result = static_mod.analyze_static("zip_container", data, "macro-test.docx")
    assert static_result["has_vba_macro"] is True
    ident = filetype.identify("macro-test.docx", data[:8192])
    r = scoring.build_file_score(ident, static_result, None, None, malwarebazaar_hit=False,
                                 detections=[], otx_pulses=0, consulted_sources=0, local_complete=True)
    codes = [f["code"] for f in r["factors"]]
    assert codes.count("office_macro_present") == 1
    assert r["score"] >= 10


def test_macro_factor_is_not_double_counted_when_office_parser_reads_macros():
    static_result = {"kind": "zip", "is_ooxml": True, "has_vba_macro": True, "executables": [],
                     "path_traversal_entries": [], "nested_archives": [], "limit_exceeded": None,
                     "is_suspicious_bomb": False,
                     "office": {"kind": "office", "has_macros": True, "auto_exec_keywords": ["AutoOpen"],
                                "suspicious_keywords": [], "macro_module_count": 1}}
    ident = {"detected_family": "zip_container", "extension_matches": True, "warnings": []}
    factors = scoring.file_factors(ident, static_result, None, None)
    codes = [f.code for f in factors]
    assert codes.count("office_macro_present") == 1
    assert "office_auto_exec" in codes
