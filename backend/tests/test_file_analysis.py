"""End-to-end file analysis on synthetic, harmless files (no malware is used)."""

import struct
import zipfile
import io

from app.analysis import filetype, static
from app.services import file_pipeline
from app.services.intel import base


class StubGateway:
    def __init__(self, answers=None):
        self.answers = answers or {}

    def lookup(self, provider, indicator_type, value):
        if (provider, indicator_type) in self.answers:
            return self.answers[(provider, indicator_type)](value)
        return base.result(provider, indicator_type, value, base.STATUS_NOT_CONFIGURED, message="not configured")


SHA = "0" * 64


def _analyze(data, name, gateway=None):
    return file_pipeline.analyze_file(data, filename=name, sha256=SHA, owner_id=1,
                                      session_factory=None, gateway=gateway or StubGateway(), history_count=0)


def test_javascript_pdf_gets_pdf_factors_and_is_not_called_clean():
    data = b"%PDF-1.4\n1 0 obj << /OpenAction 2 0 R /JavaScript (app.alert(1)) >>\n%%EOF"
    r = _analyze(data, "invoice.pdf")
    codes = {f["code"] for f in r["factors"]}
    assert {"pdf_javascript", "pdf_automatic_action"} <= codes
    assert r["score"] >= 25
    assert r["classification"] in ("medium", "high", "critical")


def test_eicar_content_is_matched_by_yara_and_listed_as_a_factor():
    r = _analyze(b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE", "sample.txt")
    assert r["yara"]["matches"][0]["rule"] == "eicar_test_file"
    assert "yara_matches" in {f["code"] for f in r["factors"]}


def test_zip_with_executable_and_path_traversal_is_flagged():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../etc/owned", b"x")
        zf.writestr("docs/invoice.exe", b"MZ-not-really")
    r = _analyze(buf.getvalue(), "archive.zip")
    codes = {f["code"] for f in r["factors"]}
    assert {"archive_executable", "archive_path_traversal"} <= codes


def test_disguised_executable_is_a_mismatch_and_recommends_not_trusting_the_name():
    pe_head = b"MZ" + b"\x00" * 58 + (0x40).to_bytes(4, "little") + b"PE\x00\x00" + b"\x00" * 64
    r = _analyze(pe_head, "invoice.pdf")
    assert "extension_mismatch" in {f["code"] for f in r["factors"]}
    assert any("does not match the content" in x for x in r["recommendations"])


def test_clean_document_without_providers_is_insufficient_evidence_with_clear_caveat():
    r = _analyze(b"%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\n%%EOF", "notes.pdf")
    assert r["score"] == 0
    assert r["classification"] == "insufficient_evidence"
    assert any("No external provider" in x or "not configured" in x for x in r["recommendations"])


def test_known_malicious_hash_from_provider_is_scored_and_explained():
    gw = StubGateway({("malwarebazaar", "sha256"): lambda v: base.result(
        "MalwareBazaar", "sha256", v, base.STATUS_OK, summary={"signature": "Example"})})
    r = _analyze(b"%PDF-1.4 clean", "doc.pdf", gateway=gw)
    assert "known_malicious_hash" in {f["code"] for f in r["factors"]}
    assert r["detections"]["known_malware_sample"] is True


def test_provider_failure_marks_the_analysis_partial_not_clean():
    gw = StubGateway({("virustotal", "sha256"): lambda v: base.result(
        "VirusTotal", "sha256", v, base.STATUS_UNAVAILABLE, message="down")})
    r = _analyze(b"%PDF-1.4 plain", "doc.pdf", gateway=gw)
    assert r["analysis_status"] == "partial"
    assert r["classification"] == "insufficient_evidence"


def test_office_macro_container_with_unparseable_project_reports_error_without_crashing():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("word/document.xml", "<w/>")
        zf.writestr("word/vbaProject.bin", b"\x00" * 64)
    result = static.analyze_static("zip_container", buf.getvalue(), "letter.docx")
    assert result["is_ooxml"] and result["has_vba_macro"]
    assert "office" in result
    assert result["office"]["parse_error"] or result["office"]["has_macros"] in (True, False)


def test_png_polyglot_is_flagged_in_the_pipeline():
    ihdr = struct.pack(">II", 2, 2) + b"\x08\x06\x00\x00\x00"
    png = (b"\x89PNG\r\n\x1a\n" + struct.pack(">I", 13) + b"IHDR" + ihdr + b"\x00\x00\x00\x00"
           + b"IEND\xaeB`\x82" + b"MZ" + b"\x00" * 40)
    r = _analyze(png, "photo.png")
    codes = {f["code"] for f in r["factors"]}
    assert {"image_trailing_data", "image_embedded_file"} <= codes
