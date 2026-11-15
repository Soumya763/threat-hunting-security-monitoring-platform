"""
Offline tests for the file/URL analysis building blocks.

No network calls are made: DNS is injected through the `resolver` argument
and file contents are synthetic bytes built in memory. No real malware is
used or needed.
"""

import io
import zipfile

import pytest

from app.analysis import filetype, hashing, scoring, ssrf, static


# ---------- hashing ----------

def test_hashes_match_known_vectors():
    result = hashing.hash_bytes(b"abc", max_bytes=1024)
    assert result["size_bytes"] == 3
    assert result["md5"] == "900150983cd24fb0d6963f7d28e17f72"
    assert result["sha1"] == "a9993e364706816aba3e25717850c26c9cd0d89d"
    assert result["sha256"] == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_hashing_rejects_oversized_stream():
    with pytest.raises(hashing.FileTooLargeError):
        hashing.hash_stream(io.BytesIO(b"x" * 2048), max_bytes=1024)


# ---------- magic-byte identification ----------

PE_HEAD = b"MZ" + b"\x00" * 58 + (0x40).to_bytes(4, "little") + b"PE\x00\x00" + b"\x00" * 64


def test_pe_detected_regardless_of_extension_and_mismatch_flagged():
    result = filetype.identify("invoice.pdf", PE_HEAD)
    assert result["detected_family"] == "pe_executable"
    assert result["extension_matches"] is False
    assert any("disguised" in w for w in result["warnings"])


def test_matching_pdf_is_not_flagged():
    result = filetype.identify("report.pdf", b"%PDF-1.7\n%...")
    assert result["detected_family"] == "pdf"
    assert result["extension_matches"] is True


def test_unsupported_extension_is_rejected_even_with_valid_magic():
    result = filetype.identify("script.sh", b"%PDF-1.4")
    assert result["extension_allowed"] is False


def test_unknown_bytes_yield_no_family():
    result = filetype.identify("data.png", b"not an image at all")
    assert result["detected_family"] is None
    assert result["extension_matches"] is None


# ---------- SSRF / URL policy ----------

def _public_resolver(host, port):
    return ["93.184.216.34"]


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://10.0.0.5/admin",
        "http://192.168.1.1/",
        "http://172.16.0.9/",
        "http://169.254.169.254/latest/meta-data/",
        "http://100.64.0.1/",
        "http://[::1]/",
        "http://[fe80::1]/",
        "http://[fc00::1]/",
        "http://0.0.0.0/",
        "http://224.0.0.1/",
        "http://localhost/",
        "http://printer.internal/",
        "ftp://example.com/file",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "http://user:pass@example.com/",
        "http://example.com:8080/",
        "http://example.com:22/",
        "",
        "http://exa mple.com/",
    ],
)
def test_validate_url_rejects_unsafe_inputs(url):
    with pytest.raises(ssrf.UnsafeURLError):
        ssrf.validate_url(url)


def test_validate_url_accepts_and_normalises_public_url():
    info = ssrf.validate_url("HTTPS://Example.COM.:443/path?q=1#frag")
    assert info["host"] == "example.com"
    assert info["port"] == 443
    assert info["url"] == "https://example.com/path?q=1"


def test_overlong_url_rejected():
    with pytest.raises(ssrf.UnsafeURLError):
        ssrf.validate_url("https://example.com/" + "a" * 3000)


def test_dns_name_resolving_to_private_address_is_blocked():
    with pytest.raises(ssrf.UnsafeURLError):
        ssrf.validate_and_resolve(
            "https://evil.example/", resolver=lambda h, p: ["93.184.216.34", "10.1.2.3"]
        )


def test_dns_name_resolving_to_loopback_is_blocked():
    with pytest.raises(ssrf.UnsafeURLError):
        ssrf.resolve_public_addresses("x.example", 443, resolver=lambda h, p: ["127.0.0.1"])


def test_ipv4_mapped_ipv6_private_address_is_blocked():
    assert not ssrf.is_public_ip("::ffff:10.0.0.1")
    assert not ssrf.is_public_ip("::ffff:127.0.0.1")


def test_unresolvable_host_is_blocked():
    def boom(host, port):
        raise OSError("nxdomain")

    with pytest.raises(ssrf.UnsafeURLError):
        ssrf.resolve_public_addresses("nope.example", 443, resolver=boom)


def test_public_resolution_returns_validated_addresses():
    info = ssrf.validate_and_resolve("https://example.com/", resolver=_public_resolver)
    assert info["addresses"] == ["93.184.216.34"]


# ---------- static inspection ----------

def test_pdf_javascript_and_open_action_detected():
    data = b"%PDF-1.4\n1 0 obj << /OpenAction 2 0 R /JS (app.alert(1)) >> endobj\n%%EOF"
    result = static.analyze_pdf(data)
    codes = {i["code"] for i in result["indicators"]}
    assert {"pdf_open_action", "pdf_js"} <= codes


def test_clean_pdf_has_no_indicators():
    result = static.analyze_pdf(b"%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\n%%EOF")
    assert result["indicators"] == []


def _zip_bytes(entries: dict[str, bytes], compress=zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=compress) as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
    return buf.getvalue()


def test_docx_like_zip_recognised_as_ooxml_with_macro_flag():
    data = _zip_bytes(
        {
            "[Content_Types].xml": b"<Types/>",
            "word/document.xml": b"<w/>",
            "word/vbaProject.bin": b"\x00" * 16,
        }
    )
    result = static.analyze_zip(data)
    assert result["is_ooxml"] is True
    assert result["has_vba_macro"] is True


def test_archive_with_executable_entry_is_listed():
    data = _zip_bytes({"readme.txt": b"hi", "setup/invoice.exe": b"MZ"})
    result = static.analyze_zip(data)
    assert result["executables"] == ["setup/invoice.exe"]


def test_path_traversal_entry_detected():
    data = _zip_bytes({"../../etc/cron.d/x": b"owned"})
    result = static.analyze_zip(data)
    assert result["path_traversal_entries"] == ["../../etc/cron.d/x"]


def test_zip_bomb_like_ratio_flagged():
    data = _zip_bytes({"big.txt": b"A" * 5_000_000})
    result = static.analyze_zip(data)
    assert result["is_suspicious_bomb"] is True


def test_corrupt_zip_is_reported_not_raised():
    result = static.analyze_zip(b"PK\x03\x04 truncated garbage")
    assert result["limit_exceeded"] == "invalid_zip"


# ---------- scoring ----------

def test_score_is_capped_and_every_point_is_explained():
    factors = [
        scoring.Factor("a", "A", 60, "reason a"),
        scoring.Factor("b", "B", 60, "reason b"),
    ]
    result = scoring.build_score(factors)
    assert result["score"] == 100
    assert result["raw_total"] == 120
    assert result["level"] == "critical"
    assert all(f["reason"] for f in result["factors"])


def test_band_thresholds():
    assert scoring.band_for(0) == "low"
    assert scoring.band_for(25) == "medium"
    assert scoring.band_for(50) == "high"
    assert scoring.band_for(75) == "critical"


def test_no_detection_never_reads_as_safe():
    ident = filetype.identify("doc.pdf", b"%PDF-1.4")
    report = scoring.build_file_report_score(ident, None, detection=(0, 70))
    assert "does not guarantee that it is safe" in report["caveats"][0]
    assert "safe" not in report["caveats"][0].replace("not guarantee that it is safe", "")


def test_known_malicious_hash_and_detections_contribute_factors():
    ident = filetype.identify("tool.exe", PE_HEAD)
    report = scoring.build_file_report_score(
        ident, None, known_malicious_hash=True, detection=(35, 70)
    )
    codes = {f["code"] for f in report["factors"]}
    assert {"known_malicious_hash", "engine_detections", "native_executable"} <= codes
    assert report["score"] >= 50
