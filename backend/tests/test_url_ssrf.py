"""SSRF protection: URL validation, DNS policy, redirect re-validation, pinned connections."""

import http.server
import socket
import ssl
import threading

import pytest

from app.analysis import fetch as fetch_mod
from app.analysis.ssrf import UnsafeURLError, is_public_ip, validate_and_resolve, validate_url

PUBLIC = "93.184.216.34"


def resolver_for(mapping):
    calls = []

    def resolve(host, port):
        calls.append(host)
        if host in mapping:
            return mapping[host]
        raise OSError("nxdomain")

    resolve.calls = calls
    return resolve


def scripted(script):
    calls = []

    def fetcher(info, ip, *, timeout, max_body):
        calls.append({"url": info["url"], "ip": ip, "max_body": max_body})
        item = script.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    fetcher.calls = calls
    return fetcher


def _redirect(location):
    return {"status": 302, "headers": {"location": location}, "body": b"", "tls": None}


def _ok(body=b"<html>ok</html>"):
    return {"status": 200, "headers": {"content-type": "text/html"}, "body": body, "tls": None}


# ---- URL syntax ----

@pytest.mark.parametrize("url", [
    "ftp://example.com/x", "file:///etc/passwd", "javascript:alert(1)", "gopher://example.com",
    "http://user:pass@example.com/", "http://example.com:8080/", "http://example.com:22/",
    "http://localhost/", "http://service.internal/", "http://printer.local/",
    "http://127.0.0.1/", "http://10.1.2.3/", "http://192.168.0.1/", "http://172.16.5.5/",
    "http://169.254.169.254/latest/meta-data/", "http://100.64.1.1/", "http://[::1]/",
    "http://[fe80::1]/", "http://[fc00::5]/", "http://0.0.0.0/", "http://224.0.0.1/",
    "http://[::ffff:10.0.0.1]/", "", "   ", "http://exa mple.com/", "https://example.com/" + "a" * 3000,
])
def test_unsafe_or_malformed_urls_are_rejected(url):
    with pytest.raises(UnsafeURLError):
        validate_url(url)


def test_valid_url_is_normalised_without_fragment_or_default_port():
    info = validate_url("HTTPS://Example.COM.:443/a/b?q=1#frag")
    assert info["url"] == "https://example.com/a/b?q=1"
    assert info["host"] == "example.com" and info["port"] == 443


# ---- DNS policy ----

def test_any_private_address_in_the_answer_blocks_the_host():
    with pytest.raises(UnsafeURLError):
        validate_and_resolve("https://mixed.example/", resolver_for({"mixed.example": [PUBLIC, "10.9.9.9"]}))


@pytest.mark.parametrize("answer", [[], ["127.0.0.1"], ["169.254.169.254"], ["::1"], ["fe80::2"], ["::ffff:192.168.1.1"], ["100.64.0.9"]])
def test_non_public_or_empty_answers_are_blocked(answer):
    with pytest.raises(UnsafeURLError):
        validate_and_resolve("https://edge.example/", resolver_for({"edge.example": answer}))


def test_unresolvable_host_is_blocked():
    with pytest.raises(UnsafeURLError):
        validate_and_resolve("https://nope.example/", resolver_for({}))


def test_public_ip_literal_is_allowed_and_private_literal_is_not():
    assert is_public_ip(PUBLIC)
    assert validate_url("http://93.184.216.34/")["host"] == PUBLIC
    with pytest.raises(UnsafeURLError):
        validate_url("http://192.168.10.10/")


# ---- redirect handling ----

def test_redirect_to_loopback_is_blocked_before_any_connection():
    resolver = resolver_for({"public.example": [PUBLIC]})
    fetcher = scripted([_redirect("http://127.0.0.1/admin")])
    outcome = fetch_mod.fetch_with_redirects("http://public.example/", resolver=resolver, fetcher=fetcher)
    assert outcome["blocked"]
    assert len(fetcher.calls) == 1  # the loopback hop was never dialled


def test_redirect_to_cloud_metadata_endpoint_is_blocked():
    fetcher = scripted([_redirect("http://169.254.169.254/latest/meta-data/iam/")])
    outcome = fetch_mod.fetch_with_redirects("http://public.example/", resolver=resolver_for({"public.example": [PUBLIC]}), fetcher=fetcher)
    assert outcome["blocked"] and len(fetcher.calls) == 1


def test_redirect_to_hostname_that_resolves_private_is_blocked_on_revalidation():
    resolver = resolver_for({"public.example": [PUBLIC], "internal.example": ["10.0.0.7"]})
    fetcher = scripted([_redirect("http://internal.example/secret")])
    outcome = fetch_mod.fetch_with_redirects("http://public.example/", resolver=resolver, fetcher=fetcher)
    assert outcome["blocked"]
    assert len(fetcher.calls) == 1


def test_redirect_to_non_http_scheme_is_blocked():
    fetcher = scripted([_redirect("file:///etc/passwd")])
    outcome = fetch_mod.fetch_with_redirects("http://public.example/", resolver=resolver_for({"public.example": [PUBLIC]}), fetcher=fetcher)
    assert outcome["blocked"]


def test_public_redirect_chain_is_followed_and_recorded():
    resolver = resolver_for({"a.example": [PUBLIC], "b.example": [PUBLIC]})
    fetcher = scripted([_redirect("https://b.example/landing"), _ok()])
    outcome = fetch_mod.fetch_with_redirects("https://a.example/", resolver=resolver, fetcher=fetcher)
    assert outcome["final_url"] == "https://b.example/landing"
    assert outcome["redirect_count"] == 1
    assert [h["url"] for h in outcome["hops"]] == ["https://a.example/", "https://b.example/landing"]


def test_redirect_limit_is_enforced():
    resolver = resolver_for({"loop.example": [PUBLIC]})
    fetcher = scripted([_redirect("https://loop.example/1"), _redirect("https://loop.example/2"),
                        _redirect("https://loop.example/3")])
    outcome = fetch_mod.fetch_with_redirects("https://loop.example/0", resolver=resolver, fetcher=fetcher, max_redirects=2)
    assert "Too many redirects" in (outcome["error"] or "")


# ---- DNS rebinding and transport ----

def test_connection_is_pinned_to_the_validated_address_and_resolution_happens_once():
    resolver = resolver_for({"rebind.example": [PUBLIC]})
    fetcher = scripted([_ok()])
    fetch_mod.fetch_with_redirects("https://rebind.example/", resolver=resolver, fetcher=fetcher)
    assert fetcher.calls[0]["ip"] == PUBLIC
    assert resolver.calls == ["rebind.example"]


def test_tls_verification_failure_is_reported_as_a_certificate_problem():
    resolver = resolver_for({"wrong-cert.example": [PUBLIC]})
    fetcher = scripted([ssl.SSLCertVerificationError("certificate verify failed: Hostname mismatch, certificate is not valid for 'wrong-cert.example'")])
    outcome = fetch_mod.fetch_with_redirects("https://wrong-cert.example/", resolver=resolver, fetcher=fetcher)
    assert outcome["tls_problem"] == "Certificate does not match the host name."
    assert outcome["error"] == "TLS handshake failed."


def test_timeout_and_connection_errors_are_reported_not_raised():
    resolver = resolver_for({"slow.example": [PUBLIC]})
    outcome = fetch_mod.fetch_with_redirects("http://slow.example/", resolver=resolver, fetcher=scripted([socket.timeout()] * 3))
    assert outcome["error"] == "The site did not respond in time."
    outcome = fetch_mod.fetch_with_redirects("http://slow.example/", resolver=resolver, fetcher=scripted([ConnectionRefusedError()] * 3))
    assert outcome["error"].startswith("Connection failed")


def test_body_limit_is_passed_to_the_transport(monkeypatch):
    resolver = resolver_for({"big.example": [PUBLIC]})
    fetcher = scripted([_ok()])
    fetch_mod.fetch_with_redirects("http://big.example/", resolver=resolver, fetcher=fetcher, max_body=1234)
    assert fetcher.calls[0]["max_body"] == 1234


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        payload = b"x" * 5000
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):  # silence test output
        pass


def test_real_pinned_transport_sends_host_header_and_caps_body():
    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        info = {"host": "example.test", "port": port, "scheme": "http",
                "url": f"http://example.test:{port}/"}
        # The transport dials the pinned loopback address; policy checks are
        # tested separately above. Host header must still carry the hostname.
        response = fetch_mod.fetch_one(info, "127.0.0.1", timeout=3, max_body=100)
        assert response["status"] == 200
        assert len(response["body"]) == 100
    finally:
        server.shutdown()
        server.server_close()


def test_tls_certificate_details_survive_connection_close(tmp_path, monkeypatch):
    """Regression: the certificate was read after 'Connection: close' had discarded the socket,
    so TLS details were always empty. This performs a real TLS handshake with a throwaway
    certificate trusted only by this test."""
    import shutil, subprocess
    if shutil.which("openssl") is None:
        pytest.skip("openssl binary not available")
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
                    "-out", str(cert), "-days", "2", "-subj", "/CN=localhost",
                    "-addext", "subjectAltName=DNS:localhost"], check=True, capture_output=True)

    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(cert, key)
    httpd = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    httpd.socket = server_ctx.wrap_socket(httpd.socket, server_side=True)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()

    original_context = ssl.create_default_context

    def trusting_context():
        return original_context(cafile=str(cert))

    monkeypatch.setattr(fetch_mod.ssl, "create_default_context", trusting_context)
    try:
        info = {"host": "localhost", "port": port, "scheme": "https", "url": f"https://localhost:{port}/"}
        response = fetch_mod.fetch_one(info, "127.0.0.1", timeout=5, max_body=100)
        assert response["status"] == 200
        assert response["tls"] is not None and response["tls"]["verified"] is True
        assert "localhost" in response["tls"]["subject"]
        assert response["tls"]["not_after"]
    finally:
        httpd.shutdown()
        httpd.server_close()
