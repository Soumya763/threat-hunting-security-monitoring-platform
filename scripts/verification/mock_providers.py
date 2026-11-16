"""MOCK provider server for end-to-end tests of the provider client code. It is NOT a real
provider: it returns canned responses so the HTTP client, mapping, caching and error paths can
be exercised. Every request is logged to mock_requests.jsonl."""
import json, time, hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit, unquote

KNOWN_SHA = None  # set from argv
SLOW_SHA = None   # set from argv: responses are delayed past the client timeout
SLOW_SHA = None   # set from argv: responses are delayed past the client timeout
LOG = "mock_requests.jsonl"
def log(entry):
    with open(LOG, "a") as f: f.write(json.dumps(entry) + "\n")

class H(BaseHTTPRequestHandler):
    def _send(self, code, body=None):
        data = json.dumps(body or {}).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
    def _body(self):
        n = int(self.headers.get("Content-Length") or 0); return self.rfile.read(n).decode(errors="replace") if n else ""
    def do_GET(self):
        path = unquote(urlsplit(self.path).path); log({"m": "GET", "p": path, "h": {k: v for k, v in self.headers.items() if k.lower() in ("x-apikey", "x-otx-api-key", "api-key")}})
        if path.startswith("/vt/api/v3/files/"):
            h = path.rsplit("/", 1)[1]
            if h == KNOWN_SHA:
                return self._send(200, {"data": {"attributes": {"last_analysis_stats": {"malicious": 6, "suspicious": 1, "undetected": 55, "harmless": 8, "timeout": 0},
                       "popular_threat_classification": {"suggested_threat_label": "trojan.mock/synthetic"}, "names": ["suspicious-indicators.pdf"]}}})
            if h == SLOW_SHA: time.sleep(25); return self._send(200, {})
            return self._send(404, {"error": {"code": "NotFoundError"}})
        if path.startswith("/vt/api/v3/ip_addresses/"):
            return self._send(429, {"error": {"code": "QuotaExceededError"}})
        if path.startswith("/vt/api/v3/domains/"):
            return self._send(200, {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0, "undetected": 70, "harmless": 4}, "categories": {"mock": "synthetic"}}}})
        if path.startswith("/vt/api/v3/urls/"):
            return self._send(404, {})
        if path.startswith("/otx/api/v1/indicators/"):
            if "/IPv4/" in path or "/domain/" in path:
                return self._send(200, {"pulse_info": {"count": 2, "pulses": [{"name": "Mock campaign", "modified": "2026-11-01", "tags": ["synthetic"]}]}, "validation": []})
            return self._send(404, {})
        if path.startswith("/us/api/v1/search/"):
            return self._send(200, {"results": [
                {"verdicts": {"overall": {"malicious": True, "score": 90}}, "page": {"url": "https://example.com/mock-bad"}, "task": {"time": "2026-11-10T00:00:00Z", "reportURL": "https://urlscan.io/result/mock/"}},
                {"verdicts": {"overall": {"malicious": False}}, "page": {"url": "https://example.com/"}, "task": {"time": "2026-11-11T00:00:00Z"}}]})
        self._send(404, {})
    def do_POST(self):
        body = self._body(); path = urlsplit(self.path).path
        log({"m": "POST", "p": path, "body": body[:300], "h": {k: v for k, v in self.headers.items() if k.lower() in ("auth-key", "api-key", "x-apikey")}})
        if path == "/mb/api/v1/":
            if "illegal" in self.headers.get("Auth-Key", "") or "bad" in self.headers.get("Auth-Key", ""):
                return self._send(200, {"query_status": "illegal_auth_key"})
            if KNOWN_SHA and KNOWN_SHA in body:
                return self._send(200, {"query_status": "ok", "data": [{"signature": "MockFamily", "file_type": "pdf", "tags": ["synthetic"], "first_seen": "2026-10-01", "last_seen": "2026-11-01"}]})
            return self._send(200, {"query_status": "hash_not_found"})
        if path == "/vt/api/v3/files":
            return self._send(200, {"data": {"type": "analysis", "id": "mock-analysis-id-0001"}})
        if path == "/vt/api/v3/files":
            return self._send(200, {"data": {"type": "analysis", "id": "mock-analysis-id-0001"}})
        if path == "/us/api/v1/scan/":
            return self._send(200, {"uuid": "11111111-2222-3333-4444-555555555555", "result": "https://urlscan.io/result/mock/"})
        self._send(404, {})
    def log_message(self, *a): pass

if __name__ == "__main__":
    import sys
    KNOWN_SHA = sys.argv[1]
    SLOW_SHA = sys.argv[2]
    SLOW_SHA = sys.argv[2]
    HTTPServer(("0.0.0.0", 8099), H).serve_forever()
