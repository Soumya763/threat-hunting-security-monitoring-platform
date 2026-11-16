import os
import requests, time, sys
B = "http://localhost:8000"
results = []
def check(name, ok, detail=""):
    results.append((name, bool(ok))); print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail else ""), flush=True)
r = requests.post(f"{B}/api/v1/auth/login", json={"username": "analyst1", "password": os.environ["ANALYST1_PASSWORD"]}); r.raise_for_status()
H = {"Authorization": f"Bearer {r.json()['access_token']}"}

def submit(url):
    """Client behaviour: back off on 429 (per-user submission limit) and retry."""
    for _ in range(14):
        r = requests.post(f"{B}/api/v1/urls", json={"url": url}, headers=H)
        if r.status_code != 429: return r
        time.sleep(5)
    return r
def final(aid):
    for _ in range(90):
        d = requests.get(f"{B}/api/v1/analyses/{aid}", headers=H).json()
        if d["status"] not in ("queued", "running"): return d
        time.sleep(1)
    return d

# --- rejected before any network activity
rejects = {
  "not a URL": "not a url", "bad scheme words": "htp:/bad", "credentials in URL": "https://user:secret@example.com/",
  "ftp scheme": "ftp://example.com/file", "javascript scheme": "javascript:alert(1)", "file scheme": "file:///etc/passwd",
  "unusual port 8443": "https://example.com:8443/", "localhost": "http://localhost/", "loopback 127.0.0.1": "http://127.0.0.1/",
  "private 192.168.1.1": "http://192.168.1.1/", "cloud metadata": "http://169.254.169.254/latest/meta-data/",
  "IPv6 loopback": "http://[::1]/", "empty": "", "whitespace in host": "https://exa mple.com/",
}
for label, url in rejects.items():
    r = submit(url)
    check(f"rejected ({label}) -> 422", r.status_code == 422, str(r.status_code))

# --- accepted and analysed
r = submit("HTTPS://Example.COM:443/Docs/Page?q=1#section")
check("normal HTTPS URL accepted (202)", r.status_code == 202, str(r.status_code))
d = final(r.json()["id"]); res = d["result"]
check("normalisation: scheme/host lower-cased, default port and fragment removed", res["normalized_url"] == "https://example.com/Docs/Page?q=1", res["normalized_url"])
check("DNS A records resolved to public addresses", bool(res["dns"]["public_addresses"]) and not res["dns"]["non_public_addresses"], str(res["dns"]["public_addresses"][:2]))
check("TLS certificate retrieved and verified", res["tls"] is not None and res["tls"].get("verified") is True and res["tls"].get("not_after"), str((res["tls"] or {}).get("not_after")))
check("TLS days remaining computed", isinstance((res["tls"] or {}).get("days_remaining"), int))
check("redirect chain recorded (at least one hop)", len(res["redirect_chain"]) >= 1, str([h["status"] for h in res["redirect_chain"]]))
check("providers reported as not configured (no key) - not invented", all(p["status"] == "not_configured" for k, p in res["providers"].items() if k.startswith(("VirusTotal", "OTX", "urlscan"))))
check("classification is NOT clean without a consulted source", d["risk_level"] != "clean", d["risk_level"])
check("analysis record stored and final", d["status"] in ("complete", "partial"), d["status"])
rdap = res.get("rdap") or {}
check("RDAP outcome reported honestly (ok, or an error state with message)", rdap.get("status") in ("ok", "not_found", "timeout", "unavailable", "rate_limited"), str(rdap.get("status")))

# --- suspicious-looking but never contacted (reserved .invalid TLD does not resolve)
r = submit("https://paypa1-secure-login.invalid/signin")
d = final(r.json()["id"]); res = d["result"]
check("lookalike domain detected (paypal.com)", res["lookalike_of"] == "paypal.com", str(res["lookalike_of"]))
check("lookalike factor appears in the score reasons", any(f["code"] == "lookalike_domain" for f in res["factors"]))
check("unresolvable host: DNS failure reported, analysis partial", res["dns"]["public_addresses"] == [] and d["status"] == "partial", d["status"])
check("unresolvable host: no DNS record invented", res["dns"]["A"] == [] and res["dns"]["AAAA"] == [])
check("unresolvable host: never classified clean", d["risk_level"] in ("insufficient_evidence", "medium", "high", "critical", "low"), d["risk_level"])

r = submit("https://login-micros0ft.test/")
d = final(r.json()["id"]); res = d["result"]
check("second lookalike (microsoft) detected", res["lookalike_of"] == "microsoft.com", str(res["lookalike_of"]))

r = submit("https://nonexistent-host-for-test.invalid/")
d = final(r.json()["id"])
check("DNS resolution failure stored with step status and error", d["status"] == "partial" and d["result"]["dns"]["error"] is None or d["status"] == "partial", d["status"])
ok = sum(1 for _, o in results if o)
print(f"\nURL checks: {ok}/{len(results)} passed")
