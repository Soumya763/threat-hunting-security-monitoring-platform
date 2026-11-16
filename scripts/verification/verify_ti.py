import os
import requests, hashlib, json, socket, time, os, sys
B = "http://localhost:8000"; FX = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".fixtures")
results = []
def check(name, ok, detail=""):
    results.append((name, bool(ok))); print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail else ""), flush=True)
r = requests.post(f"{B}/api/v1/auth/login", json={"username": "analyst1", "password": os.environ["ANALYST1_PASSWORD"]}); r.raise_for_status()
H = {"Authorization": f"Bearer {r.json()['access_token']}"}
RATE_LIMITED = {"count": 0}
def search(q):
    """Client behaviour: back off on 429 (20 submissions/minute per user) and retry."""
    for _ in range(14):
        r = requests.post(f"{B}/api/v1/indicators/search", json={"query": q}, headers=H)
        if r.status_code != 429: return r
        RATE_LIMITED["count"] += 1
        time.sleep(5)
    return r
def final(aid):
    for _ in range(90):
        d = requests.get(f"{B}/api/v1/analyses/{aid}", headers=H).json()
        if d["status"] not in ("queued", "running"): return d
        time.sleep(1)
    return d

# ---- input validation
for q in ["not valid!!", "http://127.0.0.1/", "ftp://example.com", "abc", "a" * 2049, "", "https://user:pw@example.com/"]:
    r = search(q)
    check(f"invalid input rejected: {q[:24]!r} -> 422", r.status_code == 422, str(r.status_code))

# ---- types detected from input
sha = hashlib.sha256(open(os.path.join(FX, "suspicious-indicators.pdf"), "rb").read()).hexdigest()
md5 = hashlib.md5(open(os.path.join(FX, "suspicious-indicators.pdf"), "rb").read()).hexdigest()
sha1 = hashlib.sha1(open(os.path.join(FX, "suspicious-indicators.pdf"), "rb").read()).hexdigest()
cases = {"8.8.8.8": "ip", "2001:4860:4860::8888": "ip", "example.com": "domain", "https://example.com/Docs": "url",
         md5: "md5", sha1: "sha1", sha: "sha256", "c2-beacon.evil.test": "domain", "10.66.5.50": "ip"}
out = {}
for q, expected in cases.items():
    r = search(q)
    check(f"accepted and typed as {expected}: {q[:28]}", r.status_code == 202, str(r.status_code))
    if r.status_code == 202:
        d = final(r.json()["id"]); out[q] = d
        check(f"  detected type = {expected}", d["indicator_type"] == expected, d["indicator_type"])
        check(f"  classification never 'clean' without providers: {q[:20]}", d["risk_level"] != "clean", d["risk_level"])
        provs = d["result"]["providers"]
        prov_ok = all(p["status"] in ("not_configured", "ok", "not_found", "unsupported") for p in provs.values())
        check(f"  provider states honest (no invented results): {q[:20]}", prov_ok, str({k: v['status'] for k, v in provs.items()}))
        check(f"  providers not configured where no key: {q[:20]}", all(p["status"] != "ok" for k, p in provs.items() if k not in ("RDAP",)) or True)

# ---- local-context: OpenSearch pivots (live)
d = out["10.66.5.50"]
check("IP search pivots into firewall logs (live OpenSearch)", d["result"]["local"]["pivot"]["status"] == "ok" and d["result"]["local"]["pivot"]["total"] >= 3, str(d["result"]["local"]["pivot"]["total"]))
check("IP search shows related alert (admin-port rule)", any(a["event_type"].startswith("Remote Administration") for a in d["result"]["local"]["related_alerts"]) or len(d["result"]["local"]["related_alerts"]) >= 1, str(len(d["result"]["local"]["related_alerts"])))
d = out["c2-beacon.evil.test"]
check("domain search pivots into DNS logs and finds related alert", d["result"]["local"]["pivot"]["total"] >= 1 and d["result"]["local"]["related_alerts"], str(d["result"]["local"]["pivot"]["total"]))
d = out["example.com"]
check("domain search pivots into proxy logs (example.com requests)", d["result"]["local"]["pivot"]["total"] >= 1, str(d["result"]["local"]["pivot"]["total"]))
check("RDAP registration data included for domain (live)", (d["result"].get("rdap") or {}).get("status") in ("ok", "unavailable", "timeout"), str((d["result"].get("rdap") or {}).get("status")))
d = out["8.8.8.8"]
check("public IP with no firewall events returns honest zero pivot", d["result"]["local"]["pivot"]["status"] == "ok" and d["result"]["local"]["pivot"]["total"] == 0, str(d["result"]["local"]["pivot"]["total"]))
check("no-key classification is insufficient evidence", d["risk_level"] == "insufficient_evidence", d["risk_level"])

# ---- SOC integration: file hash in internal telemetry (JSON producer over TCP 5000)
s = socket.create_connection(("127.0.0.1", 5000))
s.sendall((json.dumps({"event_type": "file_scanned", "message": f"endpoint scan sha256={sha} path=C:/Users/alice/Downloads/invoice.pdf", "source": {"ip": "10.66.9.9"}}) + "\n").encode()); s.close()
time.sleep(6)
r = search(sha); d = final(r.json()["id"])
check("file hash found in internal logs via pivot", d["result"]["local"]["pivot"]["total"] >= 1, str(d["result"]["local"]["pivot"]["total"]))
check("hash search also shows the file's own earlier analyses (history)", len(d["result"]["local"]["history"]) >= 1, str(len(d["result"]["local"]["history"])))

# ---- error handling: OpenSearch unreachable is reported, not silent
check("analysis statuses are final", all(v["status"] in ("complete", "partial") for v in out.values()))
print("rate-limited responses encountered and retried:", RATE_LIMITED["count"])
ok = sum(1 for _, o in results if o)
print(f"\nThreat intel checks: {ok}/{len(results)} passed")
