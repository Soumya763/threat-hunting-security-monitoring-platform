import os
"""Provider checks against the MOCK provider server (mock-backed, not live provider results)."""
import requests, json, os, time, sys
B = "http://localhost:8000"; FX = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".fixtures"); SP = os.path.dirname(os.path.abspath(__file__))
results = []
def check(name, ok, detail=""):
    results.append((name, bool(ok))); print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail else ""), flush=True)
def mock_log():
    p = os.path.join(SP, "mock_requests.jsonl")
    return [json.loads(l) for l in open(p)] if os.path.exists(p) else []
r = requests.post(f"{B}/api/v1/auth/login", json={"username": "analyst1", "password": os.environ["ANALYST1_PASSWORD"]}); r.raise_for_status()
H = {"Authorization": f"Bearer {r.json()['access_token']}"}
def upload(name):
    with open(os.path.join(FX, name), "rb") as fh:
        return requests.post(f"{B}/api/v1/files", headers=H, files={"file": (name, fh)})
def final(aid):
    for _ in range(120):
        d = requests.get(f"{B}/api/v1/analyses/{aid}", headers=H).json()
        if d["status"] not in ("queued", "running"): return d
        time.sleep(1)
    return d
def search(q):
    for _ in range(14):
        r = requests.post(f"{B}/api/v1/indicators/search", json={"query": q}, headers=H)
        if r.status_code != 429: return r
        time.sleep(5)
    return r

def vt_gap():
    time.sleep(16)  # respect the client-side VirusTotal minimum interval (15 s)

# A. known malicious file: VT detections + MalwareBazaar hit + factors
vt_gap(); r = upload("suspicious-indicators.pdf"); d = final(r.json()["id"]); res = d["result"]
vt = res["providers"]["VirusTotal file"]; mb = res["providers"]["MalwareBazaar"]; otx = res["providers"]["OTX file"]
check("VirusTotal (mock) returns detection counts: 7 of 70", vt["status"] == "ok" and vt["detection"] == {"positives": 7, "total": 70}, str(vt.get("detection")))
check("VirusTotal label carried through as provider summary", (vt.get("summary") or {}).get("suggested_threat_label") == "trojan.mock/synthetic")
check("MalwareBazaar (mock) reports a known sample", mb["status"] == "ok" and mb["summary"].get("known_malware_sample") is True, mb["status"])
check("OTX file lookup not found -> reported as No record, not 'clean' evidence", otx["status"] == "not_found", otx["status"])
codes = {f["code"] for f in res["factors"]}
check("score reasons include engine detections and known-malicious hash", {"engine_detections", "known_malicious_hash"} <= codes, str(sorted(codes)))
check("classification high or critical for known-malicious hash", d["risk_level"] in ("high", "critical"), f"{d['risk_level']} score={d['risk_score']}")
check("detections summary: providers flagging = 2 (VT + MalwareBazaar)", res["detections"]["providers_flagging"] == 2, str(res["detections"]))
check("analysis record says 7 of 70 engines", res["detections"]["engines_flagging"] == 7 and res["detections"]["engines_total"] == 70)
secret_leak = any(k in json.dumps(d) for k in ("mock-vt-key", "mock-mb-key", "mock-otx-key", "mock-urlscan-key"))
check("provider keys never appear in API responses", not secret_leak)
reqs = [e for e in mock_log() if e["m"] == "GET" and "/files/" in e["p"]]
check("VirusTotal request carried the x-apikey header (server side only)", any(e["h"].get("x-apikey") == "mock-vt-key" for e in reqs))

# B. unknown clean-looking file: all sources answer 'no record' -> clean is allowed WITH evidence
vt_gap(); r = upload("normal.pdf"); d = final(r.json()["id"]); res = d["result"]
check("unknown file: all three sources answered 'no record' (not invented detections)", all(res["providers"][k]["status"] == "not_found" for k in ("VirusTotal file", "MalwareBazaar", "OTX file")), str({k: res["providers"][k]["status"] for k in ("VirusTotal file", "MalwareBazaar", "OTX file")}))
check("unknown file, sources consulted, no detections -> Clean, with the no-guarantee caveat", d["risk_level"] == "clean" and any("does not guarantee" in c for c in res["caveats"]), d["risk_level"])

# C. provider timeout: response delayed past the client timeout
vt_gap(); r = upload("timeout-fixture.pdf"); d = final(r.json()["id"]); res = d["result"]
check("provider timeout reported as timeout (not clean, not crash)", res["providers"]["VirusTotal file"]["status"] == "timeout", res["providers"]["VirusTotal file"]["status"])
check("timed-out analysis is partial and says why", d["status"] == "partial" and any("VirusTotal" in c for c in res["caveats"]), d["status"])

# D. domain lookup: VirusTotal (mock detections) + OTX pulses + urlscan prior malicious scan
vt_gap(); r = search("example.com"); d = final(r.json()["id"]); res = d["result"]
check("domain: VirusTotal returns 0 of 74 detections (mock)", res["providers"]["VirusTotal"]["status"] == "ok" and res["providers"]["VirusTotal"]["detection"] == {"positives": 0, "total": 74}, str(res["providers"]["VirusTotal"].get("detection")))
us = res["providers"]["urlscan.io"]
check("urlscan.io search reports 1 malicious prior scan", us["status"] == "ok" and us["summary"]["malicious_scans"] == 1, str(us.get("summary", {}).get("malicious_scans")))
check("urlscan malicious verdict is an explained factor in the score", any(f["code"] == "urlscan_malicious_verdict" and f["points"] == 15 for f in res["factors"]), str([f["code"] for f in res["factors"]]))

# E. IP lookup: VirusTotal returns quota exceeded (429) -> rate_limited, not 'no detections'
vt_gap(); r = search("203.0.113.44"); d = final(r.json()["id"]); res = d["result"]
vt = res["providers"]["VirusTotal"]
check("IP: quota-exceeded (HTTP 429) reported as rate limited", vt["status"] in ("rate_limited",), vt["status"])
check("IP: rate-limited provider never counted as a detection", vt["detection"] is None)
check("OTX pulse count for IP reported (mock campaign)", res["providers"]["AlienVault OTX"]["summary"].get("pulse_count") == 2)

# F. cache: the same domain again within the TTL must not reach the provider again
vt_gap(); r = search("example.com"); final(r.json()["id"])  # first call fills the cache
before = len([e for e in mock_log() if e["m"] == "GET" and "/domains/example.com" in e["p"]])
r = search("example.com"); d = final(r.json()["id"]); res = d["result"]
after = len([e for e in mock_log() if e["m"] == "GET" and "/domains/example.com" in e["p"]])
check("repeat lookup served from cache (no new provider request)", after == before and res["providers"]["VirusTotal"].get("cached") is True, f"{before}->{after}")

# G. consent gates and urlscan visibility
r = requests.post(f"{B}/api/v1/urls", json={"url": "https://example.com/", "submit_to_urlscan": True, "consent": False}, headers=H)
check("urlscan submission without consent refused (422)", r.status_code == 422, str(r.status_code))
r = requests.post(f"{B}/api/v1/urls", json={"url": "https://example.com/", "submit_to_urlscan": True, "consent": True}, headers=H)
check("urlscan submission with consent accepted (202)", r.status_code == 202, str(r.status_code))
d = final(r.json()["id"]); outcome = d["result"]["providers"].get("urlscan submission", {})
check("urlscan submission outcome recorded as submitted", outcome.get("status") == "submitted", str(outcome.get("status")))
posts = [e for e in mock_log() if e["m"] == "POST" and e["p"] == "/us/api/v1/scan/"]
check("submission sent with visibility=unlisted (privacy default)", posts and '"visibility": "unlisted"' in posts[-1]["body"].replace('"visibility":"unlisted"', '"visibility": "unlisted"'), posts[-1]["body"][:120] if posts else "no request")
d2 = requests.get(f"{B}/api/v1/analyses/{d['id']}", headers=H).json()
ext = requests.post(f"{B}/api/v1/analyses/{upload('suspicious-indicators.pdf').json()['id']}/external-submission", json={"provider": "virustotal", "consent": False}, headers=H)  # noqa
check("VirusTotal upload without consent refused (422)", ext.status_code == 422, str(ext.status_code))
f_id = requests.get(f"{B}/api/v1/analyses?q=suspicious-indicators", headers=H).json()["items"][0]["id"]
vt_gap(); ext = requests.post(f"{B}/api/v1/analyses/{f_id}/external-submission", json={"provider": "virustotal", "consent": True}, headers=H)
check("VirusTotal upload with consent sends the file and records submission", ext.status_code == 200 and ext.json()["outcome"]["status"] == "submitted", str(ext.status_code))
check("external submission timestamp recorded", requests.get(f"{B}/api/v1/analyses/{f_id}", headers=H).json()["external_submitted"] is True)
ok = sum(1 for _, o in results if o)
print(f"\nProvider checks (MOCK-backed): {ok}/{len(results)} passed")
