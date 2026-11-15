import os
import requests, time, subprocess, json
B = "http://localhost:8000"; REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
results = []
def check(name, ok, detail=""):
    results.append((name, bool(ok))); print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail else ""), flush=True)
def login(u, p):
    r = requests.post(f"{B}/api/v1/auth/login", json={"username": u, "password": p}); r.raise_for_status()
    return {"Authorization": f"Bearer {r.json()['access_token']}"}
a1 = login("analyst1", os.environ["ANALYST1_PASSWORD"]); a2 = login("analyst2", os.environ["ANALYST2_PASSWORD"])
def wait(aid, h):
    for _ in range(90):
        d = requests.get(f"{B}/api/v1/analyses/{aid}", headers=h).json()
        if d["status"] not in ("queued", "running"): return d
        time.sleep(1)
    return d
def submit_url(u, h):
    for _ in range(14):
        r = requests.post(f"{B}/api/v1/urls", json={"url": u}, headers=h)
        if r.status_code != 429: return r
        time.sleep(5)
    return r
def search(q, h):
    for _ in range(14):
        r = requests.post(f"{B}/api/v1/indicators/search", json={"query": q}, headers=h)
        if r.status_code != 429: return r
        time.sleep(5)
    return r

# ownership for URL and indicator analyses
u = submit_url("https://example.com/owned-by-analyst1", a1).json()["id"]
i = search("198.51.100.200", a1).json()["id"]
wait(u, a1); wait(i, a1)
for label, aid in (("URL", u), ("indicator search", i)):
    check(f"analyst2 cannot read analyst1's {label} analysis (404)", requests.get(f"{B}/api/v1/analyses/{aid}", headers=a2).status_code == 404)
    check(f"analyst2 cannot download {label} report (404)", requests.get(f"{B}/api/v1/analyses/{aid}/report.json", headers=a2).status_code == 404)
    check(f"analyst2 cannot add a note to {label} analysis (404)", requests.post(f"{B}/api/v1/analyses/{aid}/notes", json={"content": "x"}, headers=a2).status_code == 404)
    check(f"analyst2 cannot rerun {label} analysis (404)", requests.post(f"{B}/api/v1/analyses/{aid}/rerun", headers=a2).status_code == 404)
    check(f"analyst2 cannot link {label} analysis to an incident (404)", requests.post(f"{B}/api/v1/analyses/{aid}/incidents", json={"create_incident": True, "title": "nope case"}, headers=a2).status_code == 404)
check("analyst2 history does not list analyst1 analyses", all(it["id"] not in (u, i) for it in requests.get(f"{B}/api/v1/analyses", headers=a2, params={"page_size": 100}).json()["items"]))
hist_ind = requests.get(f"{B}/api/v1/analyses", headers=a1, params={"kind": "indicator", "page_size": 100}).json()["items"]
check("indicator searches appear in history under their type filter", any(it["id"] == i for it in hist_ind), str(len(hist_ind)))
check("analyst2 pivot on analyst1 analysis refused (404)", requests.get(f"{B}/api/v1/analyses/{u}/pivot", headers=a2).status_code == 404)

# retention: expire bytes via the real purge routine, keep the record, block re-analysis
ret = subprocess.run(["docker", "compose", "exec", "-T", "backend", "python", "-W", "ignore", "-c",
    "from datetime import datetime, timedelta, timezone\nfrom app.services.quarantine import purge_expired\nprint('PURGED', purge_expired(now=datetime.now(timezone.utc)+timedelta(days=30)))"],
    capture_output=True, text=True, cwd=REPO)
purged = int(ret.stdout.strip().split()[-1]) if "PURGED" in ret.stdout else -1
check("retention purge removes expired quarantined bytes", purged >= 1, ret.stdout.strip()[-80:] or ret.stderr[-120:])
d = requests.get(f"{B}/api/v1/analyses/{i}", headers=a1).json()
d_url = requests.get(f"{B}/api/v1/analyses/{u}", headers=a1).json()
files = requests.get(f"{B}/api/v1/analyses", headers=a1, params={"kind": "file", "page_size": 100}).json()["items"]
purged_rows = [f for f in files if not f["file_available"]]
check("file analyses whose bytes were purged are marked file_available=false", len(purged_rows) >= 1, str(len(purged_rows)))
if purged_rows:
    pr = requests.get(f"{B}/api/v1/analyses/{purged_rows[0]['id']}", headers=a1).json()
    check("purged record keeps file_purged_at timestamp and status", pr["file_purged_at"] is not None and pr["status"] in ("complete", "partial"), str(pr["file_purged_at"]))
    check("purged file keeps its report (JSON still downloads)", requests.get(f"{B}/api/v1/analyses/{pr['id']}/report.json", headers=a1).status_code == 200)
    check("rerun of a purged file is refused (409) - no bytes to analyse", requests.post(f"{B}/api/v1/analyses/{pr['id']}/rerun", headers=a1).status_code == 409)
    check("external submission of a purged file refused (409)", requests.post(f"{B}/api/v1/analyses/{pr['id']}/external-submission", json={"provider": "virustotal", "consent": True}, headers=a1).status_code == 409)
ok = sum(1 for _, o in results if o); print(f"\nOwnership and retention checks: {ok}/{len(results)} passed")
