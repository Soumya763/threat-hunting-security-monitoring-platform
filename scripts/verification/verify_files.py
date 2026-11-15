import os
import requests, hashlib, json, os, sys, time, subprocess
FX = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".fixtures")
B = "http://localhost:8000"
results = []
def check(name, ok, detail=""):
    results.append((name, bool(ok))); print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail else ""), flush=True)
def login(u, p):
    r = requests.post(f"{B}/api/v1/auth/login", json={"username": u, "password": p}); r.raise_for_status()
    return {"Authorization": f"Bearer {r.json()['access_token']}"}
a1 = login("analyst1", os.environ["ANALYST1_PASSWORD"]); a2 = login("analyst2", os.environ["ANALYST2_PASSWORD"])

def upload(name, headers, data=None):
    """Client behaviour: back off on 429 (20 submissions per minute per user) and retry."""
    path = os.path.join(FX, name)
    for _ in range(14):
        with open(path, "rb") as fh:
            r = requests.post(f"{B}/api/v1/files", headers=headers, files={"file": (name, fh, "application/octet-stream")})
        if r.status_code != 429: return r
        time.sleep(5)
    return r
def wait_final(aid, headers):
    for _ in range(60):
        d = requests.get(f"{B}/api/v1/analyses/{aid}", headers=headers).json()
        if d["status"] not in ("queued", "running"): return d
        time.sleep(1)
    return d

# rejections first
check("empty file rejected (400)", upload("empty.pdf", a1).status_code == 400, str(upload("empty.pdf", a1).status_code))
check("unsupported extension rejected (415)", upload("unsupported.sh", a1).status_code == 415)
r = upload("oversized.pdf", a1)
check("file over 32 MB rejected (413)", r.status_code == 413, str(r.status_code))

expect = {
  "normal.pdf":               dict(kind="pdf", family="pdf", match=True, codes=set(), max_score=0),
  "suspicious-indicators.pdf":dict(kind="pdf", family="pdf", match=True, codes={"pdf_javascript", "pdf_automatic_action", "pdf_launch_action"}, min_score=25, yara="pdf_auto_javascript"),
  "archive.zip":              dict(kind="zip", family="zip_container", match=True, codes={"archive_executable", "archive_path_traversal"}, min_score=20),
  "document.docx":            dict(kind="zip", family="zip_container", match=True, codes=set(), max_score=0),
  "macro-test.docx":          dict(kind="zip", family="zip_container", match=True, codes={"office_macro_present"}, min_score=10),
  "image.png":                dict(kind="image", family="png", match=True, codes=set(), max_score=0),
  "image.jpg":                dict(kind="image", family="jpeg", match=True, codes=set(), max_score=0),
  "polyglot.png":             dict(kind="image", family="png", match=True, codes={"image_trailing_data", "image_embedded_file"}, min_score=30),
  "synthetic-pe.exe":         dict(kind="pe", family="pe_executable", match=True, codes={"native_executable"}, max_score=5),
  "mismatch-invoice.pdf":     dict(kind="pe", family="pe_executable", match=False, codes={"extension_mismatch", "native_executable"}, min_score=15),
  "malformed.pdf":            dict(kind=None, family="pdf", match=True, codes=set(), max_score=0),
}
ids = {}
for name, exp in expect.items():
    r = upload(name, a1)
    check(f"upload accepted: {name}", r.status_code == 202, str(r.status_code))
    if r.status_code != 202: continue
    aid = r.json()["id"]; ids[name] = aid
    d = wait_final(aid, a1)
    res = d.get("result") or {}
    local_sha = hashlib.sha256(open(os.path.join(FX, name), "rb").read()).hexdigest()
    check(f"  sha256 matches local hash: {name}", d["sha256"] == local_sha)
    ident = res.get("identification", {})
    check(f"  magic-byte family = {exp['family']}: {name}", ident.get("detected_family") == exp["family"], str(ident.get("detected_family")))
    check(f"  extension match = {exp['match']}: {name}", ident.get("extension_matches") is exp["match"], str(ident.get("extension_matches")))
    codes = {f["code"] for f in res.get("factors", [])}
    missing = exp["codes"] - codes
    check(f"  expected factors present: {name}", not missing, f"missing={sorted(missing)} got={sorted(codes)}")
    if "min_score" in exp: check(f"  score >= {exp['min_score']}: {name}", d["risk_score"] >= exp["min_score"], str(d["risk_score"]))
    if "max_score" in exp: check(f"  score <= {exp['max_score']}: {name}", d["risk_score"] <= exp["max_score"], str(d["risk_score"]))
    if exp.get("yara"):
        check(f"  YARA rule {exp['yara']} matched: {name}", any(m["rule"] == exp["yara"] for m in (res.get("yara") or {}).get("matches", [])))
    check(f"  no provider configured -> never 'clean': {name}", d["risk_level"] != "clean", d["risk_level"])
    check(f"  analysis status final ({d['status']}): {name}", d["status"] in ("complete", "partial"), d["status"])
    check(f"  steps and recommendations recorded: {name}", bool(res.get("steps")) and bool(res.get("recommendations")))

# invalid-but-accepted input: truncated PNG must report a parse error, not crash
open(os.path.join(FX, "broken.png"), "wb").write(b"\x89PNG\r\n\x1a\n" + b"\x00" * 7)
r = upload("broken.png", a1); aid = r.json()["id"]; d = wait_final(aid, a1)
check("truncated PNG: analysis finishes with a parse note, no crash", d["status"] in ("complete", "partial") and (d["result"]["static"] or {}).get("parse_error"), str((d["result"]["static"] or {}).get("parse_error")))

# ownership
aid = ids["suspicious-indicators.pdf"]
check("other user cannot read the analysis (404)", requests.get(f"{B}/api/v1/analyses/{aid}", headers=a2).status_code == 404)
check("other user cannot download PDF report (404)", requests.get(f"{B}/api/v1/analyses/{aid}/report.pdf", headers=a2).status_code == 404)
check("other user cannot delete it (404)", requests.delete(f"{B}/api/v1/analyses/{aid}", headers=a2).status_code == 404)
check("other user history does not list it", all(i["id"] != aid for i in requests.get(f"{B}/api/v1/analyses", headers=a2).json()["items"]))
check("unauthenticated report download refused (401)", requests.get(f"{B}/api/v1/analyses/{aid}/report.pdf").status_code == 401)

# reports
pdf = requests.get(f"{B}/api/v1/analyses/{aid}/report.pdf", headers=a1)
open(os.path.join(FX, "report-suspicious.pdf"), "wb").write(pdf.content)
check("PDF report downloads with %PDF header", pdf.status_code == 200 and pdf.content.startswith(b"%PDF-"), str(pdf.status_code))
pinfo = subprocess.run(["pdfinfo", os.path.join(FX, "report-suspicious.pdf")], capture_output=True, text=True)
check("PDF report opens in a PDF reader (pdfinfo)", pinfo.returncode == 0 and "Pages:" in pinfo.stdout, pinfo.stdout.split("\n")[1] if pinfo.stdout else pinfo.stderr[:80])
js = requests.get(f"{B}/api/v1/analyses/{aid}/report.json", headers=a1)
try:
    doc = js.json(); ok_json = js.status_code == 200 and doc["analysis"]["id"] == aid and doc["risk"]["score"] == requests.get(f"{B}/api/v1/analyses/{aid}", headers=a1).json()["risk_score"]
except ValueError:
    ok_json = False
check("JSON report is valid and matches stored score", ok_json)

# history, filters, sort, pagination
hist = requests.get(f"{B}/api/v1/analyses", headers=a1, params={"kind": "file", "page_size": 5}).json()
check("history lists file analyses with pagination (pages>1)", hist["total"] >= 12 and hist["pages"] >= 3, f"total={hist['total']} pages={hist['pages']}")
by_score = requests.get(f"{B}/api/v1/analyses", headers=a1, params={"sort": "risk_score", "order": "desc", "page_size": 3}).json()["items"]
check("sort by risk score desc", all(by_score[i]["risk_score"] >= by_score[i+1]["risk_score"] for i in range(len(by_score)-1)))
crit = requests.get(f"{B}/api/v1/analyses", headers=a1, params={"q": "suspicious-indicators"}).json()
check("search by file name finds the file", crit["total"] >= 1 and crit["items"][0]["display_name"] == "suspicious-indicators.pdf")

# retention and deletion
qdir = subprocess.run(["docker", "compose", "exec", "-T", "backend", "sh", "-c", "ls /app/quarantine | wc -l"], capture_output=True, text=True, cwd=os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))).stdout.strip()
check("uploaded bytes exist in quarantine", int(qdir or 0) >= 12, qdir)
dl = requests.delete(f"{B}/api/v1/analyses/{ids['normal.pdf']}", headers=a1)
check("delete own analysis -> 204", dl.status_code == 204, str(dl.status_code))
check("deleted analysis is gone (404)", requests.get(f"{B}/api/v1/analyses/{ids['normal.pdf']}", headers=a1).status_code == 404)
ok = sum(1 for _, o in results if o)
print(f"\nFile analysis checks: {ok}/{len(results)} passed")
