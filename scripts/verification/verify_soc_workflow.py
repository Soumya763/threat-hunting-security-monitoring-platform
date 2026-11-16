import os
import requests, json, sys
B = "http://localhost:8000"
results = []
def check(name, ok, detail=""):
    results.append((name, bool(ok), detail)); print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail else ""))

def login(u, p):
    r = requests.post(f"{B}/api/v1/auth/login", json={"username": u, "password": p}); r.raise_for_status()
    return {"Authorization": f"Bearer {r.json()['access_token']}"}

a1 = login("analyst1", os.environ["ANALYST1_PASSWORD"])
a2 = login("analyst2", os.environ["ANALYST2_PASSWORD"])
alerts = requests.get(f"{B}/api/v1/alerts").json()
check("public alert list returns 8 alerts", len(alerts) == 8, str(len(alerts)))
brute = next(a for a in alerts if a["event_type"].startswith("Brute Force"))
check("brute-force alert carries source IP", brute["source_ip"] == "10.66.1.10", brute["source_ip"])

r = requests.patch(f"{B}/api/v1/alerts/{brute['id']}/assignment", json={"username": "analyst1"}, headers=a1)
check("assign alert to analyst1", r.status_code == 200 and r.json()["assigned_username"] == "analyst1", str(r.status_code))
r = requests.patch(f"{B}/api/v1/alerts/{brute['id']}/status", json={"to_status": "closed"}, headers=a1)
check("illegal transition open->closed is rejected (400)", r.status_code == 400, str(r.status_code))
r = requests.patch(f"{B}/api/v1/alerts/{brute['id']}/status", json={"to_status": "acknowledged", "note": "Confirmed burst from 10.66.1.10"}, headers=a1)
check("acknowledge alert with note", r.status_code == 200 and r.json()["status"] == "acknowledged", str(r.status_code))
r = requests.patch(f"{B}/api/v1/alerts/{brute['id']}/status", json={"to_status": "closed", "note": "Account locked, source blocked"}, headers=a1)
check("close alert after acknowledgement", r.status_code == 200 and r.json()["status"] == "closed", str(r.status_code))
r = requests.patch(f"{B}/api/v1/alerts/{brute['id']}/status", json={"to_status": "open"}, headers=a1)
check("reopen closed alert", r.status_code == 200, str(r.status_code))
r = requests.post(f"{B}/api/v1/alerts/{brute['id']}/reputation", headers=a1)
check("AbuseIPDB check refuses a private source IP (never sent to a third party)", r.status_code == 200 and r.json()["status"] == "private_ip", r.json().get("status"))
r = requests.patch(f"{B}/api/v1/alerts/{brute['id']}/status", json={"to_status": "closed"}, headers={"Authorization": "Bearer bogus"})
check("status change without valid token -> 401", r.status_code == 401, str(r.status_code))

incs = requests.get(f"{B}/api/v1/incidents").json()
check("one correlated incident exists", len(incs) == 1 and len(incs[0]["alert_ids"]) == 3, str(incs and incs[0]["alert_ids"]))
inc = incs[0]
r = requests.patch(f"{B}/api/v1/incidents/{inc['id']}/assignment", json={"username": "analyst2"}, headers=a2)
check("assign incident to analyst2", r.status_code == 200 and r.json()["assigned_username"] == "analyst2", str(r.status_code))
r = requests.patch(f"{B}/api/v1/incidents/{inc['id']}/status", json={"to_status": "investigating", "note": "Starting triage"}, headers=a2)
check("incident open->investigating", r.status_code == 200 and r.json()["status"] == "investigating", str(r.status_code))
r = requests.post(f"{B}/api/v1/incidents/{inc['id']}/notes", json={"content": "Three rules fired on 10.66.1.10: brute force, HTTP burst, port scan."}, headers=a2)
check("add investigation note to incident", r.status_code in (200, 201), str(r.status_code))
notes = requests.get(f"{B}/api/v1/incidents/{inc['id']}/notes", headers=a2).json()
check("note is listed with its author", notes and notes[-1]["author"] == "analyst2", str(notes and notes[-1]))
logs = requests.get(f"{B}/api/v1/audit-logs", params={"entity_type": "alert", "entity_id": brute["id"]}, headers=a1).json()
actions = [(l["actor"], l["to_status"]) for l in logs]
check("audit trail records alert actions with actor", any(a == "analyst1" for a, _ in actions) and len(logs) >= 5, str(len(logs)))
ilogs = requests.get(f"{B}/api/v1/audit-logs", params={"entity_type": "incident", "entity_id": inc["id"]}, headers=a2).json()
check("audit trail records incident assignment and status", len(ilogs) >= 2 and all(l["actor"] == "analyst2" for l in ilogs), str(len(ilogs)))
unauth = requests.get(f"{B}/api/v1/audit-logs")
check("audit log requires login", unauth.status_code == 401, str(unauth.status_code))
other = requests.get(f"{B}/api/v1/alerts/{brute['id']}")
check("alert detail readable without login (existing public read)", other.status_code == 200)
check("incident notes require login", requests.get(f"{B}/api/v1/incidents/{inc['id']}/notes").status_code == 401)
ok = sum(1 for _, o, _ in results if o); print(f"\nSOC workflow: {ok}/{len(results)} checks passed")
sys.exit(0 if ok == len(results) else 1)
