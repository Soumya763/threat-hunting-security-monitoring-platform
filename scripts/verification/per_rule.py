import os
"""Each detection rule tested in isolation: reset events and alerts, send ONLY that rule's attack
traffic through Logstash, run one detection cycle, then assert exactly that rule fired (and no other).
A final benign-only run must produce zero alerts."""
import subprocess, json, time, urllib.request, sys
import soc_scenario as S
REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
results = []
def check(name, ok, detail=""):
    results.append((name, bool(ok))); print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail else ""), flush=True)
def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, cwd=REPO).stdout
def reset():
    urllib.request.urlopen(urllib.request.Request("http://localhost:9200/events-*", method="DELETE"))
    sh("docker compose exec -T postgres psql -U postgres -d threat_hunting -qc 'TRUNCATE alerts, incidents, investigation_notes, audit_logs RESTART IDENTITY CASCADE;' 2>/dev/null")
def wait_indexed(expected):
    for _ in range(40):
        time.sleep(1)
        if all(S.count(k) >= v for k, v in expected.items()): return True
    return False
def cycle_and_alerts():
    sh("docker compose exec -T backend python -W ignore -c 'from app.scheduler import _run_cycle_sync; _run_cycle_sync()' 2>/dev/null")
    out = sh("docker compose exec -T postgres psql -U postgres -d threat_hunting -tAc \"select event_type, entity_type, entity_key, source_ip from alerts order by id\"")
    return [l.split("|") for l in out.strip().splitlines() if l.strip()]

def send_rule(rule):
    if rule == "brute": [S.win("bf-solo.user", "10.88.1.1", "failed") for _ in range(6)]
    if rule == "spray": [S.win(f"spray-solo{i}", "10.88.2.2", "failed") for i in range(5)]
    if rule == "lateral": [S.win("lat-solo.user", "10.88.3.3", "success", h) for h in ("WS-01", "WS-02", "WS-03")]
    if rule == "portscan": [S.fw("DROP", "10.88.4.4", p) for p in range(20, 32)]
    if rule == "admin": [S.fw("ALLOW", "10.88.5.5", 22) for _ in range(3)]
    if rule == "dns": S.dns("c2-solo.evil.test", "192.168.1.70")
    if rule == "proxy": [S.proxy(404, "10.88.6.6", f"q{i}") for i in range(12)]
    if rule == "json": [S.tcp_json({"event_type": "auth_failure", "user": {"name": "json-solo.user"}, "source": {"ip": "198.51.100.88"}}) for _ in range(5)]
    if rule == "benign": S.benign()

EXPECT = {  # rule key -> (alert event_type prefix, entity_key)
  "brute": ("Brute Force", "bf-solo.user"), "spray": ("Password Spraying", "10.88.2.2"),
  "lateral": ("Lateral Movement", "lat-solo.user"), "portscan": ("Network Scan", "10.88.4.4"),
  "admin": ("Remote Administration", "10.88.5.5"), "dns": ("Suspicious DNS", "c2-solo.evil.test"),
  "proxy": ("Web Enumeration", "10.88.6.6"), "json": ("Application Authentication", "json-solo.user"),
}
for rule, (prefix, entity) in EXPECT.items():
    reset(); send_rule(rule)
    wait_indexed({k: 1 for k in ("events-windows-*",)} if False else {"events-windows-*": 0})
    time.sleep(6)
    rows = cycle_and_alerts()
    fired = [r for r in rows if r and r[0].startswith(prefix)]
    others = [r for r in rows if r and not r[0].startswith(prefix)]
    check(f"rule isolated: {prefix} fires exactly once for {entity}", len(fired) == 1 and fired[0][2] == entity, str(fired))
    check(f"  no other rule fires for the {prefix} traffic", not others, str([o[0][:30] for o in others]))
    if fired and rule not in ("dns", "json", "lateral"):
        check(f"  source IP populated for {prefix}", bool(fired[0][3]) and fired[0][3] not in ("",), fired[0][3])

reset(); S.benign(); time.sleep(10)
rows = cycle_and_alerts()
check("negative: benign-only traffic (below every threshold) produces ZERO alerts", rows == [], str([r[0][:30] for r in rows]))
ok = sum(1 for _, o in results if o); print(f"\nPer-rule and negative checks: {ok}/{len(results)} passed")
