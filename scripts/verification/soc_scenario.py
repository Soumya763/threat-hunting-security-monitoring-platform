"""Synthetic SOC scenario sent through the real Logstash inputs (UDP 5001-5004, TCP 5000).
Attack events trigger each of the eight rules; benign events stay below every threshold."""
import json, socket, time, urllib.request
from datetime import datetime

OS = "http://localhost:9200"
TS = lambda: datetime.now().strftime("%b %d %H:%M:%S")

def udp(port, line):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(line.encode(), ("127.0.0.1", port)); s.close()

def win(user, ip, action, host="WS-01"):
    eid = 4625 if action == "failed" else 4624
    udp(5002, f"<13>{TS()} {host} Security: EventID={eid} User={user} SourceIP={ip} Action={action}")

def fw(action, src, dport, sport=40000):
    udp(5001, f"<12>{TS()} FW-CORE-01 kernel: {action} TCP {src}:{sport} -> 10.0.0.10:{dport}")

def dns(domain, client):
    udp(5004, f"<13>{TS()} NS-01 named[2345]: query: {domain} A IN {client}")

def proxy(status, client, path="x"):
    udp(5003, f"<14>{TS()} PX-01 proxy: GET http://example.com/{path} {status} 512 {client}")

def tcp_json(obj):
    s = socket.create_connection(("127.0.0.1", 5000)); s.sendall((json.dumps(obj) + "\n").encode()); s.close()

ATTACKER = "10.66.1.10"      # brute force + proxy burst + port scan -> correlated
SPRAY_SRC = "10.66.2.20"
LATERAL_SRC = "10.66.3.30"
ADMIN_SRC = "10.66.5.50"
DNS_CLIENT = "192.168.1.60"
JSON_SRC = "198.51.100.70"
BENIGN_A = "10.77.1.1"; BENIGN_F = "10.77.2.2"; BENIGN_P = "10.77.3.3"

def attack():
    for _ in range(6): win("brute.user", ATTACKER, "failed")                     # R2 brute force
    for i in range(5): win(f"spray{i:02d}", SPRAY_SRC, "failed")                  # R3 password spraying
    for h in ("WS-01", "WS-02", "WS-03"): win("lateral.user", LATERAL_SRC, "success", h)   # R1 lateral
    for port in range(20, 32): fw("DROP", ATTACKER, port)                         # R4 port scan (12 ports)
    for _ in range(3): fw("ALLOW", ADMIN_SRC, 22)                                  # R5 admin port allowed
    dns("c2-beacon.evil.test", DNS_CLIENT)                                         # R6 suspicious DNS
    for i in range(12): proxy(404, ATTACKER, f"p{i}")                              # R7 HTTP error burst
    for _ in range(5): tcp_json({"event_type": "auth_failure", "user": {"name": "app.user"},
                                 "source": {"ip": JSON_SRC}, "message": "login rejected"})  # R8

def benign():
    win("normal.user", BENIGN_A, "failed"); win("normal.user", BENIGN_A, "success")      # below thresholds
    win("twohosts.user", BENIGN_A, "success", "WS-01"); win("twohosts.user", BENIGN_A, "success", "WS-02")
    for _ in range(20): fw("ALLOW", BENIGN_F, 443)                                       # normal HTTPS
    for p in (80, 8080, 3306): fw("DENY", BENIGN_F, p)                                  # few denials
    dns("www.example.com", "192.168.1.9")                                                # no keyword
    for _ in range(15): proxy(200, BENIGN_P, "ok")
    for _ in range(5): proxy(404, BENIGN_P, "missing")                                   # below 10
    for _ in range(4): tcp_json({"event_type": "auth_failure", "user": {"name": "quiet.user"},
                                 "source": {"ip": "203.0.113.5"}})                       # below 5
    for _ in range(10): tcp_json({"event_type": "page_view", "user": {"name": "quiet.user"}})

def count(index):
    try:
        with urllib.request.urlopen(f"{OS}/{index}/_count") as r: return json.load(r)["count"]
    except Exception: return 0

if __name__ == "__main__":
    attack(); benign()
    expected = {"events-windows-*": 6 + 5 + 3 + 2 + 2, "events-firewall-*": 12 + 3 + 20 + 3 + 0,
                "events-dns-*": 2, "events-proxy-*": 12 + 15 + 5, "events-json-*": 5 + 4 + 10}
    expected["events-firewall-*"] = 12 + 3 + 20 + 3
    for _ in range(40):
        time.sleep(1)
        if all(count(k) >= v for k, v in expected.items()): break
    print({k: count(k) for k in expected}, "expected>=", expected)
