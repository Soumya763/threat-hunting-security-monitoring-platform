"""Logstash -> OpenSearch ingestion check with SYNTHETIC events only.

Requires the local Compose services: `docker compose up -d opensearch logstash`.
Sends labelled test events (TEST-NET 203.0.113.0/24, users syn_*) to each Logstash input,
then proves in OpenSearch that:
  - valid lines are parsed into the expected event_type values;
  - malformed lines are labelled parse_failure and contain no literal %{...} placeholders;
  - the events are searchable through the index patterns the detection rules use.

Usage: python scripts/verification/logstash_ingestion_check.py [--opensearch http://localhost:9200]
"""

import argparse
import json
import socket
import sys
import time
import urllib.request

UDP_PORTS = {"windows": 5002, "firewall": 5001, "proxy": 5003, "dns": 5004}


def send_udp(port: int, lines: list[str]) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for line in lines:
        sock.sendto(line.encode(), ("127.0.0.1", port))
    sock.close()


def send_json_tcp(lines: list[str]) -> None:
    with socket.create_connection(("127.0.0.1", 5000), timeout=5) as sock:
        for line in lines:
            sock.sendall((line + "\n").encode())


def search(base: str, query: dict) -> dict:
    req = urllib.request.Request(f"{base}/events-*/_search", data=json.dumps(query).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.load(resp)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--opensearch", default="http://localhost:9200")
    args = parser.parse_args()
    ts = time.strftime("%b %d %H:%M:%S")
    iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    send_udp(UDP_PORTS["windows"], [
        f"<134>{ts} DC01 Security: EventID=4625 User=syn_check SourceIP=203.0.113.90 Action=failed",
        f"<134>{ts} DC01 Security: EventID=4624 User=syn_check SourceIP=203.0.113.90 Action=success",
        "not a windows line",
    ])
    send_udp(UDP_PORTS["firewall"], [
        f"<134>{ts} fw01 kernel: drop TCP 203.0.113.91:4001 -> 198.51.100.40:23",
        "not a firewall line",
    ])
    send_udp(UDP_PORTS["proxy"], [
        f"<134>{ts} px01 proxy: GET http://intranet.example.test/check 404 0 203.0.113.92",
        "not a proxy line",
    ])
    send_udp(UDP_PORTS["dns"], [
        f"{ts} named[9]: query: check.example.test IN A from 203.0.113.93",
        "not a dns line",
    ])
    send_json_tcp([json.dumps({"event_type": "auth_failure", "user.name": "syn_check", "source.ip": "203.0.113.94",
                               "message": "SYNTHETIC check event", "@timestamp": iso})])
    print("synthetic events sent; waiting for Logstash to flush")
    time.sleep(20)

    checks = []
    expected = ["windows_login_failed", "windows_login", "firewall_connection_denied", "proxy_request_error",
                "dns_query_benign", "auth_failure"]
    result = search(args.opensearch, {"size": 0, "query": {"range": {"@timestamp": {"gte": "now-30m"}}},
                                      "aggs": {"t": {"terms": {"field": "event_type.keyword", "size": 50}}}})
    seen = {b["key"]: b["doc_count"] for b in result["aggregations"]["t"]["buckets"]}
    for name in expected:
        checks.append((f"event_type '{name}' indexed", seen.get(name, 0) >= 1, seen.get(name, 0)))

    failures = search(args.opensearch, {"size": 20, "query": {"term": {"event_type.keyword": "parse_failure"}}})
    docs = [h["_source"] for h in failures["hits"]["hits"]]
    placeholders = [d for d in docs if any("%{" in str(v) for v in d.values())]
    checks.append(("parse_failure documents present", len(docs) >= 1, len(docs)))
    checks.append(("parse_failure documents have no %{...} placeholders", not placeholders, len(placeholders)))

    ok_all = True
    for label, ok, detail in checks:
        ok_all &= bool(ok)
        print(f"{'PASS' if ok else 'FAIL'} {label} (count: {detail})")
    print("SUMMARY", "PASS" if ok_all else "FAIL")
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
