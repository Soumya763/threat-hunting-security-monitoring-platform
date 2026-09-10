import socket
import json
import random
import argparse
import time
from datetime import datetime, timezone


def generate_firewall_event():
    action = random.choice(["ALLOW", "DROP", "DENY", "REJECT"])
    protocol = random.choice(["TCP", "UDP"])
    source_ip = f"192.168.1.{random.randint(10, 250)}"
    destination_ip = random.choice(["8.8.8.8", "10.0.0.10", "203.0.113.50"])
    source_port = random.randint(1024, 65000)
    destination_port = random.choice([22, 53, 80, 443, 445])

    return (
        f"<12>{datetime.now().strftime('%b %d %H:%M:%S')} "
        f"FW-CORE-01 kernel: {action} {protocol} "
        f"{source_ip}:{source_port} -> "
        f"{destination_ip}:{destination_port}"
    )


def send_firewall_event(event, host="localhost", port=5001):
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.sendto(event.encode(), (host, port))
    client.close()


def generate_dns_event():
    domain = random.choice([
        "google.com",
        "microsoft.com",
        "github.com",
        "amazon.com",
        "cloudflare.com",
        "example.com",
        "malware.ru",
        "c2-server.com"
    ])

    query_type = random.choice(["A", "AAAA", "MX", "TXT"])
    source_ip = f"192.168.1.{random.randint(10, 250)}"

    return (
        f"<13>{datetime.now().strftime('%b %d %H:%M:%S')} "
        f"NS-01 named[2345]: query: {domain} "
        f"{query_type} IN {source_ip}"
    )


def send_dns_event(event, host="localhost", port=5004):
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.sendto(event.encode(), (host, port))
    client.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", choices=["firewall", "dns"], default="firewall")
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--rate", type=float, default=1)
    args = parser.parse_args()

    for _ in range(args.count):
        if args.source == "dns":
            event = generate_dns_event()
            send_dns_event(event)
        else:
            event = generate_firewall_event()
            send_firewall_event(event)

        print(event)
        time.sleep(1 / args.rate)


if __name__ == "__main__":
    main()