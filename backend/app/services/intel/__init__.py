"""
Threat-intelligence provider layer.

- base.py       normalised result shape, rate limiter, cache interfaces
- providers.py  one client per external service (VirusTotal, MalwareBazaar,
                AlienVault OTX, urlscan.io); AbuseIPDB is reused from
                app.services.threat_intel
- gateway.py    single entry point: configuration check, cache, rate limit,
                timeouts, error mapping. Callers never see raw provider payloads.
"""
