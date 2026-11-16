# Production verification report

Date of the last run: 16 November 2026. Commit under test: `main` after PR #5 (`f6c1919`).

This report separates three things: what runs in production, what runs locally with real
services, and what cannot be verified without credentials or paid hosting.

## Architecture under the zero-budget constraint

| Component | Where it runs | Cost |
|---|---|---|
| Frontend (React, Vite) | Vercel, free plan | Free |
| Backend (FastAPI) | Render, free web service | Free |
| Database (PostgreSQL) | Neon, free plan | Free |
| OpenSearch | Local Docker Compose only | Free (your machine) |
| Logstash | Local Docker Compose only | Free (your machine) |
| Threat-intel providers | Optional; keys added by you | Free tiers only |

No paid service is used. Production has no OpenSearch, so log search returns HTTP 503 and the
application says so.

## Production smoke test (live)

| Check | Result |
|---|---|
| Frontend `https://threat-hunting-security-monitoring.vercel.app/` | HTTP 200 |
| Backend `/health` | `api: ok`, `postgres: ok`, `opensearch: unreachable` (accurate) |
| Login and authorization | Login works; data pages redirect logged-out visitors (13/13 browser checks) |
| Threat-intel providers | VirusTotal, MalwareBazaar, OTX, urlscan, AbuseIPDB: **not configured**. RDAP: configured (no key needed) |
| Log search | HTTP 503 with a clear "unavailable" message |
| Dashboard, alerts, incidents | Return data from Neon |

## Local end-to-end verification (real services)

Run against Docker Compose PostgreSQL 16, OpenSearch 2.19.7 and Logstash 8.9.0, with the local
FastAPI backend and Vite frontend.

| Area | Result |
|---|---|
| Backend tests, live services reachable | 235 passed, 0 skipped (including 11 OpenSearch and 4 PostgreSQL integration tests) |
| Frontend unit tests and production build | 5/5 pass; build succeeds |
| Logstash ingestion (`scripts/verification/logstash_ingestion_check.py`) | 8/8 pass. Parsed events indexed for each source; malformed lines indexed as `parse_failure` with no placeholders |
| Detection rules | All 8 rules produce alerts from labelled synthetic events, each with its MITRE technique |
| Browser: dashboard, alerts, alert detail, incidents, log search, settings | 7/7 pass |
| API: file upload, SHA-256, explainable score, JSON and PDF reports, empty upload rejected | 16/16 pass (combined with the URL, indicator, incident and note checks) |
| API: URL analysis (DNS, TLS), private-IP URL blocked before any network call | Pass |
| API: IP investigation pivot into internal logs and related alerts | Pass (16 internal events, 1 related alert) |
| API: analysis linked to an incident, analyst note saved, history listed | Pass |

## Defects found and fixed in this round

1. **Unparsed log lines were labelled as normal events.** The DNS, firewall, proxy and Windows
   pipelines kept events that failed to parse, with literal `%{...}` placeholders. DNS labelled
   them `dns_query_benign`. Fixed in PR #5: unparsed lines are `parse_failure` and carry no
   detection labels.
2. **Provider failure could read as a clean verdict.** Fixed in PR #2 (see the README).
3. **Dashboard, alerts and incidents were reachable without login.** Fixed in PR #3.

## Remaining limitations and what each one needs

| Limitation | Why | What you need to do |
|---|---|---|
| No real provider results yet | No API keys are set in production | Create the free accounts listed in `docs/PROVIDERS.md`, add each key to the Render environment, then press "Check now" in Settings |
| Log search unavailable in production | OpenSearch cannot run on Render's free tier, and paid or managed hosting is excluded by the zero-budget requirement | Accept the local demonstration, or approve a hosting option that is free for your use |
| Logstash only local | Depends on OpenSearch and on real log sources | Demonstrate with `scripts/verification/logstash_ingestion_check.py`; real log sources need their own forwarding setup |
| Test data in production | Production contains a smoke-test alert from earlier development | Ask before deleting; it is kept because deleting data needs your approval |
| Render free plan sleeps | Free plan behaviour | First request after idle may take about a minute |
| Scoring weights | Starting values, not tuned | Tune only with a labelled dataset |

## How to reproduce the local demonstration

See the "Local demonstration" section of `README.md`.
