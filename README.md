# Threat Hunting & Security Monitoring Platform

A security operations platform that combines three things in one application:

1. **SOC monitoring** - log ingestion (Logstash), YAML detection rules, alerts, correlated
   incidents, analyst workflow, and an audit trail.
2. **Threat analysis** - file analysis, URL analysis and a unified threat-intelligence search,
   with explainable scores.
3. **Local context** - analysis results are checked against the platform's own logs
   (OpenSearch), so a suspicious hash, domain or IP can be traced to internal activity.

The platform is built on the existing stack: React + Vite, FastAPI, PostgreSQL, Logstash,
OpenSearch (the search and log analytics engine), and Docker Compose.

> **Live demo:** the public demo was deployed before this expansion, and it does not include
> the analysis modules. Do not treat it as the current version.
> https://threat-hunting-security-monitoring.vercel.app/ · API health: https://threat-hunting-security-monitoring.onrender.com/health

## What you can do

| Area | Capability |
|---|---|
| Monitor | Dashboard with real counts, alert trend and latest analyses · Alerts (filter, sort, assign, status) · Incidents (notes, assignment) · Log Monitoring (read-only search) |
| File Analysis | Upload EXE/DLL, PDF, DOC/DOCX/XLS/XLSX/PPT/PPTX, ZIP, PNG/JPG/JPEG · magic-byte type check · MD5/SHA-1/SHA-256 · provider reputation by hash · static analysis · YARA · explainable score · JSON and PDF report |
| URL Analysis | Validation and normalisation · DNS A/AAAA · SSRF-guarded fetch with redirect re-checks · TLS certificate · RDAP domain age · phishing and brand-lookalike indicators · provider lookups · explainable score · reports |
| Threat Intel Search | IP, domain, URL, MD5, SHA-1, SHA-256 · providers · your history · related alerts · internal log pivot |
| History | Every analysis, with type and risk filters, search, sort, pagination, and owner-only access |
| Investigation | Notes on analyses · link analyses to existing or new incidents · audit entries for these actions |
| Reports | Analysis and incident reports, JSON and PDF, generated from stored data |

Every external service is optional. Without any keys, local analysis still runs and each
provider is shown as "not configured".

## Status

| Feature | Status | Notes |
|---|---|---|
| Existing SOC: ingestion, detection, alerts, incidents, audit, auth | Implemented | Unchanged except the fixes below |
| Fix: `source_ip` never written to alerts | Implemented | IP-entity alerts and user alerts (via rule sub-aggregation) |
| Fix: correlation merged unrelated users | Implemented | Requires shared IP or entity inside 15 min |
| Fix: JSON pipeline index unread by rules | Implemented | Writes `events-json-*`; a rule reads it (producer contract in the rule file) |
| Fix: frontend Analysis route missing | Implemented | Analysis routes in the new sidebar |
| Fix: tests needed `JWT_SECRET_KEY` to import | Implemented | Test-only key set in `conftest.py` |
| Detection rules | Implemented and run against live OpenSearch (8) | Brute force, password spraying, port scan, remote-admin access, suspicious DNS, web error burst, app auth failures, lateral movement. Each rule has an integration test against OpenSearch 2.19.7 |
| File analysis (type, hashes, static, YARA, score, reports) | Implemented | Tested with synthetic files; parser limits listed in the report |
| URL analysis with SSRF protection | Implemented | Tested with stubbed DNS and HTTP; real network path exercised only against example hosts |
| Threat-intel search | Implemented | Providers stubbed in tests |
| VirusTotal, MalwareBazaar, OTX, urlscan.io integrations | Implemented; client verified over real HTTP against a **labelled mock** (28 checks). Real provider responses **not verified** (no keys) | See [docs/PROVIDERS.md](docs/PROVIDERS.md) |
| AbuseIPDB | Implemented (existing, reused) | Needs key |
| RDAP domain data | Implemented, not live-tested | No key |
| Local log pivots and log search | Implemented and live-tested | Verified through the API against OpenSearch 2.19.7 (Logstash → OpenSearch → API) |
| End-to-end verification | Done; see [docs/VERIFICATION-REPORT.md](docs/VERIFICATION-REPORT.md) | Backend 219 tests passing (incl. live OpenSearch and PostgreSQL), scripted end-to-end suites in `scripts/verification/` |
| Analysis history, owner isolation | Implemented and tested | |
| Analyst notes, incident links, audit | Implemented and tested | |
| Dashboard summary | Implemented | Counts come from the database |
| Frontend pages | Implemented and verified in a headless browser (39 workflow checks, mobile layout) | Every sidebar route, uploads, URL analysis, search, history, reports, alert and incident actions, error states |
| Scoring weights | **Starting values**, not tuned | No labelled dataset yet |
| Incident page lists linked analyses | Not implemented | Incident **reports** include them |
| Frontend Dockerfile | Not implemented | Build with `npm run build` |
| Backend Docker image | Built and run as the `backend` Compose service (verified) | See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) |
| Dynamic analysis / sandbox | Out of scope | |
| AI summaries, natural-language hunting, copilot | Not implemented | Planned later, per the project report |

## Quick start

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for the full steps. In short:

```bash
docker compose up -d postgres opensearch logstash
cd backend && cp .env.example .env   # set JWT_SECRET_KEY
pip install -r requirements.txt
python -m app.database.migrate
python -m app.auth.create_user <username> <password>
python -m uvicorn app.main:app --reload --port 8000
# in another terminal
cd frontend && cp .env.example .env && npm ci && npm run dev
```

## Configuration

Copy `backend/.env.example` to `backend/.env`. It lists every variable with a comment. Key ones:

- `JWT_SECRET_KEY` (required)
- `QUARANTINE_DIR`, `FILE_MAX_UPLOAD_BYTES`, `FILE_RETENTION_HOURS`
- `URL_MAX_REDIRECTS`, `URL_FETCH_TIMEOUT_SECONDS`, `URL_MAX_BODY_BYTES`
- `VIRUSTOTAL_API_KEY`, `MALWAREBAZAAR_AUTH_KEY`, `OTX_API_KEY`, `URLSCAN_API_KEY`, `ABUSEIPDB_API_KEY` (all optional)
- `URLSCAN_VISIBILITY` (`unlisted` by default), `PROVIDER_HASH_LOOKUP_ENABLED`

No real credentials are stored in the repository. `.env` is git-ignored.

## Testing

```bash
cd backend && JWT_SECRET_KEY=test-only-secret-0123456789abcdef0123456789abcdef python -m pytest -q
cd frontend && npm test && npm run build
```

Results, and what each one does and does not prove, are in [docs/TESTING.md](docs/TESTING.md).

## Documentation

- [Architecture](docs/ARCHITECTURE.md): modules, data flow, database changes, classification
- [API reference](docs/API.md): endpoints with request and response examples
- [Providers](docs/PROVIDERS.md): each integration, what is sent, limits and terms to verify
- [Security](docs/SECURITY.md): file, URL/SSRF, auth, secrets, outputs, known gaps
- [Testing](docs/TESTING.md) · [Deployment](docs/DEPLOYMENT.md) · [Status and decisions](docs/analysis-expansion-plan.md)

## Project context

This is a final-year major project. The original report (`Threat_Hunting_Platform_Project_Report.pdf`)
recorded the baseline and the proposed design. The fixes and modules above follow that design.
Some report recommendations are not implemented yet: AI features, Sigma import, behavioural
baselines, and dynamic analysis.
