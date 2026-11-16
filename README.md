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

> **Production:** https://threat-hunting-security-monitoring.vercel.app/
> (frontend) · API: https://threat-hunting-security-monitoring.onrender.com (health: `/health`).
> The production site has no OpenSearch, no Logstash, and no provider keys yet. See
> [Production deployment](#production-deployment) for what works and what does not.

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
| End-to-end verification | Done; see [docs/VERIFICATION-REPORT.md](docs/VERIFICATION-REPORT.md) | Backend 220 tests passing (15 live-service tests skipped unless OpenSearch and PostgreSQL are reachable), scripted end-to-end suites in `scripts/verification/` |
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

## Production deployment

| Part | Where | Notes |
|---|---|---|
| Frontend (React, Vite) | Vercel: `https://threat-hunting-security-monitoring.vercel.app` | Builds `frontend/` from `main`. `VITE_API_BASE_URL` points at the backend. Public, no Vercel login wall. |
| Backend (FastAPI) | Render web service (Python, free plan): `https://threat-hunting-security-monitoring.onrender.com` | Builds `backend/` from `main`. Start: `uvicorn app.main:app`. CORS allows only the Vercel origin. |
| Database (PostgreSQL 18) | Neon project `threat-hunting-platform`, `production` branch | Connected with SSL (`POSTGRES_SSLMODE=require`). Schema migrated with additive changes only. |
| Search / logs (OpenSearch) | **Not deployed** | Log search returns "unavailable" (HTTP 503). Nothing is faked. |
| Log ingestion (Logstash) | **Not deployed** | Depends on OpenSearch. |
| Threat-intel providers | Optional, keys in Render's environment | Without keys each provider shows "not configured". Use **Settings → Check now** after adding a key. |

```
Browser ──HTTPS──▶ Vercel (static React app)
                     │  API calls with bearer token
                     ▼
                  Render (FastAPI, uvicorn)  ──SSL──▶  Neon (PostgreSQL)
                     │
                     └── OpenSearch: not deployed (optional, see limitations)
```

Secrets (database password, JWT secret, provider keys) live only in the Render environment.
They are never in the repository, the frontend bundle, logs or reports. Provider keys are read
by the backend only; the browser never receives them.

### Limitations of this deployment

- **OpenSearch and Logstash are not running**, so log search and Log Monitoring show unavailable.
  A free managed option (Aiven) exists, but it needs an account and its own connection setup.
- **Provider integrations are configured per key.** Until a valid key is set, VirusTotal, OTX,
  urlscan.io, AbuseIPDB and MalwareBazaar report "not configured". Results without keys are
  "Not scored", never clean.
- **Free Render plan:** the service sleeps after inactivity, so the first request can take
  about a minute. It has no persistent disk, so uploaded files in quarantine are not kept
  across restarts. Analysis records stay in Neon.
- **Rate limits are per process.** One backend instance is assumed.
- **Scoring weights are starting values**, not tuned on labelled data.
- Live provider behaviour with valid keys is not yet verified. See [docs/PROVIDERS.md](docs/PROVIDERS.md).

## Configuration

Copy `backend/.env.example` to `backend/.env`. It lists every variable with a comment. Key ones:

- `JWT_SECRET_KEY` (required)
- `QUARANTINE_DIR`, `FILE_MAX_UPLOAD_BYTES`, `FILE_RETENTION_HOURS`
- `URL_MAX_REDIRECTS`, `URL_FETCH_TIMEOUT_SECONDS`, `URL_MAX_BODY_BYTES`
- `VIRUSTOTAL_API_KEY`, `MALWAREBAZAAR_AUTH_KEY`, `OTX_API_KEY`, `URLSCAN_API_KEY`, `ABUSEIPDB_API_KEY` (all optional; sign-up links in [docs/PROVIDERS.md](docs/PROVIDERS.md))
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
