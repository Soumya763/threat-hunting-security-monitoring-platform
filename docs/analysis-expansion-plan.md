# Analysis Expansion: Assessment, Plan and Status

This document records the Phase 1 repository assessment, the Phase 2 design,
and the implementation status of the File / URL / Threat-Intelligence
expansion. Each feature is labelled **Implemented**, **Partial**, **Planned**
or **Not started**. Nothing is marked implemented unless code and tests exist
in this branch.

## 1. Phase 1: Repository assessment

### 1.1 Access and scope
- Repository: `Soumya763/threat-hunting-security-monitoring-platform`, checked
  out locally. Branch used: `claude/pensive-hypatia-997k5a` (the branch the
  session is configured to develop on). The original `main` is untouched.
- The original 20 backend tests were not collectable without
  `JWT_SECRET_KEY` set, because `app/config.py` refuses to start with an empty
  secret. This is pre-existing and by design; tests are run with
  `JWT_SECRET_KEY=<any value>` in the environment.

### 1.2 What exists and works (verified in code)
| Area | Evidence | Status |
|---|---|---|
| Log ingestion (5 Logstash pipelines) | `logstash/pipelines/*.conf` | Implemented (Windows source is a custom text format; DNS keyword check is a substring match) |
| Scheduled detection + correlation | `app/scheduler.py`, `app/detection/*`, `app/correlation/engine.py` | Implemented, with the known gaps below |
| Alerts API + status lifecycle + assignment | `app/api/alerts.py` | Implemented |
| Incidents API, notes, assignment | `app/api/incidents.py` | Implemented |
| Audit trail | `app/services/audit.py`, `app/api/audit.py` | Implemented |
| JWT login + rate limit | `app/api/auth.py`, `app/auth/*` | Implemented (rate limit is per-process) |
| AbuseIPDB IP reputation | `app/services/threat_intel.py` | Partial (only reachable for alerts with a `source_ip`, see 1.3) |
| React dashboard, alerts, incidents, login | `frontend/src/pages/*` | Implemented |

### 1.3 Confirmed gaps in the existing system (not changed in this branch)
These come from the attached report and were re-checked in code:
1. **`source_ip` is never written.** `alert_generator.generate_alerts` never
   sets `Alert.source_ip`, so the AbuseIPDB action always returns
   `no_source_ip` and IP-based correlation is dead code.
2. **Correlation merges unrelated users.** `correlation/engine._related`
   relates any two alerts with the same `event_type` within 15 minutes.
3. **JSON logs are ingested but no rule reads them.** The JSON pipeline writes
   `security-events-*`; the only rule reads `events-windows-*`.
4. **Only one detection rule** (`lateral_movement.yaml`).
5. **Frontend has no "Analysis" route** despite the README.
6. **Search cluster defaults are development-only** (security disabled, ports
   published in `docker-compose.yml`).

These are correctness issues in existing features. They should be fixed in a
separate, reviewable change, because the user asked to preserve existing
behaviour.

### 1.4 Integration points for the new modules
- **Backend routing:** `app/main.py` includes routers; new routers plug in the same way.
- **Persistence:** `app/database/base.py` + `app/models/*`; new tables via
  `create_all()` plus the idempotent `database/migrate.py` runner.
- **Auth:** `app/auth/dependencies.get_current_user`.
- **Audit:** `app/services/audit.record` (writes `audit_logs`; the `entity_type`
  enum must be extended for `file` and `url` entities, which is an enum change
  and needs a migration step).
- **Local telemetry pivots:** the existing `es_client` (`app/database/elasticsearch.py`)
  already queries OpenSearch; pivots can reuse it.
- **Frontend:** `App.jsx` routes, `Sidebar.jsx` nav, `services/api.js` client.

## 2. Phase 2: Design

### 2.1 Provider constraints (checked this session, see caveats)
| Provider | Use | Constraint found | Confidence |
|---|---|---|---|
| VirusTotal API v3 | hash/URL/domain/IP reports; optional upload | Public API is non-commercial/academic; ~4 requests/min; daily quota reported as 500 by secondary sources | Rate/terms partly verified; daily quota **unverified** |
| MalwareBazaar (abuse.ch) | hash lookup (`get_info`) | Requires a free `Auth-Key` header on every request | Key requirement verified from official docs |
| AlienVault OTX | indicator general info | Key is not required for general indicator data; a key is free from an account | Partly verified; key policy to re-check before shipping |
| urlscan.io | search prior scans; submit scans | `API-Key` header; **public visibility is the default on submission** and public scans are visible to everyone | Verified from official docs; default visibility must be overridden |
| AbuseIPDB | IP check | Already integrated | Existing |

Design consequences:
- Every provider is optional and reports `not_configured` when its key is missing.
- Only **hashes** are sent to providers by default. File upload to VirusTotal
  requires explicit per-file user consent and is shown as a separate action.
- urlscan submissions are always sent with `visibility=unlisted` (or private
  where the plan allows), never public by default.
- Cache lookups in the database with a time limit (planned: 24 h), to respect quotas.

### 2.2 Target architecture
- **Backend:** new package `app/analysis/` (pure logic) plus planned
  `app/services/intel/` (provider gateway), `app/api/analysis.py` (routes),
  `app/models/analysis.py` (tables).
- **Storage:** quarantine directory outside the web root, mode `0o600`, no
  execute bit, retention via `FILE_RETENTION_DAYS`.
- **Background work:** the analysis runs in a worker thread (`asyncio.to_thread`)
  with a timeout; a crash produces `status=failed`, never a 500 for the whole API.
- **Frontend:** pages `File Analysis`, `URL Analysis`, `Threat Intel Search`,
  `Analysis History`, plus the sidebar entries from the brief.

### 2.3 Planned database tables (none created yet)
`file_analyses`, `url_analyses`, `intel_cache`, `analysis_links` (links an
analysis to an incident), `analysis_notes`. The existing `audit_logs` and
`investigation_notes` are reused where the entity is an incident.

## 3. Implementation status

| Item | Status | Where / test |
|---|---|---|
| Streaming MD5/SHA-1/SHA-256 with size cap | **Implemented** (offline) | `app/analysis/hashing.py`; `tests/test_analysis_offline.py` |
| Magic-byte identification + extension mismatch | **Implemented** (offline) | `app/analysis/filetype.py` |
| PDF byte-level indicator scan (JS, OpenAction, Launch, EmbeddedFile, XFA, URI) | **Implemented** (offline, limited: compressed object streams not inspected) | `app/analysis/static.py` |
| ZIP/OOXML inspection (entries, executables, traversal, ratio limits, VBA presence) | **Implemented** (offline; macro auto-exec **not** verified) | `app/analysis/static.py` |
| Explainable scoring with capped factors and bands | **Implemented** (offline; weights are untuned starting values) | `app/analysis/scoring.py` |
| SSRF rules: scheme, credentials, ports, host, IP-literal and DNS-resolved public-address checks | **Implemented** (offline; DNS injected in tests) | `app/analysis/ssrf.py` |
| Upload endpoint, quarantine store, DB tables | Not started | — |
| Fetcher for URLs (connect-to-validated-IP, redirect re-validation, timeouts, size cap) | Not started | — |
| Provider gateway: VirusTotal, MalwareBazaar, OTX, urlscan, AbuseIPDB | Not started | — |
| RDAP, DNS A/AAAA, TLS certificate retrieval | Not started | — |
| OpenSearch local-context pivots | Not started | — |
| PDF / JSON report generation | Not started | — |
| Frontend pages | Not started | — |
| Documentation of the API / env vars | Not started (env vars for the features above will be added to `backend/.env.example` as they are implemented) | — |

## 4. Verification

```bash
cd backend
JWT_SECRET_KEY=test-only-secret-for-local-pytest python -m pytest -q
```

At the time of writing: **65 passed** (20 pre-existing + 45 new offline tests).

## 5. Open decisions for the team
1. Confirm the VirusTotal account type (public vs premium). Public-API use is
   non-commercial; a college project should state this in the report.
2. Choose the daily cap on URL fetches and on provider calls.
3. Confirm whether to fix the Section 1.3 correctness gaps first (recommended)
   or keep them as a separate change.
