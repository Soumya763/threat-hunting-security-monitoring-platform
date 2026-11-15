# Architecture

## Overview

One platform, one database per concern:

- **PostgreSQL** holds application records: users, alerts, incidents, notes, audit
  logs, analyses (file, URL and indicator), analysis notes and incident links, and the
  threat-intelligence response cache.
- **OpenSearch-compatible search** (the Elasticsearch 8.15.3 container in
  `docker-compose.yml`, accessed through `opensearch-py`) holds the ingested security
  events. Detection rules, Log Monitoring and local-context pivots read from it.
  Nothing application-level is written there.

```
Logstash pipelines ──► events-*, security-events-* ──► detection rules ──► alerts (PostgreSQL)
                            ▲                                                   │
                            │ read-only pivots                          correlation ──► incidents
                            │                                                   │
React SOC UI ──► FastAPI ───┼── analyses, notes, links, audit, reports ◄────────┘
                  │         │
                  │         └── intel_cache (PostgreSQL)
                  │
                  ├── quarantine/ (uploaded bytes, owner-only, retention purge)
                  └── providers: VirusTotal · MalwareBazaar · OTX · urlscan.io · AbuseIPDB · RDAP
```

## Modules

### Existing (kept, with fixes)
| Module | Purpose | Notes |
|---|---|---|
| `logstash/pipelines/*` | Parse firewall, Windows, proxy, DNS and JSON events | JSON now writes `events-json-*`; DNS source host and suspicious-label match fixed |
| `app/detection/*` | Load YAML rules, run aggregations, create alerts | Alerts record `entity_type`/`entity_key`; IP alerts write `source_ip`; user alerts take the top source IP from the rule |
| `app/correlation/engine.py` | Group alerts into incidents | Requires shared evidence (IP or entity) within 15 minutes; open incidents absorb related alerts within 60 minutes |
| `app/api/alerts.py`, `incidents.py`, `audit.py`, `auth.py` | Existing SOC APIs | Behaviour unchanged except added fields |
| `frontend/src/pages/*` (alerts, incidents, login) | Existing SOC screens | Unchanged, with the new sidebar |

### New
| Path | Responsibility |
|---|---|
| `app/analysis/hashing.py` | Streaming MD5/SHA-1/SHA-256 with a size cap |
| `app/analysis/filetype.py` | Magic-byte identification, extension allow-list and mismatch detection |
| `app/analysis/static.py`, `pe.py`, `office.py`, `image_scan.py` | Format-specific static analysis (PDF, ZIP/OOXML, PE via pefile, VBA via oletools, PNG/JPEG) |
| `app/analysis/strings_scan.py`, `yara_scan.py`, `yara_rules/` | Suspicious strings (ASCII and UTF-16) and bundled YARA rules |
| `app/analysis/scoring.py` | Explainable score, factors, classification |
| `app/analysis/ssrf.py` | URL policy and public-address enforcement |
| `app/analysis/fetch.py` | SSRF-hardened fetcher with pinned connections and per-hop validation |
| `app/analysis/dnsinfo.py`, `rdap.py`, `page.py`, `urlrules.py` | DNS A/AAAA, RDAP, passive HTML inspection, lookalike heuristics |
| `app/services/intel/*` | Provider clients, normalised results, cache, rate limits, gateway |
| `app/services/file_pipeline.py`, `url_pipeline.py`, `indicator_search.py` | Background workflows (queued → running → complete/partial/failed) |
| `app/services/quarantine.py` | Secure storage, size-limited streaming upload, retention purge |
| `app/services/pivot.py` | Read-only OpenSearch queries for local context |
| `app/services/reports.py` | JSON and PDF reports rendered from stored data |
| `app/services/analysis_store.py` | Owner-scoped queries, notes, links, audit |
| `app/api/analysis.py`, `platform.py` | Analysis, dashboard, log search, provider status, incident reports |
| `frontend/src/pages/` | File, URL, Threat Intel Search, Analysis (detail), History, Log Monitoring, Reports, Settings; updated Dashboard |

## Analysis lifecycle

1. The request is authenticated and rate-limited per user.
2. Inputs are validated before any work: extension and size for files, URL policy for
   URLs, indicator type for searches.
3. A row is written with status `queued`, and the route returns `202` with its id.
4. A background task moves it to `running`, runs each step under a timeout, and records
   every step's outcome.
5. The result is stored as JSON with a classification. Status becomes `complete`, or
   `partial` when a provider or step failed, or `failed` when the pipeline crashed.
6. The UI polls until the status is final. Reports are rendered from this stored result.

## Classification

| Level | Meaning |
|---|---|
| `critical` / `high` / `medium` / `low` | Score bands 75 / 50 / 25 / 1. Each point has a named reason. |
| `clean` | Score 0, at least one external source was consulted without a detection, and local checks completed. Displayed as "Clean - no known threat detected". This is not a safety guarantee. |
| `insufficient_evidence` | Score 0 but the evidence needed to call it clean is missing (no provider configured or reachable, or local checks incomplete). |

## Database changes

| Change | Type | Migration |
|---|---|---|
| `alerts.entity_type`, `alerts.entity_key` (+ indexes) | Columns | `app/database/migrate.py` (idempotent `ADD COLUMN IF NOT EXISTS`) |
| `analyses` (+ indexes on owner/created, owner/kind, risk, sha256, indicator) | New table | `create_all()` via `migrate.py` |
| `analysis_notes` | New table | `create_all()` |
| `analysis_incident_links` (unique analysis/incident) | New table | `create_all()` |
| `intel_cache` (unique provider/type/indicator) | New table | `create_all()` |
| `audit_logs.entity_type` now accepts `analysis` | Application enum only | none (VARCHAR column) |

Run `python -m app.database.migrate` once after pulling. It is safe to run repeatedly.
It was executed against a local PostgreSQL 16 instance during development, twice, with
the same result both times.

## Security summary

See [SECURITY.md](SECURITY.md).

## Known limitations

See the README, section "Status". The most important are: no live OpenSearch run was
possible in the development environment; provider calls are covered by stubbed tests
rather than live calls; the PDF inspection does not read compressed object streams;
PE and Office analysis report indicators, not verdicts; and the incident page does not
yet list linked analyses (the incident report does).
