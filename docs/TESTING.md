# Testing

## Backend

```bash
cd backend
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt
JWT_SECRET_KEY=test-only-secret-0123456789abcdef0123456789abcdef python -m pytest -q
```

The test suite needs no network, no PostgreSQL and no OpenSearch. `conftest.py` sets a
non-secret JWT key for the test process only.

| File | What it covers | Live services needed |
|---|---|---|
| `test_executor.py`, `test_threat_intel.py` | Existing rule execution and AbuseIPDB behaviour | none |
| `test_detection_rules.py` | Rule structure; every queried field is produced by a Logstash pipeline (static check) | none |
| `test_alerts_and_correlation.py` | `source_ip` population, duplicate suppression, correlation on evidence, attachment to open incidents | none (SQLite) |
| `test_file_core.py` | Hashing vectors, magic bytes, PDF/ZIP/PE/PNG parsers, YARA, scoring and classification | none |
| `test_file_analysis.py` | End-to-end file analysis on synthetic files | none |
| `test_url_ssrf.py` | URL policy, DNS policy, redirect re-validation, DNS rebinding pin, TLS and timeout handling, a real loopback transport test | none |
| `test_url_analysis.py` | Lookalike detection, page inspection, end-to-end URL scoring with stubbed I/O | none |
| `test_providers.py` | Provider configuration, normalisation, HTTP error mapping, retries, cache, rate limits, AbuseIPDB adapter | none (`requests` replaced) |
| `test_pivot_reports_quarantine.py` | Pivot escaping and unavailable handling, PDF escaping, quarantine permissions, size limits, retention purge | none (SQLite, fake ES) |
| `test_api_flow.py` | Login, existing alert workflow, file/URL/search submission, owner isolation, filters, consent gates, notes and links, audit trail, reports, rate limit, provider secrecy, dashboard, log search `503` | none (SQLite, stubbed I/O) |

Current result: **197 passed** (20 pre-existing plus new tests).

### Integration checks run manually (not part of pytest)
- `python -m app.database.migrate` applied twice against a local PostgreSQL 16 database. The second run was a no-op.
- The FastAPI app was started with uvicorn against that PostgreSQL database. `/health` returned `postgres: ok`.
- A headless browser logged in, uploaded a synthetic PDF with a JavaScript action, and waited for
  the result. The URL and search flows also completed. The log page showed an honest
  "unavailable" message because no OpenSearch was running. The only console error was the
  expected 503 from that search call.

### Not verified in this environment
- OpenSearch / Elasticsearch queries: the pivot and log search code is covered only with fake clients.
  Run `docker compose up -d` and then search for a known event to verify.
- Live provider calls (VirusTotal, MalwareBazaar, OTX, urlscan.io, AbuseIPDB, RDAP). Use real keys
  in a private `.env` and check one indicator per provider.
- Docker image build (`docker compose --profile app up --build`).

## Frontend

```bash
cd frontend
npm ci
npm test          # node:test unit tests for formatting helpers (5 tests)
npm run build     # production build
```

Browser checks were run against the dev server with Playwright: login, file upload and
result, URL analysis and result, search and result, history, log search, reports,
settings, and a 390 px viewport with no horizontal page scroll on the pages checked.
