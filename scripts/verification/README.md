# Verification and demonstration tooling

These scripts exercise the **running** platform (Compose services plus the backend and frontend),
through the public API and a headless browser. They are not unit tests; the unit and integration
tests are in `backend/tests/` and are run with pytest.

## Setup

```bash
docker compose up -d postgres opensearch logstash
docker compose --profile app up -d --build backend     # backend in a container, on :8000
docker compose exec backend python -m app.database.migrate
docker compose exec backend python -m app.auth.create_user analyst1 "<password-1>"
docker compose exec backend python -m app.auth.create_user analyst2 "<password-2>"
cd frontend && npm ci && npm run dev                    # frontend on :5173
export ANALYST1_PASSWORD="<password-1>" ANALYST2_PASSWORD="<password-2>"
```

Passwords come from environment variables; nothing is stored in the repository.

## Scripts

| Script | What it checks | Live services | Mocks |
|---|---|---|---|
| `make_fixtures.py` | Creates harmless test files in `.fixtures/` (git-ignored). No malware, no executable code. | none | none |
| `soc_scenario.py` | Sends synthetic firewall, DNS, proxy, Windows and JSON events through the real Logstash inputs (UDP 5001–5004, TCP 5000). Includes attack traffic and benign traffic. | Logstash, OpenSearch | none |
| `reset_and_seed.sh` | Clears demo SOC data (events, alerts, incidents, notes, audit) and reseeds the scenario, then runs one detection cycle in the backend container. Users and analyses are kept. | all | none |
| `verify_soc_workflow.py` | Assignment, status transitions (including an illegal one), notes, incident workflow, audit trail, auth on protected routes. | backend, Postgres | none |
| `per_rule.py` | Each of the eight detection rules in isolation, then benign-only traffic (must produce zero alerts). | Logstash, OpenSearch, Postgres | none |
| `verify_files.py` | Upload validation (empty, unsupported, oversized), magic-byte type, hashes, static analysis, factors, scores, reports, history, ownership, deletion. | backend, Postgres | none |
| `verify_urls.py` | URL rejection cases (no network), normalisation, DNS, TLS, redirects, RDAP, lookalike detection, DNS failure. | backend, network | none |
| `verify_ti.py` | Threat-intelligence search: input validation, detection of IP / domain / URL / MD5 / SHA-1 / SHA-256, OpenSearch pivots, related alerts, history, "never clean without evidence". | backend, OpenSearch | none |
| `verify_ownership_retention.py` | Other users cannot see, change, rerun or link someone else's URL or search analysis; retention purge removes bytes but keeps the report. | backend | none |
| `verify_providers.py` | Provider behaviour: detections, not-found, timeouts, quota responses, cache, urlscan visibility, consent gates for external submission. **Mock-backed**, see below. | backend | **mock provider server** |
| `mock_providers.py` | HTTP server that imitates provider responses for the tests above. **Not a real provider.** | none | — |
| `ui_e2e.js` | Browser workflow: every sidebar route, login, uploads, URL analysis, search, history, reports, alert and incident actions, log search, logout. Checks for console errors and failed API calls. | frontend, backend | none |

`run_all.sh` runs the API-key-free suite in order and finishes with a reseed, so the demo data is
ready to browse. Run `verify_providers.py` separately, as described below. Run `ui_e2e.js` after the
reseed, because `per_rule.py` clears the SOC data between rules.

## Running the provider checks (mock-backed)

These checks prove that the provider client code works over real HTTP. They do **not** prove
what a real provider returns today.

1. Generate fixtures and start the mock with the known hashes:
   ```bash
   python3 make_fixtures.py
   python3 mock_providers.py "$(cat .fixtures/known_sha.txt)" "$(cat .fixtures/slow_sha.txt)" &
   ```
2. In `backend/.env` (local, git-ignored) set a dummy key and point the URL at the mock, for
   example `VIRUSTOTAL_API_KEY=mock-vt-key` and `VIRUSTOTAL_API_URL=http://<docker-gateway-ip>:8099/vt/api/v3`.
   Do the same for MalwareBazaar, OTX and urlscan (see `mock_providers.py` for the paths).
3. Recreate the backend: `docker compose --profile app up -d --force-recreate backend`.
4. Run `python3 verify_providers.py`, then restore empty keys and recreate the backend again.

## Notes for reviewers

- The login limiter counts failed attempts per client IP for five minutes. Repeated wrong
  passwords from one machine block all logins from that machine for that time.
- Submissions are limited to 20 per user per minute. The scripts back off on HTTP 429.
- Expected output: all checks print `PASS`. Any `FAIL` line names the check that did not hold.

## Mobile layout

`ui_mobile.js` loads every sidebar route at a 390 px phone viewport and fails if any page scrolls
sideways or throws a page error. Run it the same way as `ui_e2e.js`.
