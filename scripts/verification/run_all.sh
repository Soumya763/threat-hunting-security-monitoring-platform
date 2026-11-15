#!/bin/bash
# End-to-end verification against the running Compose stack and the backend on :8000.
# Requires: docker compose services up (postgres, opensearch, logstash, backend --profile app),
# the two analyst accounts created, and the environment variables below. The provider keys
# in backend/.env must be EMPTY for the API-key-free run (the default).
set -euo pipefail
: "${ANALYST1_PASSWORD:?set ANALYST1_PASSWORD to the analyst1 account password}"
: "${ANALYST2_PASSWORD:?set ANALYST2_PASSWORD to the analyst2 account password}"
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"
python3 make_fixtures.py
./reset_and_seed.sh
python3 verify_soc_workflow.py
python3 verify_files.py
python3 verify_urls.py
python3 verify_ti.py
python3 verify_ownership_retention.py
python3 per_rule.py          # resets SOC data between rules
./reset_and_seed.sh          # leave the demo in its seeded state (8 alerts, 1 correlated incident)
echo "Browser workflow (needs the frontend dev server on :5173 and Playwright):"
echo "  cd frontend && ANALYST1_PASSWORD=... node ../scripts/verification/ui_e2e.js"
