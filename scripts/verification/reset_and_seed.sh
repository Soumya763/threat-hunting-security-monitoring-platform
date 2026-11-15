#!/bin/bash
# Clears demo SOC data (events, alerts, incidents, notes, audit) and reseeds the synthetic scenario.
# Users and analyses are kept. Runs against the local Compose stack only.
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE/../.."
curl -s -X DELETE "localhost:9200/events-*" >/dev/null
docker compose exec -T postgres psql -U postgres -d threat_hunting -qc \
  "TRUNCATE alerts, incidents, investigation_notes, audit_logs RESTART IDENTITY CASCADE;" 2>/dev/null
python3 "$HERE/soc_scenario.py"
docker compose exec -T backend python -W ignore -c "from app.scheduler import _run_cycle_sync; _run_cycle_sync()"
echo "reseeded"
