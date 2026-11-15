# Setup, Docker and deployment

## Local development (verified path)

1. **Infrastructure** (PostgreSQL, OpenSearch, Logstash with the OpenSearch output plugin):
   ```bash
   # Linux hosts need this kernel setting for OpenSearch (not persistent across reboots):
   sudo sysctl -w vm.max_map_count=262144
   docker compose up -d postgres opensearch logstash
   curl http://localhost:9200/_cluster/health?pretty   # expect "status" : "green" (or yellow)
   ```
   Docker Desktop on Windows/macOS: give its Linux VM at least 4 GB of memory.
2. **Backend**:
   ```bash
   cd backend
   cp .env.example .env          # then set JWT_SECRET_KEY (see the file)
   python -m venv .venv && source .venv/bin/activate
   pip install -r requirements.txt
   python -m app.database.migrate   # creates tables and columns; safe to repeat
   python -m app.auth.create_user <username> <password>
   python -m uvicorn app.main:app --reload --port 8000
   ```
3. **Frontend**:
   ```bash
   cd frontend
   cp .env.example .env          # VITE_API_BASE_URL=http://localhost:8000
   npm ci
   npm run dev                   # http://localhost:5173
   ```
4. Open http://localhost:5173, sign in, and check the Dashboard status (API Connected).

OpenSearch is needed for Log Monitoring, local-context pivots and the detection rules. Without it the
platform still runs, and those features report that the search engine is unavailable.

## Docker (optional backend container; not built in this environment)

```bash
docker compose --profile app up --build
```
The `backend` service in `docker-compose.yml` uses `backend/Dockerfile` (build context is
the repository root, because detection rules are outside `backend/`). It reads
`backend/.env`. Its container paths: quarantine at `/app/quarantine`, rules at
`/threat_hunting_queries`.

Limitations: the image has not been built in this environment, and the Docker daemon
was not available. The frontend has no Dockerfile yet; build it with `npm run build` and
serve `frontend/dist` from any static host.

## Production checklist
- Set `JWT_SECRET_KEY` to a fresh random value, and keep `.env` out of version control.
- Set `CORS_ALLOWED_ORIGINS` to the exact frontend origin only.
- Run OpenSearch with its security plugin enabled (users, roles, TLS) on a private network. The
  repository's compose file sets `DISABLE_SECURITY_PLUGIN=true` and publishes port 9200 for
  local development only. Put credentials in `OPENSEARCH_HOST` (`https://user:pass@host:port`).
- Set `QUARANTINE_DIR` to a directory outside any web root, on a volume with backups
  disabled for uploaded samples if your policy requires it.
- Choose `FILE_RETENTION_HOURS` and `URLSCAN_VISIBILITY` deliberately.
- Add provider keys only if your use is permitted by each provider's terms.
- Do not deploy to a public URL without reviewing [SECURITY.md](SECURITY.md) and the known gaps.
