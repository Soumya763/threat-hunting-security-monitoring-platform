# Setup, Docker and deployment

## Local development (verified path)

1. **Infrastructure** (PostgreSQL, Elasticsearch-compatible search, Logstash, pgAdmin):
   ```bash
   docker compose up -d postgres elasticsearch logstash
   ```
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

The search service is needed only for Log Monitoring, local pivots and the Dashboard's
event counts. Without it the platform still works, and those features say they are
unavailable.

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
- Put the search service on a private network with authentication and TLS. The repository's
  default compose file has security disabled and publishes ports; that is development-only.
- Set `QUARANTINE_DIR` to a directory outside any web root, on a volume with backups
  disabled for uploaded samples if your policy requires it.
- Choose `FILE_RETENTION_HOURS` and `URLSCAN_VISIBILITY` deliberately.
- Add provider keys only if your use is permitted by each provider's terms.
- Do not deploy to a public URL without reviewing [SECURITY.md](SECURITY.md) and the known gaps.
