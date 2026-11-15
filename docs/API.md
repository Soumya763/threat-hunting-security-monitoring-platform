# API reference

Base URL: `http://localhost:8000` (local). Interactive OpenAPI docs: `/docs`.

All routes except `/health`, `/api/v1/auth/login`, and the existing public reads of
alerts and incidents require `Authorization: Bearer <token>`. Analysis routes return
only records owned by the caller; another user's id returns **404**.

## Authentication
`POST /api/v1/auth/login`
```json
{ "username": "analyst1", "password": "<password>" }
```
→ `200` `{ "access_token": "<jwt>", "username": "analyst1" }`

## Submissions (all return `202` with the analysis summary, then run in the background)

### File
`POST /api/v1/files` (multipart form, field `file`)
```bash
curl -H "Authorization: Bearer $TOKEN" -F "file=@invoice.pdf" http://localhost:8000/api/v1/files
```
Errors: `415` unsupported extension · `400` empty file · `413` over `FILE_MAX_UPLOAD_BYTES` · `429` rate limit.

### URL
`POST /api/v1/urls`
```json
{ "url": "https://paypa1-secure.com/login", "submit_to_urlscan": false, "consent": false }
```
Errors: `422` for non-http(s), credentials, non-public or internal targets, or a urlscan
submission without `consent: true`.

### Indicator search
`POST /api/v1/indicators/search`
```json
{ "query": "8.8.8.8" }
```
Accepts an IPv4/IPv6 address, a domain, an `http(s)` URL, or an MD5/SHA-1/SHA-256 hash.
`422` for anything else.

Example `202` response from any submission:
```json
{
  "id": 12, "kind": "url", "indicator_type": "url",
  "indicator_value": "https://paypa1-secure.com/login", "display_name": "https://paypa1-secure.com/login",
  "status": "queued", "risk_level": null, "risk_score": null, "sha256": null,
  "file_size": null, "detected_type": null, "file_available": false, "external_submitted": false,
  "created_at": "2026-11-15T11:20:01+00:00", "completed_at": null, "error": null
}
```

## History and detail

`GET /api/v1/analyses?kind=file|url|indicator&risk=critical|high|medium|low|clean|insufficient_evidence&q=text&sort=created_at|risk_score&order=asc|desc&page=1&page_size=20`
```json
{ "items": [ { "id": 12, "kind": "url", "status": "complete", "risk_level": "high", "risk_score": 63, "...": "..." } ],
  "total": 1, "page": 1, "page_size": 20, "pages": 1 }
```
`page_size` ≤ 100. An unknown `risk` value returns `422`.

`GET /api/v1/analyses/{id}` returns the summary plus `result` (the full stored analysis:
`factors`, `providers`, `steps`, `recommendations`, `caveats`, and the kind-specific
findings), `retention_until`, `file_purged_at`, and `external_submission_at`.

Poll this endpoint while `status` is `queued` or `running`. Final values are `complete`,
`partial` (a provider or step failed or timed out), or `failed` (with `error`).

Score excerpt (the factor list explains every point):
```json
"result": {
  "score": 63, "classification": "high", "classification_label": "High risk",
  "factors": [
    { "code": "lookalike_domain", "label": "Possible brand lookalike domain", "points": 20,
      "reason": "The domain closely resembles 'paypal.com' but is not that brand's domain.", "evidence": {"brand_domain": "paypal.com"} },
    { "code": "login_form", "label": "Password field on the page", "points": 15, "reason": "..." }
  ],
  "caveats": ["A detection or a low score is a triage aid, not proof of maliciousness."],
  "recommendations": ["Do not enter credentials on this page.", "..."]
}
```

`DELETE /api/v1/analyses/{id}` → `204`. Removes the record, its notes and links, and the quarantined bytes.

`POST /api/v1/analyses/{id}/rerun` → `202`. Re-runs file, URL or search analysis. Returns `409`
if a file's bytes were purged by retention.

## Consent-gated external submission
`POST /api/v1/analyses/{id}/external-submission`
```json
{ "provider": "virustotal", "consent": true }
```
`provider` is `virustotal` (file analyses) or `urlscan` (URL analyses). `consent` must be
`true` (`422` otherwise). Returns the provider's outcome, which is `not_configured` when no key is set.

## Local context and reports
- `GET /api/v1/analyses/{id}/pivot` → live read-only OpenSearch search for the indicator.
  `result.status` is `ok` or `unavailable`. `unavailable` never means "no events".
- `GET /api/v1/analyses/{id}/report.json` → JSON report (download).
- `GET /api/v1/analyses/{id}/report.pdf` → PDF report (download).
- `GET /api/v1/reports/incidents/{incident_id}.json` / `.pdf` → incident report with its alerts,
  investigation notes and your linked analyses.

## Notes and incident links
- `GET /api/v1/analyses/{id}/notes`, `POST /api/v1/analyses/{id}/notes` with `{ "content": "..." }` → `201`
- `GET /api/v1/analyses/{id}/incidents`
- `POST /api/v1/analyses/{id}/incidents` with either `{ "incident_id": 5 }` or
  `{ "create_incident": true, "title": "Phishing wave", "severity": "high" }` → `201`
- `GET /api/v1/incidents/{incident_id}/analyses` (your analyses linked to the incident)

## Platform
- `GET /api/v1/providers` → configuration status per provider (never key values):
  `[{ "id": "virustotal", "configured": false, "environment_variable": "VIRUSTOTAL_API_KEY", "supports": [...], "limits": "..." }]`
- `GET /api/v1/platform/limits` → retention, size and fetch limits shown in the UI.
- `GET /api/v1/dashboard/summary` → alert and incident counts by severity and status, your analysis
  counts by type and risk, a 14-day alert trend, and the latest analyses and incidents.
- `GET /api/v1/logs/search?q=event_type:firewall_connection_denied&minutes=1440&size=50` → read-only
  event search. `503` when OpenSearch is unreachable.
- `GET /health` → `{ "api": "ok", "postgres": "ok", "opensearch": "unreachable" }`

## Rate limits
- Login: five failed attempts per client IP within five minutes, then `429`.
- Analysis submissions (files, URLs, indicator searches, reruns, external submissions): 20 per user
  per minute, then `429` with a retry message. Invalid submissions also count, because the check runs first.
- Provider calls: each provider has a client-side minimum interval and daily cap. A limited call is
  reported as `rate_limited`; it is never counted as a detection.

## Error format
Errors use FastAPI's `{ "detail": "..." }`. Messages are written for users and do not include
stack traces, keys or internal paths.
