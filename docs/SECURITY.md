# Security

This platform handles untrusted files, URLs and security data. The controls below are
implemented in code and covered by tests unless marked otherwise.

## Files
- **Never executed.** Uploaded bytes are parsed only. No archive entry is extracted to
  disk, and no macro is run. YARA and oletools read data; they do not execute it.
- **Quarantine storage.** Files are written to `QUARANTINE_DIR` (default `backend/quarantine`,
  git-ignored) with directory mode 0700 and file mode 0600. Stored names are random hex
  tokens. The user's name is only metadata, and it is sanitised (no path separators,
  control characters or length abuse). Tests: `test_pivot_reports_quarantine.py`.
- **Size and type limits.** The extension must be on the allow-list (415 otherwise).
  The size limit is enforced while streaming, and a partial file is deleted (413). Empty
  files are refused (400).
- **Retention.** Bytes are deleted after `FILE_RETENTION_HOURS` by the scheduler, and the
  analysis record and report are kept. Deleting an analysis removes its bytes at once.
- **Step timeouts.** Each static step runs under `ANALYSIS_STEP_TIMEOUT_SECONDS`. A step
  that times out is recorded as `timeout`, and the analysis becomes `partial`.
- **Malformed input.** Parsers return a `parse_error` rather than raising. Tests cover
  malformed PE, corrupt ZIP, and non-Office documents in an Office container.

## External submission
- Only **hashes** are sent to providers automatically, and only when
  `PROVIDER_HASH_LOOKUP_ENABLED=true`.
- Sending a **file** (VirusTotal upload) or a **URL** (urlscan.io submission) requires an
  explicit consent flag on every call (`422` without it). The UI shows a warning first.
- urlscan submissions use `URLSCAN_VISIBILITY`, which defaults to `unlisted`.

## URLs and SSRF
- Scheme must be http or https. Credentials, non-default ports, over-long input and
  control characters are rejected before any network activity.
- Every resolved address must be public. Private, loopback, link-local, multicast,
  reserved, unspecified, CGNAT and benchmarking ranges are blocked, including IPv4-mapped
  IPv6. Any single non-public record blocks the host.
- **Pinned connections.** The fetcher connects to an already-validated IP and uses the
  hostname only for the Host header and TLS verification. This blocks DNS rebinding.
- **Every redirect is re-validated** before it is followed, and the hop limit is enforced.
- GET only. No cookies, credentials, browser or JavaScript execution. Response bodies are
  read up to `URL_MAX_BODY_BYTES`. There are connect/read timeouts and an overall deadline.
- Tests (`test_url_ssrf.py`): loopback, cloud metadata (169.254.169.254), private DNS
  answers, redirects to private or non-HTTP targets, redirect loops, mixed DNS answers,
  TLS mismatch, timeouts, and a real loopback transport test for Host and body limits.

## Authentication, authorisation, rate limiting
- All analysis routes require a JWT. Analysis records are owner-scoped. Another user's id
  returns **404**, not 403, so existence is not revealed.
- Analysis submissions are rate-limited per user (`ANALYSIS_SUBMISSIONS_PER_MINUTE`).
  The login limiter is unchanged.
- Provider calls are rate-limited client-side (minimum interval and daily quota per
  provider). These limiters are per process.

## Secrets
- Provider keys are read from environment variables only. `GET /api/v1/providers` returns
  configured status and the variable name, never the value (test:
  `test_providers_endpoint_reports_status_and_never_returns_key_values`).
- No key is included in any API response, report, log message or frontend bundle.
- `.env` is git-ignored. `.env.example` contains placeholders only.
- The test suite sets a non-secret JWT key for the test process only.

## Outputs
- Reports are generated from stored data. Untrusted text (file names, URLs, notes) is
  XML-escaped before it reaches ReportLab, so it cannot inject markup (test:
  `test_analysis_pdf_renders_and_escapes_untrusted_text`).
- The UI renders analysis text as React text, not HTML.
- Every report states its limitations and that no result proves a file or URL is safe.

## Audit
- Uploads, URL and search submissions, notes, incident links, external submissions,
  report downloads, reruns and deletions are written to the existing `audit_logs` table
  with the authenticated actor's username.

## Known gaps (not implemented)
- No CSRF token: the API uses bearer tokens in the Authorization header, not cookies.
- In-process rate limiters and caches reset on restart and are not shared between
  instances.
- No malware sandbox. Dynamic analysis is out of scope.
- Log search accepts Lucene query syntax from analysts. It is read-only and limited to the
  log index patterns, but a broad query can still be expensive.

## Search engine (OpenSearch)
- The local development container runs with `DISABLE_SECURITY_PLUGIN=true` and publishes port
  9200. Anyone who can reach that port can read and write indices. Use it only on a
  development machine.
- Production must run OpenSearch with its security plugin (users, roles, TLS) on a private
  network. Give the backend and Logstash only the credentials they need, through
  `OPENSEARCH_HOST` and the Logstash output settings.
