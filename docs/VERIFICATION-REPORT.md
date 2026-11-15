# End-to-end verification report

Scope: the running platform (PostgreSQL, OpenSearch, Logstash, FastAPI backend, React frontend)
verified through the API and a headless browser, with synthetic data and harmless test files.
Test type and status of every claim are listed in [TESTING.md](TESTING.md).

## 1. Infrastructure

| Service | Status | Evidence |
|---|---|---|
| PostgreSQL 16 (Compose service `postgres`) | healthy | `docker compose ps`; health reports `postgres: ok` |
| OpenSearch 2.19.7 (service `opensearch`) | healthy; cluster `yellow` | Health check passes. Yellow is expected on one node (replica shards cannot be placed). |
| Logstash 8.9 with OpenSearch output (service `logstash`) | running, 5 pipelines started | All pipelines connected to `http://opensearch:9200` |
| FastAPI backend (service `backend`, profile `app`) | healthy | Built from `backend/Dockerfile`; `/health` → `{"api":"ok","postgres":"ok","opensearch":"ok"}` |
| pgAdmin (service `postgres_admin`) | running | Was restarting; fixed (section 4) |
| Frontend (Vite dev server) | serving, API base `http://localhost:8000` | Matches the published backend port |

Health accuracy was checked by stopping OpenSearch: `/health` reported `opensearch: unreachable`,
log search returned HTTP 503, pivots reported `unavailable` (not "no events"), and the alerts API
kept working. Restarting OpenSearch returned `/health` to `ok`.

## 2. Authentication

Verified: valid login issues a token; wrong and unknown users get the same generic 401; a
malformed body gets 422; every protected route returns 401 without a token; a tampered signature,
an `alg: none` token, a garbage token and an expired token (signed with the real key) all return
401; the login limiter returns 429 after five failed attempts from one client.

Observed behaviour, not changed: the login limiter is per client IP for five minutes, so several
analysts behind one NAT address can lock each other out. See limitations.

## 3. Existing SOC workflow

- Logstash parsed and indexed firewall, DNS, proxy, Windows and JSON events (109 events; per-index
  counts match what was sent).
- Detection cycle created alerts in PostgreSQL. Source IP populated where applicable (for example
  `10.66.1.10` on the brute-force alert).
- Correlation: the three alerts sharing source IP `10.66.1.10` became one incident. Unrelated
  alerts stayed separate.
- Analyst workflow (19/19): assignment; illegal transition rejected with 400; acknowledge, close and
  reopen with notes; incident assignment and status; investigation note; audit records with the
  correct actor; audit and notes require login.
- Alert and incident pages were driven in the browser: rows open, notes save and show.

### Detection rules (each tested alone, then benign traffic)

| Rule | Isolated result | Negative case |
|---|---|---|
| Brute force, repeated failed logins for one account | fires once, entity `bf-solo.user`, source IP populated | no other rule fires |
| Password spraying, one IP across accounts | fires once, entity IP, source IP populated | no other rule fires |
| Lateral movement, one user on several hosts | fires once, entity user, source IP populated | no other rule fires |
| Network scan, denied connections to many ports | fires once, entity IP, source IP populated | no other rule fires |
| Remote administration or SMB allowed | fires once, entity IP, source IP populated | no other rule fires |
| Suspicious DNS, domain matches keywords | fires once, entity domain | no other rule fires |
| Web enumeration, burst of HTTP errors | fires once, entity IP, source IP populated | no other rule fires |
| Application auth failures, JSON producer | fires once, entity user, source IP populated | no other rule fires |

Benign-only traffic, sent below every threshold (normal login, two-host login, allowed HTTPS,
few denials, normal DNS, normal and few-error proxy traffic, few auth failures), produced
**zero alerts**. Results: 22/22 checks.

## 4. Defects found and fixed

Each fix has a regression test unless noted.

| # | Defect | Root cause | Fix | Regression test |
|---|---|---|---|---|
| 1 | A DOCX containing a macro project scored 0 | The macro factor was added only when the VBA parser succeeded. The dummy project in the test file cannot be parsed, so the container evidence was lost. | The macro factor comes from the container (`vbaProject.bin`); parser results only add auto-run and suspicious-function factors, with no double count. | `test_macro_container_is_scored_even_when_vba_parser_cannot_read_it`, `test_macro_factor_is_not_double_counted…` |
| 2 | A domain with **no threat provider configured** was reported "Clean - no known threat detected" | RDAP (registration data) answered OK and counted as a consulted source. RDAP is not a threat source. | Only threat-intelligence sources count toward "clean". | `test_registration_data_alone_never_makes_an_indicator_clean` |
| 3 | A host that does not resolve produced a "complete" analysis | The DNS step was marked complete when the lookup returned no error, even with no public address. | DNS step fails when no public address is found; analysis becomes partial. | `test_unresolvable_host_marks_dns_step_failed_and_analysis_partial` |
| 4 | TLS certificate details were always empty for every HTTPS URL | The request sends `Connection: close`, so `http.client` discards the socket once the response is read. The certificate was read after that. | The verified certificate is captured during the handshake. | `test_tls_certificate_details_survive_connection_close` (real TLS handshake with a throwaway certificate) |
| 5 | Inside the container, every HTTPS check failed certificate verification on intercepting networks | The image had no trust bundle containing the local CA. | `backend/certs/` (git-ignored) is combined with the public roots into one bundle; `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE` and `PIP_CERT` point at it. | Verified live: TLS to `example.com` and RDAP succeed in the container. |
| 6 | TLS failure text said "self-signed" for every intercepted chain | The message mapping was too narrow. | Message describes the chain problem; mapping tests added. | `test_tls_problem_messages_describe_the_actual_failure` |
| 7 | Docker image build failed behind a TLS-intercepting proxy | Same as 5, at build time. | Build uses the CA bundle when present; no CA is committed. | Verified: image builds. |
| 8 | The Dockerfile set `PIP_CERT` to a file that may not exist on clean networks | First version set the variable globally. | Scoped to the install step only. | Verified: build on this host. |
| 9 | pgAdmin restart loop | pgAdmin tried to bind an IPv6 address unavailable to the container network. | `PGADMIN_LISTEN_ADDRESS=0.0.0.0`. | Verified: pgAdmin running and serving. |
| 10 | Failed OpenSearch requests printed a full stack trace each time | The library logs a traceback per failed request; the application already logs each failure once. | The library logger is set to ERROR. | `test_opensearch_client_logs_are_quieted…` |
| 11 | Docker build context included secrets and local data | No `.dockerignore`. | `.dockerignore` excludes `.env` files, `node_modules`, uploads, build output. | Verified: build context size and contents. |

Harness problems found while verifying (not product defects, corrected in the scripts): a
verification script missing `import os`; a seed script that failed when run from another
directory; tests that did not back off on the per-user submission limit (20/min); and
selectors that matched the wrong dropdown or read text before the page was ready. Each was
corrected, and the corrected run was repeated.

Checked and found correct (no change needed): the AbuseIPDB check refuses private addresses
(`private_ip`), as designed; expired and tampered tokens are rejected; the upload size limit
returns 413 and leaves no partial file; an empty file returns 400; the file-type mismatch is
flagged; the lookalike domain is detected; the SSRF refusals return 422 before any network
activity.

## 5. File analysis

Fixtures are harmless and generated by `scripts/verification/make_fixtures.py`: a normal PDF, a
PDF with JavaScript and automatic-action names as text, a ZIP with an executable-named text entry
and a traversal name, a DOCX, a DOCX with a dummy macro project, PNG and JPEG images, a PNG with
appended bytes, a header-only PE-format structure, a PE named `.pdf`, a malformed PDF, an empty
file, a 33 MB file, and a shell script. Results: 118/118 checks, covering magic-byte type, SHA-256
against the local hash, factors, scores, classification (never "clean" without a consulted source),
analysis status, PDF and JSON reports (the PDF opens in `pdfinfo`, the JSON matches the stored
score), history filters and pagination, ownership, deletion and retention.

## 6. URL analysis

Rejected with 422 without any network activity: non-URL text, `htp:/`, credentials, `ftp:`,
`javascript:`, `file:`, port 8443, `localhost`, `127.0.0.1`, `192.168.1.1`, the cloud metadata
address, `[::1]`, empty input, and a space in the host.

Accepted and analysed: `HTTPS://Example.COM:443/Docs/Page?q=1#section` normalised to
`https://example.com/Docs/Page?q=1`; DNS A records public; TLS verified with the certificate
expiry computed; redirect chain recorded; RDAP data returned; providers reported as not
configured (not invented); classification not clean. Lookalike domains `paypa1-secure-login.invalid`
and `login-micros0ft.test` detected. `.invalid` and `.test` never resolve, so the DNS failure is
reported and the analysis is partial.

## 7. Threat intelligence search

Invalid input refused (422) for free text, a loopback URL, an FTP URL, an empty string, a
2049-character string and a URL with credentials. Accepted and typed correctly: IPv4, IPv6,
domain, URL, MD5, SHA-1, SHA-256. With no keys, every provider reported `not_configured` and the
classification was `insufficient_evidence`. Live OpenSearch pivots: `10.66.5.50` returned 3 firewall
events and one related alert; `c2-beacon.evil.test` returned DNS events and a related alert;
`example.com` returned 32 proxy events; a file hash placed in a JSON log line through Logstash was
found by the pivot, and the file's own earlier analyses were listed. A public IP with no events
returned an honest zero.

Rate limiting: the search endpoint returned 429 when the per-user limit was exceeded; the client
backs off and retries. Provider rate limits and timeouts are covered by the provider checks.

## 8. Analysis history and reports

Verified: file, URL and indicator analyses appear in history; type and risk filters, search by
name, sort by score and date, pagination; reopening an earlier analysis; PDF and JSON reports
download and are valid; the other analyst cannot read, download, annotate, rerun, link or pivot
another user's analysis (404 in each case).

## 9. OpenSearch integration

Live: indices are created automatically on first write (no custom index templates); all eight rules run against live
indices; pivots and log search return real counts; health reflects OpenSearch being stopped and
restarted. The development container runs with the security plugin disabled (see SECURITY.md).

## 10. Without API keys (mandatory run)

The default `backend/.env` has empty keys, and the backend reports all providers as not configured
except RDAP, which needs no key. With no keys: the full file-analysis suite passed (118/118), the
URL suite passed (31/31), threat-intel search accepted and processed every indicator type (62/62),
the SOC workflow passed (19/19), and the browser workflow passed (39/39). Reports generate normally.

## 11. Frontend and browser

Headless Chromium, real login form, real API. Every sidebar route renders content (not blank).
Dashboard counts match the database. Workflows completed: file upload and result, PDF and JSON
downloads from the result page, analyst note on a file result, internal-log pivot, URL analysis,
private-address URL refusal shown to the user, IP search, history filter, pagination and reopen,
report download from the reports page, settings showing OpenSearch status, alert and incident
detail, incident note, log search returning indexed events, logout, and the protected-route
redirect. No console errors. The only failed API response is the deliberate 422 for the
private-address URL. Mobile (390 px): all ten routes show no horizontal scrolling and report no
errors.

Error states: with the backend stopped, Dashboard and Alerts show "Unable to connect to the
security API" with a Retry button, and Settings shows "Cannot reach the security API" with Retry.
Empty states are used for empty history and log results.

## 12. Limitations

- Live provider responses are **not verified**. Provider code is verified over HTTP against a
  labelled mock. Keys are needed for a real check.
- A redirect from a public host to a private address is **not verified live** in this environment.
  It is covered by controlled tests and the loopback transport test.
- VBA auto-execution and real PE import/packing indicators are **not verified** on real samples.
- The login limiter is per client IP. Analysts behind one NAT address can lock each other out for
  five minutes after failed attempts. Not changed in this round.
- Scoring weights are starting values, not tuned on a labelled dataset.
- The development OpenSearch container has the security plugin disabled; production needs it enabled.
- Browsers tested: Chromium only. Docker tested on Linux; Windows and macOS hosts not tested.
- Single-node OpenSearch reports `yellow` by design; replica shards are unassigned.
