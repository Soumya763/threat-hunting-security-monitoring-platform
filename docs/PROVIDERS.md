# Threat-intelligence providers

Every provider is optional. Without a key it reports **not configured** and the platform
continues with local analysis. A "clean" classification requires at least one consulted
source, so an unconfigured platform reports *insufficient evidence*, never "clean".

## Summary

| Provider | Used for | Key | Status in this release | Limits and terms (verify before use) |
|---|---|---|---|---|
| VirusTotal API v3 | File hash, URL, domain, IP reputation; optional file upload (consent) | `VIRUSTOTAL_API_KEY` | Live API reached: a test key was rejected as expected. **A valid key has not been tested yet.** | Public API is for non-commercial and academic use. About 4 requests/minute and a daily quota (the 500/day figure came from secondary sources). Commercial use needs the Premium API. Set `VIRUSTOTAL_MIN_INTERVAL_SECONDS` and `VIRUSTOTAL_DAILY_QUOTA` to match your account. |
| MalwareBazaar (abuse.ch) | File hash lookup (MD5/SHA-1/SHA-256) | `MALWAREBAZAAR_AUTH_KEY` | Client implemented; not called live | Free Auth-Key is required on every request. Fair-use limits apply; the client's own limit (1 request/second) is a conservative placeholder, not a published quota. |
| AlienVault OTX | Indicator general info (IP, domain, URL, file hash) | `OTX_API_KEY` | Client implemented; not called live | Free account and key. The client calls OTX only when a key is set. Confirm current rate limits before relying on them. |
| urlscan.io | Domain search of prior scans; URL submission (consent) | `URLSCAN_API_KEY` | Client implemented; not called live | API key in the `API-Key` header. Submissions default to `unlisted`; public scans are visible to everyone. Per-minute, hourly and daily quotas apply. |
| AbuseIPDB | IP reputation for public addresses | `ABUSEIPDB_API_KEY` | Existing integration, reused via an adapter | Free plan has a daily check limit. Private addresses are never sent. |
| RDAP (default `rdap.org`) | Domain registration date, registrar, name servers | none | Implemented; live call not made in development | Registry-specific rate limits. The domain name is sent to the RDAP service. |

"Not called live" means the code is covered by tests that replace the network with stubs.
Those tests check response mapping and error handling. They do not prove that the
provider's current API behaves exactly as coded. Run **Settings → Check now** with your own
key (see below) before presenting results.

## Getting keys (sign-up pages)

Create the account, copy the key, and set it in the backend environment (Render's
Environment tab, or `backend/.env` locally). Never paste keys into the browser, GitHub or docs.

| Provider | Sign up / key page | Variable |
|---|---|---|
| VirusTotal | https://www.virustotal.com/gui/join-us (key is on your profile after sign-up) | `VIRUSTOTAL_API_KEY` |
| AlienVault OTX | https://otx.alienvault.com/ (key under API settings: https://otx.alienvault.com/api) | `OTX_API_KEY` |
| urlscan.io | https://urlscan.io/user/signup (key under profile: https://urlscan.io/user/profile) | `URLSCAN_API_KEY` |
| AbuseIPDB | https://www.abuseipdb.com/register then https://www.abuseipdb.com/account/api | `ABUSEIPDB_API_KEY` |
| MalwareBazaar (abuse.ch) | https://auth.abuse.ch/ (Auth-Key) | `MALWAREBAZAAR_AUTH_KEY` |

Sign-up pages and terms change. Check them before you create an account.

## Provider checks (Settings)

- **Check now** makes one benign lookup per provider: `example.com` for VirusTotal, OTX and
  urlscan; the EICAR test-file hash for MalwareBazaar; `8.8.8.8` for AbuseIPDB.
- It is a lookup only. It never submits a URL or file, and it uses no consent.
- Results: **Working** (key accepted and provider answered), **Not working** (rejected key,
  timeout or provider error), or **Inconclusive** (rate limited). Keys are never returned.
- Backend endpoint: `POST /api/v1/providers/{id}/check` (login required).

## How failures are handled

- Each provider runs independently. A crash, timeout, rejected key or rate limit in one
  provider becomes that provider's own result. Other providers still answer.
- A failed provider is **never** read as "no detections". Results show
  "Checked successfully: X of Y applicable providers. Failed: Z. Not configured: W."
- A result is called **clean** only when at least one provider answered and no applicable
  provider failed. Otherwise it is **unknown (insufficient evidence)**.
- Unknown results show **Not scored** rather than a score of 0. A 0 score always means the
  evidence was checked and found nothing, and the clean rule above still applies.

## What is sent to whom

| Action | Sent to a provider | Automatic? |
|---|---|---|
| File analysis | SHA-256 (also MD5/SHA-1 in the analysis result) to VirusTotal, MalwareBazaar, OTX | Yes, unless `PROVIDER_HASH_LOOKUP_ENABLED=false`. The file itself is **not** sent. |
| File → VirusTotal upload | The file bytes | **No.** Explicit consent per call. |
| URL analysis | The normalised URL and host to VirusTotal and OTX; host to urlscan.io search and AbuseIPDB (for resolved public IPs); registrable domain to RDAP | Yes, for lookups |
| URL → urlscan.io submission | The URL, with the configured visibility | **No.** Explicit consent per call. |
| Indicator search | The indicator to the providers that support its type | Yes, when the user searches |

## Caching and rate limits
- Consulted results (`ok` and `not_found`) are cached in `intel_cache` for
  `PROVIDER_CACHE_TTL_HOURS`. Errors and rate-limit responses are not cached.
- Client-side limits are applied per provider in the process: a minimum interval and a
  daily cap. A limited request returns `rate_limited` with a retry hint. It does not
  silently return "no results".
- Retries: one retry on connection errors and 5xx responses. Timeouts are `PROVIDER_TIMEOUT_SECONDS`.

## Response normalisation
Every provider result has the same shape: `provider`, `indicator_type`, `indicator`,
`status` (`ok`, `not_found`, `not_configured`, `unavailable`, `timeout`, `invalid_key`,
`rate_limited`, `unsupported`, `submitted`), `detection` (`positives` and `total`, or
null), a small `summary`, `message`, `fetched_at`, and `cached`. Raw provider payloads are
never stored or returned.

## Key handling
Keys are read from the backend environment only. They are never returned by any endpoint,
written to reports, or placed in the frontend bundle. `GET /api/v1/providers` reports
whether a key is set.

## Not integrated
Hybrid Analysis, ANY.RUN and similar sandboxes (dynamic analysis is out of scope), and
OpenCTI and MISP (a future feed-import option). Their terms and quotas were not reviewed for
this release.
