# Status and decisions (current)

This replaces the earlier assessment, which described the offline core only. The current
status of each feature is in the [README](../README.md#status). Decisions made during
implementation:

| Decision | Reason |
|---|---|
| Use OpenSearch 2.19.7 as the search engine everywhere (compose, Logstash output, backend client) | The project's search engine is OpenSearch. The compose file had been running Elasticsearch 8.15.3 with an OpenSearch-compatible client, which contradicted the project's design. It is now corrected. |
| Analysis runs in FastAPI background tasks; the UI polls | No extra worker service is needed for a student deployment. Step timeouts keep requests bounded. |
| Store analysis results as JSON in PostgreSQL; files only in quarantine | Keeps the database small, keeps bytes out of backups by default, and lets reports render without re-fetching. |
| Use the existing `audit_logs` table for analysis actions | Reuses the audit trail and its UI rather than adding a second log. |
| Pinned-IP HTTP connections for URL analysis | Prevents DNS rebinding between the check and the connection. |
| RDAP through `rdap.org` by default | No key and no library. The base URL is configurable. |
| Provider limits are conservative client-side placeholders where no quota is published | Avoids assuming quotas that were not verified. |
| `clean` only with a consulted source and no detection | Avoids a false "safe" result when no provider was reachable. |
| Hash lookups are automatic; file upload and URL submission need consent per call | Matches the brief's privacy requirement. |
| Tests use SQLite for ORM logic and stubs for network | Keeps the suite runnable without services. Live checks are listed separately in TESTING.md. |
| Branch `feature/threat-intelligence-expansion` | Approved name; the original branch is preserved. |

## Open items for the team
1. Run one live check per provider with your own keys and record the results.
2. Verify the detection rules and pivots against real events from the live pipelines (done in this release, see TESTING.md).
3. Tune scoring weights on a labelled set of benign and malicious samples (EICAR and synthetic files are not enough).
4. Decide whether to keep `rdap.org` or use the registry-specific servers directly.
5. Confirm your VirusTotal account type and whether the project's use is non-commercial.
