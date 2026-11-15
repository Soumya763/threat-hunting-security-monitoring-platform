"""
Application configuration.

Reads settings from environment variables / .env file. Defaults match the
values in docker-compose.yml so the backend works against the local
containers. Every external provider is optional: an empty API key means
"not configured", and the platform keeps working with local analysis.
"""

from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Values jwt_secret_key must never be left at.
_INSECURE_JWT_SECRETS = {"", "dev-insecure-secret-change-me"}

BACKEND_DIR = Path(__file__).resolve().parents[1]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Postgres
    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_db: str = "threat_hunting"
    postgres_user: str = "postgres"
    postgres_password: str = "postgres"
    postgres_sslmode: str = ""

    # Elasticsearch / OpenSearch-compatible search (single URL)
    elasticsearch_host: str = "http://localhost:9200"

    # CORS: comma-separated exact origins. Never "*".
    cors_allowed_origins: str = "http://localhost:5173"

    # Auth
    jwt_secret_key: str = ""
    jwt_algorithm: str = "HS256"
    jwt_expires_minutes: int = 480
    login_rate_limit_max_attempts: int = 5
    login_rate_limit_window_seconds: int = 300

    # Detection scheduler
    enable_scheduler: bool = True
    detection_interval_seconds: int = 300

    # ----- AbuseIPDB (existing) -----
    abuseipdb_api_key: str = ""
    abuseipdb_api_url: str = "https://api.abuseipdb.com/api/v2/check"
    abuseipdb_timeout_seconds: float = 5.0
    abuseipdb_max_age_days: int = 90
    abuseipdb_cache_ttl_seconds: int = 1800
    abuseipdb_error_cache_ttl_seconds: int = 60

    # ----- File analysis -----
    quarantine_dir: str = str(BACKEND_DIR / "quarantine")
    file_max_upload_bytes: int = 32 * 1024 * 1024
    file_retention_hours: int = 168
    yara_rules_dir: str = ""  # empty = bundled rules in app/analysis/yara_rules
    analysis_step_timeout_seconds: float = 60.0

    # ----- URL analysis (SSRF-hardened fetcher) -----
    url_fetch_timeout_seconds: float = 8.0
    url_fetch_total_seconds: float = 20.0
    url_max_redirects: int = 5
    url_max_body_bytes: int = 262144

    # ----- Analysis API rate limit (per authenticated user) -----
    analysis_submissions_per_minute: int = 20

    # ----- Threat-intelligence providers (all optional) -----
    provider_timeout_seconds: float = 10.0
    provider_cache_ttl_hours: int = 24
    # Sends the SHA-256 of an uploaded file to providers (never the file itself).
    provider_hash_lookup_enabled: bool = True

    virustotal_api_key: str = ""
    virustotal_api_url: str = "https://www.virustotal.com/api/v3"
    # Public API: 4 requests/minute and a daily quota. Premium keys have other limits.
    virustotal_min_interval_seconds: float = 15.0
    virustotal_daily_quota: int = 500

    malwarebazaar_auth_key: str = ""
    malwarebazaar_api_url: str = "https://mb-api.abuse.ch/api/v1/"

    otx_api_key: str = ""
    otx_api_url: str = "https://otx.alienvault.com/api/v1"

    urlscan_api_key: str = ""
    urlscan_api_url: str = "https://urlscan.io/api/v1"
    # Public scans are visible to everyone; "unlisted" is the safe default.
    urlscan_visibility: str = "unlisted"

    rdap_base_url: str = "https://rdap.org"

    # ----- Local-context pivots (OpenSearch) -----
    opensearch_log_indices: str = "events-*,security-events-*"
    pivot_lookback_days: int = 7

    @field_validator("jwt_secret_key")
    @classmethod
    def _reject_insecure_jwt_secret(cls, value: str) -> str:
        if value in _INSECURE_JWT_SECRETS:
            raise ValueError(
                "JWT_SECRET_KEY is missing or still set to a known-insecure "
                "placeholder value. The application refuses to start until "
                "a real secret is set - see backend/.env.example for "
                "instructions on generating one. (The secret's value is "
                "intentionally not included in this error.)"
            )
        return value

    @field_validator("urlscan_visibility")
    @classmethod
    def _validate_visibility(cls, value: str) -> str:
        if value not in ("public", "unlisted", "private"):
            raise ValueError("URLSCAN_VISIBILITY must be public, unlisted or private.")
        return value

    @property
    def postgres_url(self) -> str:
        base = (
            f"postgresql+psycopg2://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )
        return f"{base}?sslmode={self.postgres_sslmode}" if self.postgres_sslmode else base

    @property
    def cors_allowed_origins_list(self) -> list[str]:
        return [
            origin.strip()
            for origin in self.cors_allowed_origins.split(",")
            if origin.strip()
        ]

    @property
    def quarantine_path(self) -> Path:
        path = Path(self.quarantine_dir)
        return path if path.is_absolute() else BACKEND_DIR / path

    @property
    def yara_rules_path(self) -> Path:
        if self.yara_rules_dir:
            return Path(self.yara_rules_dir)
        return BACKEND_DIR / "app" / "analysis" / "yara_rules"


settings = Settings()
