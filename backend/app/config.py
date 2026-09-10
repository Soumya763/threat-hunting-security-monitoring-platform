"""
Application configuration.

Reads settings from environment variables / .env file. Defaults match the
values already defined in docker-compose.yml so the backend works out of
the box against the existing containers.
"""

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Values jwt_secret_key must never be left at - an empty value (never
# configured) or the known placeholder that used to ship as a default in
# earlier versions of this project. Both are "insecure" in the same way:
# a secret an attacker could trivially guess or find checked into a repo.
_INSECURE_JWT_SECRETS = {"", "dev-insecure-secret-change-me"}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Postgres
    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_db: str = "threat_hunting"
    postgres_user: str = "postgres"
    postgres_password: str = "postgres"
    # Optional libpq sslmode (e.g. "require" for Neon's pooled
    # endpoint). Blank (default) leaves the connection string exactly
    # as before, so local Docker Postgres is unaffected.
    postgres_sslmode: str = ""

    # Elasticsearch
    elasticsearch_host: str = "http://localhost:9200"

    # Auth. No usable default on purpose - see _reject_insecure_jwt_secret
    # below, which fails application startup rather than silently signing
    # tokens with a missing or known-insecure secret. Set a real value via
    # .env (see backend/.env.example for how to generate one).
    jwt_secret_key: str = ""
    jwt_algorithm: str = "HS256"
    jwt_expires_minutes: int = 480

    # Basic in-process login rate limiting (see app.api.auth). Single
    # process only - not a distributed rate limiter.
    login_rate_limit_max_attempts: int = 5
    login_rate_limit_window_seconds: int = 300

    # Automatic detection/correlation scheduler (see app.scheduler).
    enable_scheduler: bool = True
    detection_interval_seconds: int = 300

    # AbuseIPDB threat-intelligence enrichment (see
    # app.services.threat_intel). An empty api key is a valid "feature
    # disabled" state, not a startup error like an insecure JWT secret -
    # the platform must keep working normally without it, so there is no
    # validator here rejecting a blank key.
    abuseipdb_api_key: str = ""
    abuseipdb_api_url: str = "https://api.abuseipdb.com/api/v2/check"
    abuseipdb_timeout_seconds: float = 5.0
    abuseipdb_max_age_days: int = 90
    # How long a successful lookup / a provider failure stays cached
    # in-process, keyed by IP (see threat_intel._ReputationCache). The
    # error TTL is deliberately shorter than the success TTL so a
    # transient outage doesn't get "stuck" for as long as a real result.
    abuseipdb_cache_ttl_seconds: int = 1800
    abuseipdb_error_cache_ttl_seconds: int = 60

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

    @property
    def postgres_url(self) -> str:
        base = (
            f"postgresql+psycopg2://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )
        return f"{base}?sslmode={self.postgres_sslmode}" if self.postgres_sslmode else base


settings = Settings()
