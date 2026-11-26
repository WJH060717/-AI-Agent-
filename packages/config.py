"""Single typed configuration boundary; model access disabled by default."""

from decimal import Decimal
from pathlib import Path
from typing import Literal, Self
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="forbid")
    app_env: Literal["development", "demo", "test"] = "development"
    app_bind: str = "127.0.0.1"
    app_port: int = Field(default=8000, ge=1, le=65535)
    web_dist: Path | None = None
    knowledge_enabled: bool = True
    replay_event_limit: int = Field(default=100000, ge=1, le=100000)
    replay_batch_size: int = Field(default=500, ge=1, le=500)
    database_url: SecretStr | None = None
    raw_store: Path = Path("data/raw")
    staging_store: Path = Path("data/staging")
    backup_pg_bin: Path | None = None
    backup_timeout_seconds: int = Field(default=600, ge=10, le=3600)
    api_read_requests_per_minute: int = Field(default=120, ge=1, le=6000)
    api_write_requests_per_minute: int = Field(default=20, ge=1, le=1000)
    api_rate_max_identities: int = Field(default=1024, ge=1, le=10000)
    max_upload_mb: int = Field(default=100, ge=1, le=100)
    report_export_max_lines: int = Field(default=5000, ge=1, le=10000)
    report_export_max_bytes: int = Field(default=5_000_000, ge=1024, le=10_000_000)
    worker_lease_seconds: int = Field(default=60, ge=5, le=300)
    worker_heartbeat_seconds: int = Field(default=10, ge=1, le=30)
    worker_max_attempts: int = Field(default=3, ge=1, le=3)
    worker_poll_seconds: float = Field(default=1, ge=0.05, le=30)
    import_chunk_lines: int = Field(default=500, ge=1, le=500)
    snapshot_event_limit: int = Field(default=250, ge=1, le=250)
    snapshot_scan_limit: int = Field(default=20000, ge=250, le=100000)
    detection_event_limit: int = Field(default=100000, ge=1, le=100000)
    detection_byte_limit: int = Field(default=268435456, ge=1024, le=536870912)
    detection_work_limit: int = Field(default=2000000, ge=1, le=10000000)
    detection_timeout_seconds: float = Field(default=20, ge=0.05, le=30)
    detection_finding_limit: int = Field(default=2000, ge=1, le=5000)
    detection_reference_limit: int = Field(default=500000, ge=1, le=1000000)
    model_provider: Literal["disabled", "compatible"] = "disabled"
    model_base_url: str | None = None
    model_name: str | None = None
    model_api_key: SecretStr | None = None
    model_timeout_seconds: float = Field(default=20, ge=0.05, le=20)
    tool_timeout_seconds: float = Field(default=3, ge=0.05, le=3)
    model_output_tokens_per_call: int = Field(default=768, ge=1, le=3000)
    model_test_stub: bool = False
    model_thinking: Literal["disabled"] | None = None
    model_plan_fact_limit: int = Field(default=1, ge=1, le=6)
    model_input_usd_per_million: Decimal | None = Field(
        default=None, ge=0, le=10000, allow_inf_nan=False
    )
    model_output_usd_per_million: Decimal | None = Field(
        default=None, ge=0, le=10000, allow_inf_nan=False
    )
    model_price_version: str = Field(default="unconfigured", min_length=1, max_length=100)
    agent_max_cost_microusd: int = Field(default=0, ge=0, le=100_000_000)

    @model_validator(mode="after")
    def model_requirements(self) -> Self:
        if self.worker_heartbeat_seconds >= self.worker_lease_seconds:
            raise ValueError("worker heartbeat must be shorter than the lease")
        if self.model_provider != "disabled" and not (
            self.model_base_url and self.model_name and self.model_api_key
        ):
            raise ValueError("enabled model requires base URL, name and API key")
        if self.model_base_url:
            parsed = urlsplit(self.model_base_url)
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.hostname
                or parsed.username
                or parsed.password
                or parsed.query
                or parsed.fragment
                or parsed.scheme == "http"
                and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}
            ):
                raise ValueError(
                    "model URL needs HTTPS (HTTP only for loopback), no credentials/query/fragment"
                )
        if self.model_test_stub and (
            self.app_env != "test"
            or not self.model_base_url
            or urlsplit(self.model_base_url).hostname not in {"localhost", "127.0.0.1", "::1"}
        ):
            raise ValueError("protocol test stub is restricted to test environment and loopback")
        return self
