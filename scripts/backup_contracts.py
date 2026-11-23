"""Local offline backup format. The database dump is PRIVATE, never a release input."""

from typing import Literal

from pydantic import AwareDatetime, Field

from packages.contracts.models import Contract, Digest


class BackupFile(Contract):
    sha256: Digest
    bytes: int = Field(ge=0)


class TableState(Contract):
    rows: int = Field(ge=0)
    sha256: Digest


class BackupManifest(Contract):
    version: Literal["d12-backup@1.0.0"]
    created_at: AwareDatetime
    engine: Literal["sqlite", "postgresql"]
    migration_head: Literal["0006_d9"]
    database_file: Literal["database.sqlite", "database.dump"]
    application_version: str
    sensitivity: Literal["private_database_and_authorized_raw_evidence"]
    tables: dict[str, TableState]
    files: dict[str, BackupFile]
    publication_high_water: int = Field(ge=0)
    reports_verified: int = Field(ge=0)
    events_verified: int = Field(ge=0)
