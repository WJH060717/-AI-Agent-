"""Frozen schema for Alembic revision 0001; future changes require new revisions."""

from sqlalchemy import (
    JSON,
    Column,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB

metadata = MetaData()
document = JSON().with_variant(JSONB(), "postgresql")

workspaces = Table(
    "workspaces",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("name", String(200), nullable=False),
)
tokens = Table(
    "role_tokens",
    metadata,
    Column("digest", String(64), primary_key=True),
    Column("workspace_id", ForeignKey("workspaces.id"), nullable=False),
    Column("role", String(20), nullable=False),
)
datasets = Table(
    "datasets",
    metadata,
    Column("workspace_id", ForeignKey("workspaces.id"), primary_key=True),
    Column("id", String(36), primary_key=True),
    Column("name", String(200), nullable=False),
    Column("provenance_type", String(30), nullable=False),
    Column("created_at", String(40), nullable=False),
)
sessions = Table(
    "analysis_sessions",
    metadata,
    Column("workspace_id", String(36), primary_key=True),
    Column("id", String(36), primary_key=True),
    Column("dataset_id", String(36), nullable=False),
    Column("mode", String(20), nullable=False),
    ForeignKeyConstraint(["workspace_id", "dataset_id"], ["datasets.workspace_id", "datasets.id"]),
)
objects = Table(
    "raw_objects",
    metadata,
    Column("workspace_id", String(36), primary_key=True),
    Column("id", String(36), primary_key=True),
    Column("sha256", String(64), nullable=False),
    Column("sensor_id", String(200), nullable=False),
    Column("storage_key", String(200), nullable=False),
    Column("byte_size", Integer, nullable=False),
    Column("sealed_at", String(40), nullable=False),
    UniqueConstraint("workspace_id", "sha256", "sensor_id"),
)
batches = Table(
    "import_batches",
    metadata,
    Column("workspace_id", String(36), primary_key=True),
    Column("id", String(36), primary_key=True),
    Column("dataset_id", String(36), nullable=False),
    Column("session_id", String(36), nullable=False),
    Column("source_type", String(30), nullable=False),
    Column("sensor_id", String(200), nullable=False),
    Column("timezone", String(80), nullable=False),
    Column("staging_key", String(100), nullable=False),
    Column("sha256", String(64), nullable=False),
    Column("byte_size", Integer, nullable=False),
    Column("status", String(20), nullable=False),
    Column("object_id", String(36)),
    Column("accepted", Integer, nullable=False, default=0),
    Column("duplicate", Integer, nullable=False, default=0),
    Column("quarantined", Integer, nullable=False, default=0),
    Column("error_code", String(80)),
    ForeignKeyConstraint(["workspace_id", "dataset_id"], ["datasets.workspace_id", "datasets.id"]),
)
jobs = Table(
    "jobs",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("workspace_id", String(36), nullable=False),
    Column("batch_id", String(36), nullable=False),
    Column("state", String(20), nullable=False),
    Column("error_code", String(80)),
    ForeignKeyConstraint(
        ["workspace_id", "batch_id"], ["import_batches.workspace_id", "import_batches.id"]
    ),
)
events = Table(
    "events",
    metadata,
    Column("workspace_id", String(36), primary_key=True),
    Column("event_id", String(64), primary_key=True),
    Column("dataset_id", String(36), nullable=False),
    Column("event_time", String(40), nullable=False),
    Column("event_type", String(40), nullable=False),
    Column("payload", document, nullable=False),
    ForeignKeyConstraint(["workspace_id", "dataset_id"], ["datasets.workspace_id", "datasets.id"]),
)
members = Table(
    "session_events",
    metadata,
    Column("workspace_id", String(36), primary_key=True),
    Column("session_id", String(36), primary_key=True),
    Column("event_id", String(64), primary_key=True),
    ForeignKeyConstraint(
        ["workspace_id", "session_id"], ["analysis_sessions.workspace_id", "analysis_sessions.id"]
    ),
    ForeignKeyConstraint(["workspace_id", "event_id"], ["events.workspace_id", "events.event_id"]),
)
quarantine = Table(
    "quarantine_records",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("workspace_id", String(36), nullable=False),
    Column("batch_id", String(36), nullable=False),
    Column("object_id", String(36), nullable=False),
    Column("line", Integer, nullable=False),
    Column("error_code", String(80), nullable=False),
    ForeignKeyConstraint(
        ["workspace_id", "batch_id"], ["import_batches.workspace_id", "import_batches.id"]
    ),
)
idempotency = Table(
    "idempotency_keys",
    metadata,
    Column("workspace_id", String(36), primary_key=True),
    Column("actor", String(64), primary_key=True),
    Column("route", String(100), primary_key=True),
    Column("key", String(200), primary_key=True),
    Column("request_hash", String(64), nullable=False),
    Column("response", document, nullable=False),
    Column("expires_at", String(40), nullable=False),
)
audit = Table(
    "audit_logs",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("workspace_id", String(36), nullable=False),
    Column("actor", String(64), nullable=False),
    Column("action", String(80), nullable=False),
    Column("object_id", String(100), nullable=False),
    Column("created_at", String(40), nullable=False),
)
Index(
    "ix_events_scope_time",
    events.c.workspace_id,
    events.c.dataset_id,
    events.c.event_time,
    events.c.event_id,
)
Index("ix_jobs_state", jobs.c.state)
