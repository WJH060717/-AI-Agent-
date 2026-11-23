"""Frozen additions for revision 0002_d3. V1 remains untouched."""

from sqlalchemy import (
    Column,
    ForeignKeyConstraint,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    UniqueConstraint,
)

from packages.storage import schema_v1

metadata = MetaData()
for original in schema_v1.metadata.sorted_tables:
    original.to_metadata(metadata)
document = schema_v1.document


def job_columns() -> list[Column]:
    return [
        Column("kind", String(30), nullable=False, server_default="import"),
        Column("payload", document),
        Column("worker_id", String(100)),
        Column("lease_until", String(40)),
        Column("available_at", String(40), nullable=False, server_default=""),
        Column("attempt", Integer, nullable=False, server_default="0"),
        Column("version", Integer, nullable=False, server_default="0"),
        Column("cursor_line", Integer, nullable=False, server_default="0"),
        Column("cursor_byte", Integer, nullable=False, server_default="0"),
        Column("cancel_requested", Integer, nullable=False, server_default="0"),
    ]


jobs = metadata.tables["jobs"]
jobs.c.batch_id.nullable = True
for column in job_columns():
    jobs.append_column(column)
Index("ix_jobs_due", jobs.c.state, jobs.c.available_at)
batch_events = Table(
    "batch_events",
    metadata,
    Column("workspace_id", String(36), primary_key=True),
    Column("batch_id", String(36), primary_key=True),
    Column("event_id", String(64), primary_key=True),
    ForeignKeyConstraint(
        ["workspace_id", "batch_id"], ["import_batches.workspace_id", "import_batches.id"]
    ),
    ForeignKeyConstraint(["workspace_id", "event_id"], ["events.workspace_id", "events.event_id"]),
)
findings = Table(
    "findings",
    metadata,
    Column("workspace_id", String(36), primary_key=True),
    Column("id", String(64), primary_key=True),
    Column("dataset_id", String(36), nullable=False),
    Column("session_id", String(36), nullable=False),
    Column("payload", document, nullable=False),
    ForeignKeyConstraint(
        ["workspace_id", "session_id"], ["analysis_sessions.workspace_id", "analysis_sessions.id"]
    ),
)
incidents = Table(
    "incidents",
    metadata,
    Column("workspace_id", String(36), primary_key=True),
    Column("id", String(36), primary_key=True),
    Column("dataset_id", String(36), nullable=False),
    Column("session_id", String(36), nullable=False),
    Column("finding_id", String(64)),
    Column("title", String(200), nullable=False),
    Column("start_time", String(40), nullable=False),
    Column("end_time", String(40), nullable=False),
    Column("created_at", String(40), nullable=False),
    ForeignKeyConstraint(
        ["workspace_id", "session_id"], ["analysis_sessions.workspace_id", "analysis_sessions.id"]
    ),
)
snapshots = Table(
    "snapshots",
    metadata,
    Column("workspace_id", String(36), primary_key=True),
    Column("id", String(36), primary_key=True),
    Column("incident_id", String(36), nullable=False),
    Column("scope", document, nullable=False),
    Column("event_ids", document, nullable=False),
    Column("created_at", String(40), nullable=False),
    ForeignKeyConstraint(
        ["workspace_id", "incident_id"], ["incidents.workspace_id", "incidents.id"]
    ),
)
runs = Table(
    "investigation_runs",
    metadata,
    Column("workspace_id", String(36), primary_key=True),
    Column("id", String(36), primary_key=True),
    Column("incident_id", String(36), nullable=False),
    Column("snapshot_id", String(36), nullable=False),
    Column("job_id", String(36), nullable=False),
    Column("state", String(20), nullable=False),
    Column("report_id", String(36)),
    Column("graph", document),
    Column("created_at", String(40), nullable=False),
    ForeignKeyConstraint(
        ["workspace_id", "snapshot_id"], ["snapshots.workspace_id", "snapshots.id"]
    ),
)
reports = Table(
    "reports",
    metadata,
    Column("workspace_id", String(36), primary_key=True),
    Column("id", String(36), primary_key=True),
    Column("run_id", String(36), nullable=False),
    Column("version", Integer, nullable=False),
    Column("payload", document, nullable=False),
    UniqueConstraint("workspace_id", "run_id", "version"),
    ForeignKeyConstraint(
        ["workspace_id", "run_id"], ["investigation_runs.workspace_id", "investigation_runs.id"]
    ),
)

for name in (
    "workspaces",
    "tokens",
    "datasets",
    "sessions",
    "objects",
    "batches",
    "events",
    "members",
    "quarantine",
    "idempotency",
    "audit",
):
    globals()[name] = metadata.tables[getattr(schema_v1, name).name]

NEW_TABLES = [batch_events, findings, incidents, snapshots, runs, reports]
