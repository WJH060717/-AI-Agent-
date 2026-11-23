"""Frozen D4 schema additions; prior revisions remain unchanged."""

from sqlalchemy import Column, ForeignKeyConstraint, Integer, MetaData, String, Table

from packages.storage import schema_v2

metadata = MetaData()
for original in schema_v2.metadata.sorted_tables:
    original.to_metadata(metadata)
document = schema_v2.document
metadata.tables["jobs"].append_column(Column("checkpoint", document))
for name in ("raw_records", "aggregated_records"):
    metadata.tables["import_batches"].append_column(
        Column(name, Integer, nullable=False, server_default="0")
    )

contexts = Table(
    "dataset_contexts",
    metadata,
    Column("workspace_id", String(36), primary_key=True),
    Column("id", String(36), primary_key=True),
    Column("payload", document, nullable=False),
    Column("context_hash", String(64), nullable=False),
    ForeignKeyConstraint(["workspace_id", "id"], ["datasets.workspace_id", "datasets.id"]),
)
private_keys = Table(
    "workspace_private_keys",
    metadata,
    Column("workspace_id", String(36), primary_key=True),
    Column("salt", String(64), nullable=False),
)

for name in (
    "workspaces",
    "tokens",
    "datasets",
    "sessions",
    "objects",
    "batches",
    "jobs",
    "events",
    "members",
    "quarantine",
    "idempotency",
    "audit",
    "batch_events",
    "findings",
    "incidents",
    "snapshots",
    "runs",
    "reports",
):
    globals()[name] = metadata.tables[getattr(schema_v2, name).name]
