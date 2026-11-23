"""Frozen revision 0004_d5 additions; earlier metadata remains unchanged."""

from sqlalchemy import Column, ForeignKeyConstraint, Index, Integer, MetaData, String, Table

from packages.storage import schema_v3

metadata = MetaData()
for original in schema_v3.metadata.sorted_tables:
    original.to_metadata(metadata)
document = schema_v3.document
metadata.tables["datasets"].append_column(
    Column("created_seq", Integer, nullable=False, server_default="0")
)
members = metadata.tables["session_events"]
members.append_column(Column("publication", Integer, nullable=False, server_default="0"))
Index("ix_members_publication", members.c.workspace_id, members.c.session_id, members.c.publication)

details = Table(
    "incident_details",
    metadata,
    Column("workspace_id", String(36), primary_key=True),
    Column("id", String(36), primary_key=True),
    Column("payload", document, nullable=False),
    ForeignKeyConstraint(["workspace_id", "id"], ["incidents.workspace_id", "incidents.id"]),
)
catalogs = Table(
    "incident_catalogs",
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
heads = Table(
    "incident_heads",
    metadata,
    Column("workspace_id", String(36), primary_key=True),
    Column("id", String(36), primary_key=True),
    Column("catalog_id", String(64), nullable=False),
    ForeignKeyConstraint(
        ["workspace_id", "id"], ["analysis_sessions.workspace_id", "analysis_sessions.id"]
    ),
    ForeignKeyConstraint(
        ["workspace_id", "catalog_id"], ["incident_catalogs.workspace_id", "incident_catalogs.id"]
    ),
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
    "quarantine",
    "idempotency",
    "audit",
    "batch_events",
    "findings",
    "incidents",
    "snapshots",
    "runs",
    "reports",
    "contexts",
    "private_keys",
):
    globals()[name] = metadata.tables[getattr(schema_v3, name).name]
