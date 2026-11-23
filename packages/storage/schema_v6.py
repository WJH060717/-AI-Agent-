"""Frozen D9 append-only claim reviews; previous migration metadata is unchanged."""

from sqlalchemy import (
    Column,
    ForeignKeyConstraint,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    UniqueConstraint,
)

from packages.storage import schema_v5

metadata = MetaData()
for original in schema_v5.metadata.sorted_tables:
    original.to_metadata(metadata)
for name, original in vars(schema_v5).items():
    if isinstance(original, Table):
        globals()[name] = metadata.tables[original.name]

reviews = Table(
    "report_reviews",
    metadata,
    Column("seq", Integer, primary_key=True, autoincrement=True),
    Column("workspace_id", String(36), nullable=False),
    Column("id", String(36), nullable=False),
    Column("report_id", String(36), nullable=False),
    Column("claim_id", String(200), nullable=False),
    Column("decision", String(30), nullable=False),
    Column("comment", Text, nullable=False),
    Column("actor_id", String(64), nullable=False),
    Column("created_at", String(40), nullable=False),
    UniqueConstraint("workspace_id", "id"),
    ForeignKeyConstraint(["workspace_id", "report_id"], ["reports.workspace_id", "reports.id"]),
)
