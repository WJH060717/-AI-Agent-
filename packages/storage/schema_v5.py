"""Frozen D6 Agent state/action/transition metadata; revisions1–4 unchanged."""

from sqlalchemy import Column, ForeignKeyConstraint, Integer, MetaData, String, Table

from packages.storage import schema_v4

metadata = MetaData()
for original in schema_v4.metadata.sorted_tables:
    original.to_metadata(metadata)
document = schema_v4.document
agent_states = Table(
    "agent_states",
    metadata,
    Column("workspace_id", String(36), primary_key=True),
    Column("id", String(36), primary_key=True),
    Column("phase", String(30), nullable=False),
    Column("version", Integer, nullable=False),
    Column("payload", document, nullable=False),
    Column("updated_at", String(40), nullable=False),
    ForeignKeyConstraint(
        ["workspace_id", "id"], ["investigation_runs.workspace_id", "investigation_runs.id"]
    ),
)
agent_actions = Table(
    "agent_actions",
    metadata,
    Column("workspace_id", String(36), primary_key=True),
    Column("run_id", String(36), primary_key=True),
    Column("seq", Integer, primary_key=True),
    Column("kind", String(20), nullable=False),
    Column("name", String(100), nullable=False),
    Column("status", String(30), nullable=False),
    Column("args_hash", String(64), nullable=False),
    Column("args_payload", document),
    Column("result_payload", document),
    Column("result_digest", String(64)),
    Column("request_id", String(200)),
    Column("usage", document),
    Column("error_code", String(100)),
    Column("new_evidence_count", Integer, nullable=False, server_default="0"),
    Column("cache_hit", Integer, nullable=False, server_default="0"),
    Column("started_at", String(40), nullable=False),
    Column("ended_at", String(40)),
    ForeignKeyConstraint(
        ["workspace_id", "run_id"], ["investigation_runs.workspace_id", "investigation_runs.id"]
    ),
)
agent_transitions = Table(
    "agent_transitions",
    metadata,
    Column("workspace_id", String(36), primary_key=True),
    Column("run_id", String(36), primary_key=True),
    Column("version", Integer, primary_key=True),
    Column("phase", String(30), nullable=False),
    Column("reason", String(100), nullable=False),
    Column("occurred_at", String(40), nullable=False),
    Column("budget_used", document, nullable=False),
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
    "contexts",
    "private_keys",
    "details",
    "catalogs",
    "heads",
):
    globals()[name] = metadata.tables[getattr(schema_v4, name).name]
