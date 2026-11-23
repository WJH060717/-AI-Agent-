"""Add immutable incident catalog/details and publication watermark, preserving legacy IDs."""

import hashlib
import json
import secrets
from collections import defaultdict

from alembic import op
from sqlalchemy import Column, Integer, select, update

from packages.storage import schema_v4 as t

revision = "0004_d5"
down_revision = "0003_d4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("datasets", Column("created_seq", Integer, nullable=False, server_default="0"))
    op.add_column(
        "session_events", Column("publication", Integer, nullable=False, server_default="0")
    )
    op.create_index(
        "ix_members_publication", "session_events", ["workspace_id", "session_id", "publication"]
    )
    conn = op.get_bind()
    sequences = defaultdict(int)
    for dataset in conn.execute(
        select(t.datasets).order_by(t.datasets.c.created_at, t.datasets.c.id)
    ).mappings():
        sequences[dataset["workspace_id"]] += 1
        conn.execute(
            update(t.datasets)
            .where(
                t.datasets.c.workspace_id == dataset["workspace_id"],
                t.datasets.c.id == dataset["id"],
            )
            .values(created_seq=sequences[dataset["workspace_id"]])
        )
    for table in (t.details, t.catalogs, t.heads):
        table.create(conn)
    for workspace in conn.execute(select(t.workspaces.c.id)).scalars():
        if (
            conn.execute(
                select(t.private_keys.c.workspace_id).where(
                    t.private_keys.c.workspace_id == workspace
                )
            ).first()
            is None
        ):
            conn.execute(
                t.private_keys.insert().values(workspace_id=workspace, salt=secrets.token_hex(32))
            )
    scopes = defaultdict(list)
    for incident in conn.execute(select(t.incidents)).mappings():
        finding = conn.execute(
            select(t.findings.c.payload).where(
                t.findings.c.workspace_id == incident["workspace_id"],
                t.findings.c.id == incident["finding_id"],
            )
        ).scalar_one()
        conn.execute(
            t.details.insert().values(
                workspace_id=incident["workspace_id"],
                id=incident["id"],
                payload={
                    "finding_ids": [incident["finding_id"]],
                    "evidence_ids": finding["evidence_ids"],
                    "strong_entities": [],
                    "reasons": [],
                    "method_version": "legacy_single@1.0.0",
                },
            )
        )
        scopes[(incident["workspace_id"], incident["dataset_id"], incident["session_id"])].append(
            incident["id"]
        )
    for (workspace, dataset, session), ids in scopes.items():
        catalog_id = hashlib.sha256(
            json.dumps([workspace, dataset, session, sorted(ids)]).encode()
        ).hexdigest()
        conn.execute(
            t.catalogs.insert().values(
                workspace_id=workspace,
                id=catalog_id,
                dataset_id=dataset,
                session_id=session,
                payload={"incident_ids": sorted(ids)},
            )
        )
        conn.execute(
            t.heads.insert().values(workspace_id=workspace, id=session, catalog_id=catalog_id)
        )


def downgrade() -> None:
    raise RuntimeError("Destructive evidence downgrade is not supported")
