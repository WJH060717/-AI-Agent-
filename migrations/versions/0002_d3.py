"""D3 leases, checkpoints, detections and immutable investigation results."""

from alembic import op
from sqlalchemy import String

from packages.storage.schema_v2 import NEW_TABLES, job_columns

revision = "0002_d3"
down_revision = "0001_d2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("jobs") as batch:
        batch.alter_column("batch_id", existing_type=String(36), nullable=True)
        for column in job_columns():
            batch.add_column(column)
    op.create_index("ix_jobs_due", "jobs", ["state", "available_at"])
    for table in NEW_TABLES:
        table.create(op.get_bind())


def downgrade() -> None:
    raise RuntimeError("Destructive evidence downgrade is not supported")
