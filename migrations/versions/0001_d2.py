"""D2 initial frozen schema."""

from alembic import op

from packages.storage.schema_v1 import metadata

revision = "0001_d2"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    metadata.create_all(op.get_bind(), checkfirst=False)


def downgrade() -> None:
    raise RuntimeError("Destructive downgrade not provided for the evidence prototype")
