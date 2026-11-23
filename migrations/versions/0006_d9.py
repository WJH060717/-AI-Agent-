from alembic import op

from packages.storage.schema_v6 import reviews

revision = "0006_d9"
down_revision = "0005_d6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    reviews.create(op.get_bind())


def downgrade() -> None:
    raise RuntimeError("Destructive evidence downgrade is not supported")
