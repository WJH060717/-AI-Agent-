from alembic import op
from sqlalchemy import Column, Integer

from packages.storage.schema_v3 import contexts, document, private_keys

revision = "0003_d4"
down_revision = "0002_d3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("jobs", Column("checkpoint", document))
    for name in ("raw_records", "aggregated_records"):
        op.add_column("import_batches", Column(name, Integer, nullable=False, server_default="0"))
    # Existing line-local D2/D3 counts retain their physical-record accounting.
    op.execute(
        "UPDATE import_batches SET raw_records=accepted+duplicate+quarantined, "
        "aggregated_records=accepted+duplicate"
    )
    contexts.create(op.get_bind())
    private_keys.create(op.get_bind())


def downgrade() -> None:
    raise RuntimeError("Destructive evidence downgrade is not supported")
