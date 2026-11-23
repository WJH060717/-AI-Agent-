from alembic import op

from packages.storage.schema_v5 import agent_actions, agent_states, agent_transitions

revision = "0005_d6"
down_revision = "0004_d5"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for table in (agent_states, agent_actions, agent_transitions):
        table.create(op.get_bind())


def downgrade() -> None:
    raise RuntimeError("Destructive evidence downgrade is not supported")
