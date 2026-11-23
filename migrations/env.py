from alembic import context

from packages.storage.schema_v5 import metadata

connection = context.config.attributes.get("connection")
if connection is None:
    raise RuntimeError("Use python -m apps.api.manage migrate with configured DATABASE_URL")
context.configure(connection=connection, target_metadata=metadata)
with context.begin_transaction():
    context.run_migrations()
