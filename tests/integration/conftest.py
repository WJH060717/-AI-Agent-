import os

import pytest
from sqlalchemy import update

from packages.config import Settings
from packages.storage import schema_v3 as tables
from packages.storage.database import Database
from packages.storage.service import DataService


@pytest.fixture
def context(tmp_path):
    url = os.environ.get("D2_TEST_DATABASE_URL", f"sqlite:///{tmp_path / 'test.db'}")
    settings = Settings(
        _env_file=None,
        app_env="test",
        database_url=url,
        staging_store=tmp_path / "staging",
        raw_store=tmp_path / "raw",
    )
    db = Database(settings)
    db.migrate()
    service = DataService(db, settings)
    workspace, tokens = service.init_workspace("test")
    yield settings, db, service, workspace, tokens
    # Temporary test workspaces only: abandoned retry jobs must not affect another case.
    with db.engine.begin() as conn:
        conn.execute(
            update(tables.jobs)
            .where(
                tables.jobs.c.workspace_id == workspace,
                tables.jobs.c.state.in_(["queued", "running"]),
            )
            .values(state="cancelled")
        )
    db.engine.dispose()
