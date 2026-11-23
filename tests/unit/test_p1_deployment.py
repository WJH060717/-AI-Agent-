from types import SimpleNamespace

import pytest


def test_container_health_checks_schema_archive_and_http(tmp_path, monkeypatch):
    from packages.config import Settings
    from packages.storage.database import Database
    from scripts.container_health import check

    settings = Settings(
        _env_file=None,
        database_url=f"sqlite:///{tmp_path / 'health.db'}",
        raw_store=tmp_path / "raw",
        staging_store=tmp_path / "staging",
    )
    settings.raw_store.mkdir()
    settings.staging_store.mkdir()
    monkeypatch.setattr(
        "scripts.container_health.urlopen",
        lambda *args, **kwargs: SimpleNamespace(status=200, close=lambda: None),
    )
    with pytest.raises(RuntimeError, match="SCHEMA"):
        check(settings)
    db = Database(settings)
    db.migrate()
    check(settings)
    settings.raw_store.rmdir()
    with pytest.raises(RuntimeError, match="ARCHIVE"):
        check(settings)
    db.engine.dispose()
