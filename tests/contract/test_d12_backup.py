import json

import pytest

from packages.config import Settings
from packages.storage import schema_v6 as t
from packages.storage.database import Database
from packages.storage.service import DataService
from scripts import backup
from tests.integration.d6_helpers import pending


@pytest.fixture
def source(tmp_path):
    settings = Settings(
        _env_file=None,
        app_env="test",
        database_url=f"sqlite:///{tmp_path / 'source.db'}",
        raw_store=tmp_path / "raw",
        staging_store=tmp_path / "staging",
    )
    db = Database(settings)
    db.migrate()
    service = DataService(db, settings)
    workspace, tokens = service.init_workspace("recovery fixture")
    actor, dataset, run = pending((settings, db, service, workspace, tokens), mode="deterministic")
    service.process_one()
    yield settings, db, service, actor, run
    db.engine.dispose()


def target(tmp_path):
    return Settings(
        _env_file=None,
        app_env="test",
        database_url=f"sqlite:///{tmp_path / 'restored.db'}",
        raw_store=tmp_path / "restored-raw",
        staging_store=tmp_path / "restored-staging",
    )


def test_round_trip_keeps_all_tables_evidence_and_old_report(source, tmp_path):
    settings, db, service, actor, run = source
    from packages.storage.analysis import AnalysisService

    analysis = AnalysisService(service)
    before = analysis.get_report(actor, analysis.get_run(actor, run["run_id"])["report_id"])
    dest = tmp_path / "backup"
    manifest = backup.create_backup(settings, dest)
    assert manifest["migration_head"] == "0006_d9"
    assert manifest["tables"]["reports"]["rows"] == 1
    restored = target(tmp_path)
    result = backup.restore_backup(restored, dest)
    assert result["verified"] and result["reports_verified"] == 1
    restored_db = Database(restored)
    restored_service = DataService(restored_db, restored)
    a = restored_service.system_actor(actor.workspace_id)
    after = AnalysisService(restored_service).get_report(a, before["report_id"])
    assert after == before
    new = AnalysisService(restored_service).create_run(
        a,
        analysis.get_run(actor, run["run_id"])["incident_id"],
        "after-restore",
        mode="deterministic",
    )
    restored_service.process_one()
    assert (
        AnalysisService(restored_service).get_run(a, new["run_id"])["report_id"]
        != before["report_id"]
    )
    assert AnalysisService(restored_service).get_report(a, before["report_id"]) == before
    restored_db.engine.dispose()


def test_backup_rejects_queued_work_and_does_not_publish_manifest(source, tmp_path):
    settings, db, _, _, _ = source
    with db.engine.begin() as conn:
        conn.execute(t.jobs.update().values(state="queued"))
    with pytest.raises(ValueError, match="QUEUE_NOT_DRAINED"):
        backup.create_backup(settings, tmp_path / "busy")
    assert not (tmp_path / "busy/manifest.json").exists()


def test_corrupt_object_rejected_before_target_database_created(source, tmp_path):
    settings, _, _, _, _ = source
    dest = tmp_path / "backup"
    manifest = backup.create_backup(settings, dest)
    raw = next(name for name in manifest["files"] if name.startswith("raw/"))
    (dest / raw).write_bytes(b"tampered")
    with pytest.raises(ValueError, match="FILE_INTEGRITY"):
        backup.restore_backup(target(tmp_path), dest)
    assert not (tmp_path / "restored.db").exists()


def test_existing_database_and_directory_are_never_overwritten(source, tmp_path):
    settings, _, _, _, _ = source
    dest = tmp_path / "backup"
    backup.create_backup(settings, dest)
    with pytest.raises(ValueError, match="TARGET_NOT_EMPTY"):
        backup.restore_backup(settings, dest)
    restored = target(tmp_path)
    restored.raw_store.mkdir()
    marker = restored.raw_store / "keep"
    marker.write_bytes(b"user data")
    with pytest.raises(ValueError, match="TARGET_NOT_EMPTY"):
        backup.restore_backup(restored, dest)
    assert marker.read_bytes() == b"user data"


@pytest.mark.parametrize(
    "name", ["../outside", "C:/escape", "raw/../../escape", "raw\\escape", "raw/a:stream"]
)
def test_manifest_path_escape_rejected(source, tmp_path, name):
    dest = tmp_path / "backup"
    backup.create_backup(source[0], dest)
    doc = json.loads((dest / "manifest.json").read_bytes())
    doc["files"][name] = next(iter(doc["files"].values()))
    (dest / "manifest.json").write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(ValueError, match="PATH"):
        backup.verify_backup(dest)


def test_backup_does_not_publish_secrets_or_copy_env(source, tmp_path):
    settings, db, _, _, _ = source
    dest = tmp_path / "backup"
    backup.create_backup(settings, dest)
    with db.engine.connect() as conn:
        salt = conn.execute(t.private_keys.select()).mappings().first()["salt"]
    assert salt not in (dest / "manifest.json").read_text()
    assert "database_url" not in (dest / "config.json").read_text()
    assert not (dest / ".env").exists()


def test_unknown_revision_is_refused(source, tmp_path):
    from sqlalchemy import text

    with source[1].engine.begin() as conn:
        conn.execute(text("UPDATE alembic_version SET version_num='future'"))
    with pytest.raises(ValueError, match="MIGRATION_MISMATCH"):
        backup.create_backup(source[0], tmp_path / "backup")


@pytest.mark.parametrize(
    "query", ["?dbname=other", "?host=127.0.0.2", "?port=5555", "?host=/tmp/socket"]
)
def test_connection_overrides_are_rejected_before_database_access(tmp_path, monkeypatch, query):
    settings = Settings(
        _env_file=None, database_url="postgresql+psycopg://admin:secret@127.0.0.1:5432/a" + query
    )

    def forbidden(_):
        pytest.fail("Database was accessed before ambiguous endpoint rejected")

    monkeypatch.setattr(backup, "Database", forbidden)
    with pytest.raises(ValueError, match="DATABASE_OPTIONS"):
        backup.create_backup(settings, tmp_path / "backup")


def test_missing_sqlite_source_does_not_create_database(tmp_path):
    settings = target(tmp_path)
    with pytest.raises(ValueError, match="SOURCE_DATABASE_MISSING"):
        backup.create_backup(settings, tmp_path / "backup")
    assert not (tmp_path / "restored.db").exists()


def test_inherited_libpq_endpoint_is_rejected_before_database_access(tmp_path, monkeypatch):
    settings = Settings(
        _env_file=None, database_url="postgresql+psycopg://admin:secret@127.0.0.1:5432/a"
    )
    monkeypatch.setenv("PGSERVICE", "different-target")
    with pytest.raises(ValueError, match="DATABASE_ENVIRONMENT"):
        backup.create_backup(settings, tmp_path / "backup")
