import json

import pytest

from infra.handoff.bootstrap import initialize_identity


def test_new_handoff_identity_reuses_same_tokens_after_retry(context, tmp_path):
    settings, db, _, _, _ = context
    # This fixture already contains a workspace. A new initialization must refuse it.
    with pytest.raises(ValueError, match="NONEMPTY"):
        initialize_identity(db, tmp_path / "access.json")
    assert not (tmp_path / "access.json").exists()


def test_handoff_identity_recovers_durable_tokens_before_commit(tmp_path):
    from packages.config import Settings
    from packages.storage.database import Database
    from packages.storage.service import DataService

    db = Database(Settings(_env_file=None, database_url=f"sqlite:///{tmp_path / 'new.db'}"))
    db.migrate()
    path = tmp_path / "access.json"
    value = initialize_identity(db, path)
    before = path.read_bytes()
    assert initialize_identity(db, path) == value and path.read_bytes() == before
    service = DataService(db, Settings(_env_file=None))
    assert service.authenticate(value["tokens"]["admin"]).workspace_id == value["workspace_id"]
    damaged = json.loads(before)
    damaged["tokens"]["admin"] = "changed"
    path.write_text(json.dumps(damaged))
    with pytest.raises(ValueError, match="IDENTITY"):
        initialize_identity(db, path)
    db.engine.dispose()


def test_interrupted_credential_write_can_retry_without_bad_canonical_file(tmp_path, monkeypatch):
    from infra.handoff import bootstrap
    from packages.config import Settings
    from packages.storage.database import Database

    db = Database(Settings(_env_file=None, database_url=f"sqlite:///{tmp_path / 'new.db'}"))
    db.migrate()
    original = bootstrap.json.dump

    def interrupted(value, stream, **kwargs):
        stream.write('{"partial":')
        raise OSError("simulated process interruption")

    monkeypatch.setattr(bootstrap.json, "dump", interrupted)
    with pytest.raises(OSError):
        initialize_identity(db, tmp_path / "access.json")
    assert not (tmp_path / "access.json").exists()
    monkeypatch.setattr(bootstrap.json, "dump", original)
    assert initialize_identity(db, tmp_path / "access.json")["tokens"]["admin"]
    db.engine.dispose()
