"""Actual disposable PostgreSQL recovery drill; public evidence contains no DB secrets."""

import argparse
import json
import secrets
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

import psycopg
from psycopg import sql

from packages.config import Settings
from packages.storage.analysis import AnalysisService
from packages.storage.database import Database
from packages.storage.service import DataService, file_digest
from scripts.backup import create_backup, encoded, frozen_database, restore_backup, verify_backup
from tests.integration.d6_helpers import pending

ROOT = Path(__file__).resolve().parents[1]


def drill(output: Path) -> dict:
    output.mkdir(parents=True, exist_ok=False)
    info = json.loads((ROOT / ".tools/pg-sandbox.json").read_bytes())
    runtime = Path(info["runtime"])
    password = (runtime / "password").read_text(encoding="ascii")
    names = ["trace_d12_" + secrets.token_hex(8) for _ in range(2)]
    with psycopg.connect(
        host="127.0.0.1",
        port=info["port"],
        user="trace_owner",
        password=password,
        dbname="postgres",
        autocommit=True,
    ) as conn:
        server = conn.execute("SHOW server_version").fetchone()[0]
        for name in names:
            conn.execute(sql.SQL("CREATE DATABASE {} ENCODING 'UTF8'").format(sql.Identifier(name)))
    # Keep private dumps in OS temp, outside distributable artifacts and release catalog.
    private = Path(tempfile.mkdtemp(prefix="trace-d12-private-recovery-"))
    settings = [
        Settings(
            _env_file=None,
            app_env="test",
            model_provider="disabled",
            database_url=f"postgresql+psycopg://trace_owner:{password}@127.0.0.1:{info['port']}/{name}",
            raw_store=private / str(i) / "raw",
            staging_store=private / str(i) / "staging",
            backup_pg_bin=runtime / "pgsql/bin",
        )
        for i, name in enumerate(names)
    ]
    source_db = Database(settings[0])
    source_db.migrate()
    service = DataService(source_db, settings[0])
    workspace, tokens = service.init_workspace("authorized synthetic recovery drill")
    actor, _, run = pending(
        (settings[0], source_db, service, workspace, tokens), mode="deterministic"
    )
    service.process_one()
    analysis = AnalysisService(service)
    before = analysis.get_report(actor, analysis.get_run(actor, run["run_id"])["report_id"])
    folder = private / "backup"
    with frozen_database(source_db):
        with psycopg.connect(
            host="127.0.0.1",
            port=info["port"],
            user="trace_owner",
            password=password,
            dbname=names[0],
            autocommit=True,
        ) as other:
            other.execute("SET lock_timeout='100ms'")
            try:
                other.execute("UPDATE workspaces SET name=name")
            except psycopg.errors.LockNotAvailable:
                writer_blocked = True
            else:
                raise AssertionError("BACKUP_WRITE_LOCK_NOT_HELD")
    start = time.perf_counter()
    manifest = create_backup(settings[0], folder)
    backup_seconds = time.perf_counter() - start
    verify_backup(folder)
    start = time.perf_counter()
    result = restore_backup(settings[1], folder)
    restore_seconds = time.perf_counter() - start
    target_db = Database(settings[1])
    restored = DataService(target_db, settings[1])
    restored_actor = restored.authenticate(tokens["admin"])
    restored_analysis = AnalysisService(restored)
    assert restored_analysis.get_report(restored_actor, before["report_id"]) == before
    new = restored_analysis.create_run(
        restored_actor,
        analysis.get_run(actor, run["run_id"])["incident_id"],
        "post-restore",
        mode="deterministic",
    )
    restored.process_one()
    new_state = restored_analysis.get_run(restored_actor, new["run_id"])
    assert new_state["state"] == "completed" and new_state["report_id"] != before["report_id"]
    assert restored_analysis.get_report(restored_actor, before["report_id"]) == before
    # Negative checks are real operations against these disposable targets only.
    negatives = {}
    for label, configured in (
        ("existing_source_rejected", settings[0]),
        ("existing_target_rejected", settings[1]),
    ):
        try:
            restore_backup(configured, folder)
        except ValueError as exc:
            assert str(exc) == "TARGET_NOT_EMPTY"
            negatives[label] = True
        else:
            raise AssertionError("NONEMPTY_TARGET_ACCEPTED")
    # Fresh directories force the database emptiness branch to execute.
    nonempty = settings[1].model_copy(
        update={"raw_store": private / "guard-raw", "staging_store": private / "guard-staging"}
    )
    try:
        restore_backup(nonempty, folder)
    except ValueError as exc:
        assert str(exc) == "TARGET_NOT_EMPTY" and not nonempty.raw_store.exists()
        negatives["nonempty_database_with_new_directories_rejected"] = True
    else:
        raise AssertionError("NONEMPTY_DATABASE_ACCEPTED")
    source_db.engine.dispose()
    target_db.engine.dispose()
    evidence = dict(
        version="d12-recovery@1.0.0",
        recorded_at=datetime.now(UTC).isoformat(),
        engine="postgresql",
        server_version=server,
        provenance="synthetic",
        backup_seconds=backup_seconds,
        restore_seconds=restore_seconds,
        backup_manifest_sha256=file_digest(folder / "manifest.json"),
        backup_bytes=sum(r["bytes"] for r in manifest["files"].values()),
        old_report_unchanged=True,
        new_investigation_completed=True,
        token_and_hmac_preserved=True,
        non_author_accepted=False,
        private_backup_distributed=False,
        concurrent_writer_blocked=writer_blocked,
        negatives=negatives,
        **result,
    )
    (output / "recovery.json").write_bytes(encoded(evidence))
    # This pointer contains no credentials, but is local operational metadata, not release input.
    (ROOT / ".tools/d12-last-recovery.json").write_bytes(
        encoded({"private_folder": str(private), "database_names": names})
    )
    return evidence


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = drill(args.output)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
