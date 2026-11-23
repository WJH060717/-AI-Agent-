"""Stopped-service full backup/restore. Never drop, truncate or overwrite a target."""

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import tomllib
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath, PureWindowsPath

from sqlalchemy import MetaData, func, select, text
from sqlalchemy.engine import Connection, make_url

from packages.config import Settings
from packages.storage import schema_v6 as t
from packages.storage.database import Database
from packages.storage.service import DataService, file_digest
from scripts.backup_contracts import BackupManifest

ROOT = Path(__file__).resolve().parents[1]
HEAD = "0006_d9"


def database_url(settings: Settings):
    if settings.database_url is None:
        raise ValueError("BACKUP_DATABASE_REQUIRED")
    url = make_url(settings.database_url.get_secret_value())
    if url.get_backend_name() == "postgresql":
        allowed = {"sslmode", "sslrootcert", "sslcert", "sslkey"}
        if (
            not url.host
            or not url.username
            or not url.database
            or not set(url.query) <= allowed
            or any(not isinstance(v, str) for v in url.query.values())
        ):
            raise ValueError("UNSUPPORTED_BACKUP_DATABASE_OPTIONS")
        # SQLAlchemy and libpq may otherwise inherit different endpoint/service options.
        if any(k.upper().startswith("PG") for k in os.environ):
            raise ValueError("UNSUPPORTED_BACKUP_DATABASE_ENVIRONMENT")
    elif url.get_backend_name() == "sqlite":
        if url.query or not url.database or url.database == ":memory:":
            raise ValueError("UNSUPPORTED_BACKUP_DATABASE_OPTIONS")
    else:
        raise ValueError("UNSUPPORTED_BACKUP_ENGINE")
    return url


def encoded(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def safe_path(root: Path, name: str) -> Path:
    relative = PurePosixPath(name)
    if (
        not name
        or "\\" in name
        or ":" in name
        or PureWindowsPath(name).drive
        or relative.is_absolute()
        or ".." in relative.parts
        or relative.as_posix() != name
        or any(ord(c) < 32 for c in name)
    ):
        raise ValueError("INVALID_BACKUP_PATH")
    result = root / name
    for part in (result, *result.parents):
        if part.is_symlink() or part.is_junction():
            raise ValueError("BACKUP_PATH_LINK")
    if not result.resolve().is_relative_to(root.resolve()):
        raise ValueError("BACKUP_PATH_ESCAPE")
    return result


def file_record(path: Path) -> dict:
    return {"sha256": file_digest(path), "bytes": path.stat().st_size}


def table_states(conn: Connection) -> dict:
    metadata = MetaData()
    metadata.reflect(conn)
    expected = set(t.metadata.tables) | {"alembic_version"}
    if set(metadata.tables) != expected:
        raise ValueError("UNEXPECTED_DATABASE_SCHEMA")
    result = {}
    for name, table in sorted(metadata.tables.items()):
        query = select(table).order_by(*table.primary_key.columns)
        digest = hashlib.sha256()
        rows = 0
        for row in conn.execution_options(stream_results=True).execute(query).mappings():
            digest.update(encoded(dict(row)))
            rows += 1
        result[name] = {"rows": rows, "sha256": digest.hexdigest()}
    return result


@contextmanager
def frozen_database(db: Database):
    """Hold write exclusion for the whole copy; refuse queued/running work."""
    with db.engine.connect() as conn:
        try:
            if conn.dialect.name == "sqlite":
                conn.exec_driver_sql("PRAGMA busy_timeout=1000")
                conn.exec_driver_sql("BEGIN IMMEDIATE")
            elif conn.dialect.name == "postgresql":
                conn.execute(text("SET LOCAL lock_timeout='3s'"))
                names = sorted(set(t.metadata.tables) | {"alembic_version"})
                conn.execute(
                    text("LOCK TABLE " + ",".join('"' + n + '"' for n in names) + " IN SHARE MODE")
                )
            else:
                raise ValueError("UNSUPPORTED_BACKUP_ENGINE")
            if conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one() != HEAD:
                raise ValueError("MIGRATION_MISMATCH")
            if conn.execute(
                select(func.count())
                .select_from(t.jobs)
                .where(t.jobs.c.state.in_(["queued", "running"]))
            ).scalar_one():
                raise ValueError("QUEUE_NOT_DRAINED")
            yield conn
        finally:
            conn.rollback()


def pg_tool(settings: Settings, tool: str, args: list[str]) -> None:
    url = database_url(settings)
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("PG")}
    env.update(
        PGHOST=url.host or "localhost",
        PGPORT=str(url.port or 5432),
        PGUSER=url.username or "",
        PGPASSWORD=url.password or "",
        PGDATABASE=url.database or "",
        PGCONNECT_TIMEOUT="10",
    )
    # libpq TLS parameters are preserved; no URL or password in argv/output.
    for key in ("sslmode", "sslrootcert", "sslcert", "sslkey"):
        if key in url.query:
            env["PG" + key.upper()] = str(url.query[key])
    executable = (
        str(settings.backup_pg_bin / (tool + (".exe" if os.name == "nt" else "")))
        if settings.backup_pg_bin
        else tool
    )
    result = subprocess.run(
        [executable, *args],
        env=env,
        capture_output=True,
        timeout=settings.backup_timeout_seconds,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )
    if result.returncode:
        raise ValueError("POSTGRES_BACKUP_TOOL_FAILED")


def verify_references(service: DataService) -> dict:
    count = reports = 0
    with service.db.engine.connect() as conn:
        workspaces = conn.execute(select(t.workspaces.c.id)).scalars().all()
    for workspace in workspaces:
        actor = service.system_actor(workspace)
        with service.db.engine.connect() as conn:
            ids = (
                conn.execute(
                    select(t.events.c.event_id).where(t.events.c.workspace_id == workspace)
                )
                .scalars()
                .all()
            )
            report_rows = (
                conn.execute(select(t.reports).where(t.reports.c.workspace_id == workspace))
                .mappings()
                .all()
            )
        for event_id in ids:
            service.verify_evidence(actor, event_id)
            count += 1
        for row in report_rows:
            payload = row["payload"]
            with service.db.engine.connect() as conn:
                snapshot = service._get(conn, t.snapshots, actor, payload["snapshot_id"])
            allowed = set(snapshot["event_ids"])
            for claim in payload["claims"]:
                for ref in claim["evidence_refs"]:
                    if ref["event_id"] not in allowed:
                        raise ValueError("REPORT_REFERENCE_OUT_OF_SNAPSHOT")
                    service.verify_evidence(actor, ref["event_id"])
            reports += 1
    return {"events_verified": count, "reports_verified": reports}


def create_backup(settings: Settings, destination: Path) -> dict:
    url = database_url(settings)
    if url.get_backend_name() == "sqlite" and not Path(url.database).is_file():
        raise ValueError("SOURCE_DATABASE_MISSING")
    destination = destination.absolute()
    safe_path(destination.parent, destination.name)
    if destination.exists():
        raise ValueError("TARGET_NOT_EMPTY")
    # A backup inside either evidence store could recursively contaminate future imports.
    for folder in (settings.raw_store, settings.staging_store):
        if destination.resolve().is_relative_to(folder.resolve()):
            raise ValueError("BACKUP_PATH_OVERLAP")
    db = Database(settings)
    try:
        with frozen_database(db) as conn:
            tables = table_states(conn)
            destination.mkdir(parents=True, exist_ok=False, mode=0o700)
            files = {}
            for row in conn.execute(select(t.objects)).mappings():
                source = safe_path(settings.raw_store.absolute(), row["storage_key"])
                if not source.is_file() or file_record(source) != {
                    "sha256": row["sha256"],
                    "bytes": row["byte_size"],
                }:
                    raise ValueError("RAW_FILE_INTEGRITY")
                name = "raw/" + row["storage_key"]
                output = safe_path(destination, name)
                output.parent.mkdir(parents=True, exist_ok=True)
                if not output.exists():
                    with source.open("rb") as reader, output.open("xb") as writer:
                        shutil.copyfileobj(reader, writer)
                files[name] = file_record(output)
                if files[name] != file_record(source):
                    raise ValueError("RAW_CHANGED_DURING_BACKUP")
            for row in conn.execute(select(t.batches)).mappings():
                source = safe_path(settings.staging_store.absolute(), row["staging_key"])
                if not source.exists():
                    if not row["object_id"]:
                        raise ValueError("STAGING_OBJECT_MISSING")
                    continue
                name = "staging/" + row["staging_key"]
                output = safe_path(destination, name)
                output.parent.mkdir(parents=True, exist_ok=True)
                with source.open("rb") as reader, output.open("xb") as writer:
                    shutil.copyfileobj(reader, writer)
                files[name] = file_record(output)
                if files[name] != {"sha256": row["sha256"], "bytes": row["byte_size"]}:
                    raise ValueError("STAGING_FILE_INTEGRITY")
            checks = verify_references(DataService(db, settings))
            engine = db.engine.dialect.name
            dbfile = "database.sqlite" if engine == "sqlite" else "database.dump"
            if engine == "sqlite":
                # Separate read connection while BEGIN IMMEDIATE prevents all writers.
                with (
                    sqlite3.connect(db.engine.url.database) as source,
                    sqlite3.connect(destination / dbfile) as target,
                ):
                    source.backup(target)
            else:
                snapshot = conn.execute(text("SELECT pg_export_snapshot()")).scalar_one()
                pg_tool(
                    settings,
                    "pg_dump",
                    [
                        "--format=custom",
                        "--no-owner",
                        "--no-privileges",
                        "--snapshot=" + snapshot,
                        "--file=" + str(destination / dbfile),
                    ],
                )
            files[dbfile] = file_record(destination / dbfile)
            config = {
                key: getattr(settings, key)
                for key in (
                    "app_env",
                    "model_provider",
                    "detection_event_limit",
                    "snapshot_event_limit",
                    "worker_lease_seconds",
                    "worker_heartbeat_seconds",
                    "import_chunk_lines",
                )
            }
            (destination / "config.json").write_bytes(encoded(config))
            files["config.json"] = file_record(destination / "config.json")
            for name in (
                "pyproject.toml",
                "requirements-dev.lock",
                "apps/web/package-lock.json",
                "infra/compose.yaml",
            ):
                if (ROOT / name).is_file():
                    out = safe_path(destination, "deployment/" + name)
                    out.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(ROOT / name, out)
                    files["deployment/" + name] = file_record(out)
            version = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))[
                "project"
            ]["version"]
            high_water = conn.execute(select(func.max(t.members.c.publication))).scalar_one() or 0
            payload = dict(
                version="d12-backup@1.0.0",
                created_at=datetime.now(UTC).isoformat(),
                engine=engine,
                migration_head=HEAD,
                database_file=dbfile,
                application_version=version,
                sensitivity="private_database_and_authorized_raw_evidence",
                tables=tables,
                files=files,
                publication_high_water=high_water,
                **checks,
            )
            BackupManifest.model_validate(payload)
            with (destination / "manifest.json").open("xb") as stream:
                stream.write(encoded(payload))
            return payload
    finally:
        db.engine.dispose()


def verify_backup(folder: Path) -> dict:
    path = safe_path(folder.absolute(), "manifest.json")
    payload = BackupManifest.model_validate_json(path.read_bytes()).model_dump(mode="json")
    if payload["database_file"] != (
        "database.sqlite" if payload["engine"] == "sqlite" else "database.dump"
    ):
        raise ValueError("BACKUP_ENGINE_MISMATCH")
    if payload["database_file"] not in payload["files"] or "config.json" not in payload["files"]:
        raise ValueError("BACKUP_INCOMPLETE")
    for name, expected in payload["files"].items():
        file = safe_path(folder.absolute(), name)
        if not file.is_file() or file_record(file) != expected:
            raise ValueError("BACKUP_FILE_INTEGRITY")
    return payload


def restore_backup(settings: Settings, folder: Path) -> dict:
    url = database_url(settings)
    payload = verify_backup(folder)
    version = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"][
        "version"
    ]
    if version != payload["application_version"]:
        raise ValueError("APPLICATION_VERSION_MISMATCH")
    if url.get_backend_name() != payload["engine"]:
        raise ValueError("BACKUP_ENGINE_MISMATCH")
    dirs = [settings.raw_store.absolute(), settings.staging_store.absolute()]
    for directory in dirs:
        safe_path(directory.parent, directory.name)
        if directory.exists():
            raise ValueError("TARGET_NOT_EMPTY")
        if directory.resolve().is_relative_to(folder.resolve()) or folder.resolve().is_relative_to(
            directory.resolve()
        ):
            raise ValueError("BACKUP_PATH_OVERLAP")
    if any(
        a.resolve().is_relative_to(b.resolve()) for a, b in ((dirs[0], dirs[1]), (dirs[1], dirs[0]))
    ):
        raise ValueError("BACKUP_PATH_OVERLAP")
    if payload["engine"] == "sqlite":
        database_path = Path(url.database).absolute()
        safe_path(database_path.parent, database_path.name)
        if database_path.exists():
            raise ValueError("TARGET_NOT_EMPTY")
        # Exclusive reservation avoids replacing a database created concurrently.
        database_path.parent.mkdir(parents=True, exist_ok=True)
        with (
            database_path.open("xb") as out,
            (folder / payload["database_file"]).open("rb") as source,
        ):
            shutil.copyfileobj(source, out)
    else:
        db = Database(settings)
        try:
            with db.engine.connect() as conn:
                if conn.execute(
                    text(
                        "SELECT count(*) FROM pg_class c JOIN pg_namespace n "
                        "ON n.oid=c.relnamespace WHERE n.nspname "
                        "NOT IN ('pg_catalog','information_schema') "
                        "AND n.nspname NOT LIKE 'pg_toast%' AND n.nspname NOT LIKE 'pg_temp%' "
                    )
                ).scalar_one():
                    raise ValueError("TARGET_NOT_EMPTY")
                pg_tool(
                    settings,
                    "pg_restore",
                    [
                        "--single-transaction",
                        "--exit-on-error",
                        "--no-owner",
                        "--no-privileges",
                        "--dbname=" + (url.database or ""),
                        str((folder / payload["database_file"]).absolute()),
                    ],
                )
        finally:
            db.engine.dispose()
    # On an interrupted restore, retain partial target for inspection; never auto-delete it.
    for directory in dirs:
        directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    for name in payload["files"]:
        for prefix, destination in (("raw/", dirs[0]), ("staging/", dirs[1])):
            if name.startswith(prefix):
                out = safe_path(destination, name[len(prefix) :])
                out.parent.mkdir(parents=True, exist_ok=True)
                with (folder / name).open("rb") as source, out.open("xb") as target:
                    shutil.copyfileobj(source, target)
    db = Database(settings)
    try:
        with frozen_database(db) as conn:
            if table_states(conn) != payload["tables"]:
                raise ValueError("RESTORED_DATABASE_MISMATCH")
            checks = verify_references(DataService(db, settings))
            if any(checks[k] != payload[k] for k in checks):
                raise ValueError("RESTORED_REFERENCE_MISMATCH")
        return {
            "verified": True,
            "migration_head": HEAD,
            "tables_verified": len(payload["tables"]),
            **checks,
        }
    finally:
        db.engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["create", "verify", "restore"])
    parser.add_argument("--folder", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.action == "verify":
            result = verify_backup(args.folder)
        elif args.action == "create":
            result = create_backup(Settings(), args.folder)
        else:
            result = restore_backup(Settings(), args.folder)
        print(
            json.dumps(
                {
                    "action": args.action,
                    "verified": True,
                    "reports_verified": result["reports_verified"],
                }
            )
        )
    except Exception as exc:
        # DB/tool exceptions may contain credentials or SQL values. Print only safe code.
        code = (
            str(exc)
            if type(exc) is ValueError and str(exc).replace("_", "").isalnum()
            else type(exc).__name__
        )
        print(json.dumps({"verified": False, "error": code}))
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
