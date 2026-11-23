"""Run integration tests against a NEW database in our disposable PostgreSQL sandbox."""

import json
import os
import secrets
import subprocess
import sys
from pathlib import Path

import psycopg
from psycopg import sql

from packages.config import Settings
from packages.storage.database import Database


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    info = json.loads((root / ".tools/pg-sandbox.json").read_text(encoding="utf-8"))
    password = (Path(info["runtime"]) / "password").read_text(encoding="ascii")
    database = "trace_d2_" + secrets.token_hex(6)
    with psycopg.connect(
        host="127.0.0.1",
        port=info["port"],
        dbname="postgres",
        user="trace_owner",
        password=password,
        autocommit=True,
    ) as conn:
        version = conn.execute("SHOW server_version").fetchone()[0]
        conn.execute(sql.SQL("CREATE DATABASE {} ENCODING 'UTF8'").format(sql.Identifier(database)))
    owner_url = f"postgresql+psycopg://trace_owner:{password}@127.0.0.1:{info['port']}/{database}"
    owner_db = Database(Settings(_env_file=None, database_url=owner_url))
    owner_db.migrate("0001_d2")
    from uuid import uuid4

    from packages.storage.schema_v1 import workspaces

    legacy_id = str(uuid4())
    with owner_db.engine.begin() as connection:
        connection.execute(workspaces.insert().values(id=legacy_id, name="D2 migration sentinel"))
    owner_db.migrate()
    with owner_db.engine.connect() as connection:
        assert connection.execute(workspaces.select().where(workspaces.c.id == legacy_id)).first()
    print("D2 -> D9 migration preserved existing workspace", flush=True)
    owner_db.engine.dispose()
    app_role, read_role = database + "_app", database + "_reader"
    app_password, read_password = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    with psycopg.connect(
        host="127.0.0.1",
        port=info["port"],
        dbname=database,
        user="trace_owner",
        password=password,
        autocommit=True,
    ) as conn:
        for role, secret in ((app_role, app_password), (read_role, read_password)):
            conn.execute(
                sql.SQL(
                    "CREATE ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD {}"
                ).format(sql.Identifier(role), sql.Literal(secret))
            )
            conn.execute(sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(sql.Identifier(role)))
        conn.execute(
            sql.SQL(
                "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {}"
            ).format(sql.Identifier(app_role))
        )
        conn.execute(
            sql.SQL("REVOKE INSERT, UPDATE, DELETE ON alembic_version FROM {}").format(
                sql.Identifier(app_role)
            )
        )
        conn.execute(
            sql.SQL(
                "REVOKE UPDATE, DELETE ON audit_logs, raw_objects, events, "
                "findings, snapshots, reports, batch_events, dataset_contexts, "
                "workspace_private_keys, incidents, incident_details, incident_catalogs, "
                "agent_transitions, report_reviews FROM {}"
            ).format(sql.Identifier(app_role))
        )
        conn.execute(
            sql.SQL("GRANT USAGE, SELECT ON SEQUENCE report_reviews_seq_seq TO {}").format(
                sql.Identifier(app_role)
            )
        )
        conn.execute(
            sql.SQL(
                "GRANT SELECT ON events, datasets, analysis_sessions, "
                "session_events, raw_objects TO {}"
            ).format(sql.Identifier(read_role))
        )
    for role, secret, statement in (
        (app_role, app_password, "CREATE TABLE forbidden_d2(x int)"),
        (read_role, read_password, "DELETE FROM events WHERE false"),
        (read_role, read_password, "SELECT * FROM role_tokens"),
        (read_role, read_password, "SELECT * FROM workspace_private_keys"),
        (app_role, app_password, "DELETE FROM incident_details WHERE false"),
        (app_role, app_password, "UPDATE incident_catalogs SET payload=payload WHERE false"),
        (app_role, app_password, "DELETE FROM agent_transitions WHERE false"),
        (app_role, app_password, "DELETE FROM report_reviews WHERE false"),
        (app_role, app_password, "UPDATE report_reviews SET comment=comment WHERE false"),
        (read_role, read_password, "SELECT * FROM agent_actions"),
    ):
        with psycopg.connect(
            host="127.0.0.1",
            port=info["port"],
            dbname=database,
            user=role,
            password=secret,
            autocommit=True,
        ) as conn:
            try:
                conn.execute(statement)
            except psycopg.errors.InsufficientPrivilege:
                continue
            raise RuntimeError("Database role boundary unexpectedly allowed forbidden operation")
    print(
        "Role boundary checks passed: app DDL / reader write / reader credentials denied",
        flush=True,
    )
    env = os.environ.copy()
    env["D2_TEST_DATABASE_URL"] = (
        f"postgresql+psycopg://{app_role}:{app_password}@127.0.0.1:{info['port']}/{database}"
    )
    print(f"PostgreSQL {version}: new disposable database {database}", flush=True)
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/integration", "-q", "-p", "no:cacheprovider"],
        cwd=root,
        env=env,
    )
    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
