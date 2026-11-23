"""New handoff database only. Durable credentials precede the identity transaction."""

import json
import os
import re
import secrets
from pathlib import Path
from uuid import uuid4

from sqlalchemy import select, text

from packages.config import Settings
from packages.storage import schema_v4 as t
from packages.storage.database import Database
from packages.storage.service import DataService, digest


def initialize_identity(db: Database, path: Path) -> dict:
    if path.is_symlink():
        raise ValueError("IDENTITY_LINK_REFUSED")
    with db.engine.begin() as conn:
        existing = conn.execute(select(t.workspaces.c.id)).scalars().all()
        if not path.exists():
            if existing:
                raise ValueError("NONEMPTY_DATABASE_REFUSED")
            value = {
                "workspace_id": str(uuid4()),
                "tokens": {
                    role: secrets.token_urlsafe(32) for role in ("viewer", "analyst", "admin")
                },
            }
            temporary = path.with_name(path.name + "." + uuid4().hex + ".pending")
            try:
                with temporary.open("x", encoding="utf-8") as stream:
                    json.dump(value, stream, indent=2)
                    stream.flush()
                    os.fsync(stream.fileno())
                # Atomic, exclusive publication; unlike POSIX rename this cannot
                # replace a credential file created by a concurrent initializer.
                os.link(temporary, path)
            finally:
                temporary.unlink(missing_ok=True)
        else:
            value = json.loads(path.read_bytes())
        if set(value) != {"workspace_id", "tokens"} or set(value["tokens"]) != {
            "viewer",
            "analyst",
            "admin",
        }:
            raise ValueError("IDENTITY_INVALID")
        if not all(isinstance(v, str) and len(v) >= 32 for v in value["tokens"].values()):
            raise ValueError("IDENTITY_INVALID")
        if not existing:
            conn.execute(t.workspaces.insert().values(id=value["workspace_id"], name="handoff"))
            conn.execute(
                t.private_keys.insert().values(
                    workspace_id=value["workspace_id"], salt=secrets.token_hex(32)
                )
            )
            for role, token in value["tokens"].items():
                conn.execute(
                    t.tokens.insert().values(
                        workspace_id=value["workspace_id"], role=role, digest=digest(token.encode())
                    )
                )
        else:
            actual = {
                row.role: row.digest
                for row in conn.execute(
                    select(t.tokens.c.role, t.tokens.c.digest).where(
                        t.tokens.c.workspace_id == value["workspace_id"]
                    )
                )
            }
            if actual != {role: digest(token.encode()) for role, token in value["tokens"].items()}:
                raise ValueError("IDENTITY_DATABASE_MISMATCH")
    return value


def configure_roles(db: Database, password: str, sql_path: Path) -> None:
    if not re.fullmatch(r"[a-f0-9]{64}", password):
        raise ValueError("INVALID_APPLICATION_PASSWORD")
    statements = "\n".join(
        line for line in sql_path.read_text().splitlines() if not line.startswith("--")
    ).split(";")
    with db.engine.begin() as conn:
        for statement in statements:
            statement = statement.strip()
            if not statement:
                continue
            if statement.startswith("CREATE ROLE"):
                role = statement.split()[2]
                if conn.execute(
                    text("SELECT 1 FROM pg_roles WHERE rolname=:role"), {"role": role}
                ).first():
                    continue
            conn.exec_driver_sql(statement)
        conn.exec_driver_sql(f"ALTER ROLE trace_app LOGIN PASSWORD '{password}'")
        conn.exec_driver_sql("ALTER ROLE trace_reader NOLOGIN")


def main() -> None:
    settings = Settings(_env_file=None)
    if settings.model_provider != "disabled" or settings.model_api_key is not None:
        raise ValueError("MODEL_MUST_BE_DISABLED")
    if Path("/handoff/initialized.json").exists():
        value = json.loads(Path("/handoff/access.json").read_bytes())
        app_settings = Settings(_env_file=None, database_url=os.environ["HANDOFF_APP_DATABASE_URL"])
        existing_db = Database(app_settings)
        actor = DataService(existing_db, app_settings).authenticate(value["tokens"]["admin"])
        if actor.workspace_id != value["workspace_id"]:
            raise ValueError("IDENTITY_DATABASE_MISMATCH")
        existing_db.engine.dispose()
        print("Existing workspace verified; data and credentials unchanged.")
        return
    db = Database(settings)
    db.migrate()
    value = initialize_identity(db, Path("/handoff/access.json"))
    configure_roles(db, os.environ["HANDOFF_APP_PASSWORD"], Path("/opt/trace/handoff-roles.sql"))
    app_settings = Settings(_env_file=None, database_url=os.environ["HANDOFF_APP_DATABASE_URL"])
    app_db = Database(app_settings)
    service = DataService(app_db, app_settings)
    actor = service.authenticate(value["tokens"]["admin"])
    with app_db.engine.connect() as conn:
        dataset = conn.execute(
            select(t.datasets.c.id).where(
                t.datasets.c.workspace_id == actor.workspace_id,
                t.datasets.c.name == "入门示例（合成数据）",
            )
        ).scalar_one_or_none()
    if dataset is None:
        dataset = service.create_dataset(
            actor,
            {"name": "入门示例（合成数据）", "provenance_type": "synthetic"},
            "handoff-seed-dataset",
        )["dataset_id"]
    batch = service.stage_bytes(
        actor,
        dataset,
        "zeek",
        "handoff-example",
        "UTC",
        Path("/opt/trace/handoff-example.jsonl").read_bytes(),
        "handoff-seed-import",
    )
    Path("/handoff/initialized.json").write_text(
        json.dumps(
            {
                "workspace_id": actor.workspace_id,
                "dataset_id": dataset,
                "batch_id": batch["batch_id"],
                "model_provider": "disabled",
            }
        ),
        encoding="utf-8",
    )
    app_db.engine.dispose()
    db.engine.dispose()
    print("New workspace ready; local credentials saved. Model disabled.")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # Do not print database URLs, tokens or driver exception details.
        print("Handoff initialization failed: " + type(error).__name__)
        raise SystemExit(1) from None
