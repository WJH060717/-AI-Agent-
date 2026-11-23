"""Read-only orphan inventory. Never automatically deletes evidence."""

import json
import time
from uuid import UUID

from sqlalchemy import select

from packages.config import Settings
from packages.storage import schema_v3 as t
from packages.storage.database import Database


def inventory(db: Database, settings: Settings) -> list[dict]:
    with db.engine.connect() as conn:
        referenced = set(conn.execute(select(t.objects.c.storage_key)).scalars())
        staged = set(conn.execute(select(t.batches.c.staging_key)).scalars())
        active = set(
            conn.execute(
                select(t.jobs.c.workspace_id).where(t.jobs.c.state.in_(["queued", "running"]))
            ).scalars()
        )
    result = []
    cutoff = time.time() - 86400
    for kind, root in (("raw", settings.raw_store), ("staging", settings.staging_store)):
        if not root.exists():
            continue
        base = root.resolve()
        for path in root.rglob("*"):
            if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(base):
                continue
            if path.suffix not in (".partial", ".jsonl") or path.stat().st_mtime >= cutoff:
                continue
            try:
                UUID(path.stem)
            except ValueError:
                continue
            relative = path.relative_to(root).as_posix()
            if (kind == "raw" and (relative in referenced or relative.split("/")[0] in active)) or (
                kind == "staging" and path.name in staged
            ):
                continue
            result.append(
                {"store": kind, "relative_path": relative, "reason": "unreferenced_older_than_24h"}
            )
    return result


if __name__ == "__main__":
    settings = Settings()
    print(
        json.dumps({"mode": "dry_run_only", "candidates": inventory(Database(settings), settings)})
    )
