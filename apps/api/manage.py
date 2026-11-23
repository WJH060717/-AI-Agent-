"""Explicit DB management; tokens are printed once, never stored as plaintext."""

import argparse
import json

from sqlalchemy import select

from packages.config import Settings
from packages.storage.database import Database
from packages.storage.schema_v1 import workspaces
from packages.storage.service import DataService


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["migrate", "init-demo"])
    args = parser.parse_args()
    settings = Settings()
    db = Database(settings)
    if args.command == "migrate":
        db.migrate()
        print("Migration head: 0006_d9")
    else:
        with db.engine.connect() as connection:
            existing = connection.execute(
                select(workspaces.c.id).where(workspaces.c.name == "demo")
            ).first()
        if existing:
            print(
                json.dumps(
                    {
                        "workspace_id": existing[0],
                        "already_initialized": True,
                        "tokens_shown_once": {},
                    }
                )
            )
            return
        workspace, tokens = DataService(db, settings).init_workspace("demo")
        print(json.dumps({"workspace_id": workspace, "tokens_shown_once": tokens}))


if __name__ == "__main__":
    main()
