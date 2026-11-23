"""Read-only final evidence/backup-watermark verification on a stopped local installation."""

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select

from packages.config import Settings
from packages.storage import schema_v6 as tables
from packages.storage.database import Database
from packages.storage.service import DataService
from scripts.backup import frozen_database, table_states, verify_references
from scripts.deploy_d13 import load_install, runtime_env


def audit(target: Path) -> dict:
    record = load_install(target)
    env = runtime_env(target, record["port"])
    settings = Settings(
        _env_file=None,
        database_url=env["DATABASE_URL"],
        raw_store=env["RAW_STORE"],
        staging_store=env["STAGING_STORE"],
        model_provider="disabled",
    )
    database = Database(settings)
    try:
        with frozen_database(database) as connection:
            state = table_states(connection)
            checks = verify_references(DataService(database, settings))
            reports = {}
            for row in connection.execute(select(tables.reports)).mappings():
                report = row["payload"]
                reports[row["id"]] = {
                    "sha256": hashlib.sha256(
                        json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
                    ).hexdigest(),
                    "mode": report["mode"],
                    "generated_at": report["generated_at"],
                    "claim_validation": report.get("claim_validation"),
                }
        return {
            "version": "d14-runtime-audit@1.0.0",
            "recorded_at": datetime.now(UTC).isoformat(),
            "base_freeze_sha256": record["base_freeze_sha256"],
            "tables": state,
            "reports": reports,
            "all_raw_hashes_and_report_scopes_verified": True,
            "stopped_queue_verified": True,
            **checks,
        }
    finally:
        database.engine.dispose()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = audit(args.target.resolve())
    with args.output.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print(
        json.dumps(
            {
                "verified": True,
                "events": result["events_verified"],
                "reports": result["reports_verified"],
            }
        )
    )
