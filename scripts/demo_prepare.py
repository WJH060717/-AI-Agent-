"""Prepare a disposable SQLite demo in a new directory.

This entry point never overwrites an existing directory and never enables a
model. It imports only the public synthetic D1 fixtures.
"""

import argparse
import json
from pathlib import Path
from uuid import uuid4

from packages.config import Settings
from packages.contracts.context import Asset, DatasetContext, SensorProfile
from packages.storage.context import ContextService
from packages.storage.database import Database
from packages.storage.service import DataService

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "data/fixtures/d1"
HOST = "33333333-3333-4333-8333-333333333333"


def context() -> DatasetContext:
    assets = json.loads((FIXTURE / "assets.json").read_text(encoding="utf-8"))
    return DatasetContext.model_validate(
        {
            "assets": [
                {
                    "asset_id": item["asset_id"],
                    "hostnames": [item["name"]],
                    "addresses": [
                        {
                            "ip": item["ip"],
                            "observation_domain": "lab-a",
                            "valid_from": "2026-11-14T00:00:00Z",
                            "valid_to": "2026-11-15T00:00:00Z",
                        }
                    ],
                }
                for item in assets
            ],
            "sensors": [
                {
                    "sensor_id": "net-a",
                    "source_type": "zeek",
                    "instance_id": "demo",
                    "observation_domain": "lab-a",
                    "clock_basis": "synthetic_clock",
                    "uncertainty_ms": 0,
                },
                {
                    "sensor_id": "auth-a",
                    "source_type": "linux_auth",
                    "asset_id": HOST,
                    "instance_id": "demo",
                    "observation_domain": "lab-a",
                    "clock_basis": "synthetic_clock",
                    "uncertainty_ms": 0,
                },
                {
                    "sensor_id": "audit-a",
                    "source_type": "linux_audit",
                    "asset_id": HOST,
                    "instance_id": "demo",
                    "observation_domain": "lab-a",
                    "clock_basis": "synthetic_clock",
                    "uncertainty_ms": 0,
                },
                {
                    "sensor_id": "alert-a",
                    "source_type": "suricata",
                    "instance_id": "demo",
                    "observation_domain": "lab-a",
                    "clock_basis": "synthetic_clock",
                    "uncertainty_ms": 0,
                },
            ],
        }
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    args = parser.parse_args()
    if args.root.exists():
        raise SystemExit("refusing to reuse an existing demo directory")
    args.root.mkdir(parents=True)
    db_path = (args.root / "demo.db").as_posix()
    settings = Settings(
        _env_file=None,
        app_env="demo",
        database_url=f"sqlite:///{db_path}",
        raw_store=args.root / "raw",
        staging_store=args.root / "staging",
        model_provider="disabled",
    )
    db = Database(settings)
    db.migrate()
    service = DataService(db, settings)
    workspace, tokens = service.init_workspace("demo")
    actor = service.system_actor(workspace)
    dataset = service.create_dataset(
        actor, {"name": "demo-d1", "provenance_type": "synthetic"}, "dataset"
    )
    ContextService(service).configure(actor, dataset["dataset_id"], context(), "context")
    for name, source, sensor in (
        ("zeek.jsonl", "zeek", "net-a"),
        ("linux_auth.jsonl", "linux_auth", "auth-a"),
        ("linux_audit.jsonl", "linux_audit", "audit-a"),
        ("suricata.jsonl", "suricata", "alert-a"),
    ):
        service.stage_bytes(
            actor,
            dataset["dataset_id"],
            source,
            sensor,
            "UTC",
            (FIXTURE / name).read_bytes(),
            f"demo-{name}",
        )
    while service.process_one():
        pass
    env = args.root / "demo.env"
    env.write_text(
        "\n".join(
            [
                f"DATABASE_URL=sqlite:///{db_path}",
                f"RAW_STORE={args.root / 'raw'}",
                f"STAGING_STORE={args.root / 'staging'}",
                "MODEL_PROVIDER=disabled",
                "APP_ENV=demo",
                "",
            ]
        ),
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "root": str(args.root),
                "workspace_id": workspace,
                "dataset_id": dataset["dataset_id"],
                "default_session_id": dataset["default_session_id"],
                "tokens_shown_once": tokens,
                "env_file": str(env),
                "model": "disabled",
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()