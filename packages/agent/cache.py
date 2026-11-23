"""Exact immutable-snapshot report cache identity; never reads evaluation data."""

import json
from pathlib import Path

from packages.agent.state import config_version
from packages.config import Settings
from packages.storage.service import digest

ROOT = Path(__file__).resolve().parents[2]


def pipeline_version() -> str:
    paths = [
        p
        for folder in ("agent", "contracts", "detection", "graph", "ingest", "knowledge")
        for p in (ROOT / "packages" / folder).glob("*.py")
    ]
    paths += list((ROOT / "rules").glob("*.json"))
    paths += list((ROOT / "knowledge/attack-18.1").glob("*.json"))
    paths += [
        ROOT / "packages/storage/service.py",
        ROOT / "packages/storage/analysis.py",
        ROOT / "packages/storage/evidence_projection.py",
    ]
    values = {
        str(p.relative_to(ROOT)).replace("\\", "/"): digest(p.read_bytes()) for p in sorted(paths)
    }
    return digest(json.dumps(values, sort_keys=True).encode())


def report_cache_key(
    settings: Settings, snapshot: dict, events: list[dict], findings: list[dict], budget: dict
) -> str:
    return digest(
        json.dumps(
            {
                "version": "report_cache@1.0.0",
                "pipeline": pipeline_version(),
                "knowledge": settings.knowledge_enabled,
                "model_config": config_version(settings),
                "snapshot": {
                    k: snapshot[k]
                    for k in ("workspace_id", "id", "incident_id", "scope", "event_ids")
                },
                "events": events,
                "findings": findings,
                "budget": budget,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    )
