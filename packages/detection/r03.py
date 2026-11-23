from collections import defaultdict
from pathlib import Path
from typing import Literal

from pydantic import Field

from packages.contracts.models import Contract, NormalizedEvent
from packages.detection.common import finding, strong_process
from packages.detection.limits import checkpoint
from packages.ingest.identity import precedes


class R03Config(Contract):
    id: Literal["R03"] = "R03"
    version: str = "1.0.0"
    window_seconds: int = Field(default=600, ge=1, le=600)
    service_parents: list[str] = Field(min_length=1, max_length=100)
    suspicious_children: list[str] = Field(min_length=1, max_length=100)
    allowed_pairs: list[tuple[str, str]] = Field(default_factory=list, max_length=100)


def config() -> R03Config:
    return R03Config.model_validate_json(
        (Path(__file__).resolve().parents[2] / "rules/R03.json").read_bytes()
    )


def detect_process_anomalies(
    events: list[NormalizedEvent], session_id: str, rule: R03Config | None = None
) -> list[dict]:
    rule = rule or config()
    processes = [e for e in events if e.event_type == "host.process" and strong_process(e)]
    parents = defaultdict(list)
    for event in processes:
        parents[
            (
                event.workspace_id,
                event.dataset_id,
                event.sensor.observation_domain,
                event.process.entity_id,
            )
        ].append(event)
    found = {}
    for child in processes:
        checkpoint()
        if (
            child.process.action != "create"
            or child.process.executable not in rule.suspicious_children
        ):
            continue
        for parent in parents[
            (
                child.workspace_id,
                child.dataset_id,
                child.sensor.observation_domain,
                child.process.parent_entity_id,
            )
        ]:
            checkpoint()
            if (
                parent.process.entity_id != child.process.parent_entity_id
                or parent.process.action != "create"
                or parent.process.executable not in rule.service_parents
                or parent.host != child.host
                or parent.workspace_id != child.workspace_id
                or parent.dataset_id != child.dataset_id
                or parent.sensor.observation_domain != child.sensor.observation_domain
                or (parent.process.executable, child.process.executable) in rule.allowed_pairs
                or not precedes(parent, child, rule.window_seconds)
            ):
                continue
            item = finding(
                rule,
                [parent, child],
                session_id,
                [str(child.asset_id), child.host.boot_id, child.process.entity_id, parent.event_id],
                "suspicious_process_parent",
                parent_id=parent.event_id,
                child_id=child.event_id,
                interpretation="基线服务产生未允许解释器的候选；不证明恶意，需核查运维与配置变更",
            )
            found[item["id"]] = item
    return sorted(found.values(), key=lambda f: f["id"])
