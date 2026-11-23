"""R02: identity-bound authentication sequence, never actor attribution."""

import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Literal

from pydantic import Field

from packages.contracts.models import Contract, NormalizedEvent
from packages.detection.limits import checkpoint
from packages.ingest.identity import precedes


class R02Config(Contract):
    id: Literal["R02"] = "R02"
    version: str = "1.0.0"
    failure_count: int = Field(default=5, ge=2, le=100)
    failure_window_seconds: int = Field(default=300, ge=1, le=300)
    success_after_seconds: int = Field(default=120, ge=1, le=120)


def config() -> R02Config:
    return R02Config.model_validate_json(
        (Path(__file__).resolve().parents[2] / "rules/R02.json").read_bytes()
    )


def detect_auth_sequence(
    events: list[NormalizedEvent], session_id: str, rule: R02Config | None = None
) -> list[dict]:
    rule = rule or config()
    groups = defaultdict(list)
    for e in {event.event_id: event for event in events}.values():
        checkpoint()
        if (
            e.event_type != "auth.login"
            or e.sensor.type != "linux_auth"
            or not e.auth
            or not e.user
            or not e.user.entity_id
            or not e.user.realm
            or not e.src
            or not e.asset_id
            or not e.host
            or not e.host.boot_id
            or e.host.asset_id != e.asset_id
            or "identity_ambiguous" in e.quality_flags
        ):
            continue
        key = (
            str(e.workspace_id),
            str(e.dataset_id),
            session_id,
            e.sensor.observation_domain,
            e.sensor.sensor_id,
            e.sensor.instance_id,
            e.user.realm,
            e.user.entity_id,
            str(e.src.ip),
            str(e.asset_id),
            e.host.boot_id,
            e.auth.service,
        )
        groups[key].append(e)
    results = []
    for key, records in groups.items():
        checkpoint()
        failures = []
        for event in sorted(records, key=lambda e: (e.event_time, e.event_id)):
            if event.auth.outcome == "failure":
                failures.append(event)
                continue
            if event.auth.outcome != "success":
                continue
            eligible = [f for f in failures if precedes(f, event)]
            if eligible:
                last = eligible[-1]
                eligible = [
                    f
                    for f in eligible
                    if (last.event_time - f.event_time).total_seconds()
                    + (last.time_quality.uncertainty_ms + f.time_quality.uncertainty_ms) / 1000
                    <= rule.failure_window_seconds
                ]
                if len(eligible) >= rule.failure_count and precedes(
                    last, event, rule.success_after_seconds
                ):
                    ids = [f.event_id for f in eligible] + [event.event_id]
                    base_key = hashlib.sha256(
                        json.dumps([*key, rule.id, rule.version, event.event_id]).encode()
                    ).hexdigest()
                    fid = hashlib.sha256(
                        json.dumps([base_key, ids, rule.model_dump()], sort_keys=True).encode()
                    ).hexdigest()
                    checkpoint(references=len(ids))
                    results.append(
                        {
                            "id": fid,
                            "base_key": base_key,
                            "rule_id": "R02",
                            "rule_version": rule.version,
                            "config": rule.model_dump(),
                            "kind": "auth_failure_then_success",
                            "evidence_ids": ids,
                            "failure_ids": ids[:-1],
                            "success_id": event.event_id,
                            "group_key": list(key),
                            "start_time": eligible[0].event_time.isoformat(timespec="microseconds"),
                            "end_time": event.event_time.isoformat(timespec="microseconds"),
                            "severity": "medium",
                            "interpretation": "认证失败后成功候选；"
                            "可能为正常输错密码、运维或凭据异常，需人工核查",
                        }
                    )
            failures = []
    return sorted(results, key=lambda f: f["id"])
