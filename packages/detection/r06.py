"""Originator byte counters in fixed connection-start buckets; no content attribution."""

import hashlib
import json
import math
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

from pydantic import Field

from packages.contracts.context import EgressBaseline
from packages.contracts.models import Contract, NormalizedEvent
from packages.detection.common import finding
from packages.detection.limits import checkpoint


class R06Config(Contract):
    id: Literal["R06"] = "R06"
    version: str = "1.0.0"
    window_seconds: Literal[300] = 300
    min_bytes: int = Field(default=10_000_000, ge=10_000_000)
    baseline_min_windows: int = Field(default=30, ge=30, le=120)
    p95_multiplier: Literal[3] = 3


def config() -> R06Config:
    return R06Config.model_validate_json(
        (Path(__file__).resolve().parents[2] / "rules/R06.json").read_bytes()
    )


def detect_egress(
    events: list[NormalizedEvent],
    session_id: str,
    rule: R06Config | None = None,
    baselines: list[EgressBaseline] | None = None,
) -> list[dict]:
    rule = rule or config()
    groups = defaultdict(list)
    for e in {e.event_id: e for e in events}.values():
        checkpoint()
        if (
            e.event_type != "network.connection"
            or e.sensor.type != "zeek"
            or not e.src
            or not e.dst
            or not e.network
            or e.network.bytes_out is None
            or not e.src.asset_id
            or e.src.resolution_quality != "inventory_interval"
            or e.dst.resolution_quality == "ambiguous"
        ):
            continue
        start = math.floor(e.event_time.timestamp() / 300) * 300
        error = e.time_quality.uncertainty_ms / 1000
        if (
            e.event_time.timestamp() - error < start
            or e.event_time.timestamp() + error >= start + 300
        ):
            continue
        key = (
            str(e.workspace_id),
            str(e.dataset_id),
            e.sensor.observation_domain,
            e.sensor.sensor_id,
            e.sensor.instance_id,
            str(e.src.asset_id),
            start,
        )
        groups[key].append(e)
    result = []
    for key, records in groups.items():
        checkpoint()
        total = sum(e.network.bytes_out for e in records)
        if total < rule.min_bytes:
            continue
        start = datetime.fromtimestamp(key[-1], UTC)
        matches = [
            b
            for b in baselines or []
            if str(b.asset_id) == key[5]
            and b.observation_domain == key[2]
            and b.sensor_id == key[3]
            and b.instance_id == key[4]
        ]
        reference = matches[0] if len(matches) == 1 else None
        samples = [s.bytes_out for s in reference.samples if s.end <= start] if reference else []
        p95 = (
            sorted(samples)[math.ceil(len(samples) * 0.95) - 1]
            if len(samples) >= rule.baseline_min_windows
            else None
        )
        if p95 is not None and total <= p95 * rule.p95_multiplier:
            continue
        frozen_baseline = reference.model_dump(mode="json") if reference else None
        baseline_hash = hashlib.sha256(
            json.dumps(frozen_baseline, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        result.append(
            finding(
                rule,
                records,
                session_id,
                [*key[3:], baseline_hash],
                "outbound_volume_anomaly" if p95 is not None else "fixed_threshold_signal",
                window_start=start.isoformat(),
                window_end=(start + timedelta(seconds=300)).isoformat(),
                statistics={
                    "bytes_out": total,
                    "baseline_windows": len(samples),
                    "p95_bytes": p95,
                    "metric": "connection_start_bytes_out@1",
                },
                baseline=frozen_baseline,
                baseline_hash=baseline_hash,
                interpretation=(
                    "出站连接计数高于固定阈值及正常开发基线；备份/上传亦可符合，不能证明外传内容"
                    if p95 is not None
                    else "基线不足，仅固定阈值出站连接计数信号；不能证明外传内容"
                ),
            )
        )
    return sorted(result, key=lambda f: f["id"])
