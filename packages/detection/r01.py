"""Deterministic R01 candidates; an observed pattern is not attacker attribution."""

import hashlib
import ipaddress
import json
import math
from bisect import bisect_right
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

from pydantic import Field

from packages.contracts.models import Contract, NormalizedEvent
from packages.detection.limits import checkpoint


class R01Config(Contract):
    id: str = "R01"
    version: str = "1.0.0"
    window_seconds: int = Field(default=60, ge=1, le=60)
    slide_seconds: int = Field(default=10, ge=1, le=10)
    port_threshold: int = Field(default=20, ge=2, le=1000)
    host_threshold: int = Field(default=10, ge=2, le=1000)
    internal_cidrs: list[str] = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]


def config() -> R01Config:
    return R01Config.model_validate_json(
        (Path(__file__).resolve().parents[2] / "rules/R01.json").read_bytes()
    )


def detect_scans(
    events: list[NormalizedEvent], session_id: str, rule: R01Config | None = None
) -> list[dict]:
    rule = rule or config()
    groups = defaultdict(list)
    networks = [ipaddress.ip_network(n) for n in rule.internal_cidrs]
    for event in events:
        if (
            event.event_type != "network.connection"
            or event.sensor.type != "zeek"
            or not event.src
            or not event.dst
            or not event.network
        ):
            continue
        if event.dst.port is None:
            continue
        base = (
            str(event.workspace_id),
            str(event.dataset_id),
            session_id,
            event.sensor.observation_domain,
            str(event.src.ip),
            event.network.transport,
        )
        groups[base + ("ports", str(event.dst.ip))].append(event)
        if any(event.dst.ip in net for net in networks if net.version == event.dst.ip.version):
            groups[base + ("hosts", str(event.dst.port))].append(event)
    results = []
    for key, records in groups.items():
        checkpoint()
        records = sorted(
            {e.event_id: e for e in records}.values(), key=lambda e: (e.event_time, e.event_id)
        )
        threshold = rule.port_threshold if key[-2] == "ports" else rule.host_threshold
        all_values = {e.dst.port if key[-2] == "ports" else str(e.dst.ip) for e in records}
        if len(all_values) < threshold:
            continue
        # Only evaluate windows that can contain an observed event; avoid iterating empty days.
        ends = set()
        for event in records:
            first = (
                math.ceil(event.event_time.timestamp() / rule.slide_seconds) * rule.slide_seconds
            )
            ends.update(range(first, first + rule.window_seconds + 1, rule.slide_seconds))
        hits = []
        times = [e.event_time.timestamp() for e in records]
        for end in sorted(ends):
            checkpoint()
            window = records[
                bisect_right(times, end - rule.window_seconds) : bisect_right(times, end)
            ]
            checkpoint(len(window))
            values = {e.dst.port if key[-2] == "ports" else str(e.dst.ip) for e in window}
            if len(values) >= threshold:
                hits.append((end, window))
        merged = []
        for end, window in hits:
            if merged and end - merged[-1][1] <= rule.slide_seconds:
                merged[-1][1] = end
                merged[-1][2].update({e.event_id: e for e in window})
            else:
                merged.append([end - rule.window_seconds, end, {e.event_id: e for e in window}])
        for start, end, evidence in merged:
            payload = [*key, rule.id, rule.version, start, end]
            ordered = sorted(evidence.values(), key=lambda e: (e.event_time, e.event_id))
            base_key = hashlib.sha256(
                json.dumps(payload, separators=(",", ":")).encode()
            ).hexdigest()
            finding_id = hashlib.sha256(
                json.dumps(
                    [base_key, [e.event_id for e in ordered], rule.model_dump()],
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest()
            checkpoint(references=len(ordered))
            results.append(
                {
                    "id": finding_id,
                    "rule_id": rule.id,
                    "rule_version": rule.version,
                    "base_key": base_key,
                    "config": rule.model_dump(),
                    "kind": key[-2],
                    "source_ip": key[-4],
                    "group_key": list(key),
                    "window_start": datetime.fromtimestamp(start, UTC).isoformat(),
                    "window_end": datetime.fromtimestamp(end, UTC).isoformat(),
                    "start_time": ordered[0].event_time.isoformat(timespec="microseconds"),
                    "end_time": ordered[-1].event_time.isoformat(timespec="microseconds"),
                    "evidence_ids": [e.event_id for e in ordered],
                    "severity": "medium",
                    "interpretation": "扫描候选；批准的运维扫描也可能符合此模式",
                }
            )
    return sorted(results, key=lambda finding: finding["id"])
