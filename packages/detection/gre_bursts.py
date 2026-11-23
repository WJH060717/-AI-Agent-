"""Bounded passive GRE behavior observations."""

import json
from collections import Counter, defaultdict
from typing import Literal

from packages.contracts.models import Contract, GreEncapsulation, NormalizedEvent
from packages.detection.common import finding
from packages.detection.fragmentation import MICROSECOND
from packages.detection.freeze import RULES, FrozenRulesError, config_digest
from packages.detection.limits import checkpoint
from packages.detection.packet_recon import _capture_scope

GRE_BURST_RULE = "R27"
GRE_BURST_FREEZE = RULES / "ipv4-gre-bursts-freeze.json"


class GreBurstRule(Contract):
    id: Literal["R27"]
    version: Literal["1.0.0"]
    window_records: Literal[64]
    minimum_matches: Literal[48]
    minimum_span_us: Literal[1000]
    maximum_span_us: Literal[250000]


def load_gre_burst_rule() -> GreBurstRule:
    try:
        frozen = json.loads(GRE_BURST_FREEZE.read_bytes())
        rule = GreBurstRule.model_validate(frozen["config"])
        if (
            rule.id != GRE_BURST_RULE
            or rule.version != "1.0.0"
            or config_digest(rule.model_dump(mode="json")) != frozen["config_hash"]
        ):
            raise ValueError("GRE configuration drift")
        return rule
    except (OSError, KeyError, TypeError, ValueError):
        raise FrozenRulesError("RULE_CONFIGURATION_DRIFT") from None


def detect_gre_bursts(
    events: list[NormalizedEvent], session: str, rule: GreBurstRule
) -> list[dict]:
    groups: dict[tuple[str, ...], dict[str, NormalizedEvent]] = defaultdict(dict)
    for event in events:
        checkpoint()
        if event.packet is None or event.packet.protocol_number != 47 or event.dst is None:
            continue
        groups[(*_capture_scope(event), str(event.dst.ip))][event.event_id] = event
    results = []
    for key, records in sorted(groups.items()):
        checkpoint(len(records))
        ordered = sorted(
            records.values(), key=lambda e: (e.source_locators[0].record_start, e.event_id)
        )
        width = rule.window_records
        shapes = [event.packet.gre_encapsulation for event in ordered]
        counts: Counter[GreEncapsulation | None] = Counter(shapes[:width-1])
        for end in range(width-1, len(ordered)):
            checkpoint()
            start = end + 1 - width
            current = shapes[end]
            counts[current] += 1
            shape = next(
                (kind for kind in ("ip", "ethernet") if counts[kind] >= rule.minimum_matches),
                None,
            )
            counts[shapes[start]] -= 1
            if shape is None:
                continue
            checkpoint(width)
            window = ordered[start:end+1]
            times = [event.event_time for event in window]
            span = (max(times)-min(times)) // MICROSECOND
            if not rule.minimum_span_us <= span <= rule.maximum_span_us:
                continue
            ids = [event.event_id for event in window if event.packet.gre_encapsulation == shape]
            results.append(finding(
                rule, window, session, list(key[3:]), "ipv4_gre_burst_observation",
                gre_encapsulation=shape,
                maliciousness="unknown",
                observation_span_us=span,
                contributing_evidence_ids=ids,
                limitations=[
                    "仅记录同一外层目标的 GRE 封装突发，家族、授权和服务影响未知。",
                ],
            ))
            break
    return results
