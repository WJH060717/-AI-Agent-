"""Bounded IPv4 fragment-burst candidates over passive packet observations."""

import json
from bisect import bisect_left, bisect_right
from collections import defaultdict
from datetime import timedelta
from pathlib import Path
from typing import Literal

from pydantic import Field, StrictInt

from packages.contracts.models import Contract, NormalizedEvent
from packages.detection.common import finding, merged_dos_subtype
from packages.detection.freeze import RULES, FrozenRulesError, config_digest
from packages.detection.limits import checkpoint

FRAGMENT_RULES = {
    "R12": (6, "DDoS-ACK_Fragmentation"),
    "R13": (17, "DDoS-UDP_Fragmentation"),
    "R14": (1, "DDoS-ICMP_Fragmentation"),
}
ACTIVE_FRAGMENT_RULES = RULES / "ipv4-fragments-v12"
PACKET_SCOPE_LIMIT = 100_000
MICROSECOND = timedelta(microseconds=1)


class FragmentRule(Contract):
    id: Literal["R12", "R13", "R14"]
    version: Literal["1.0.0", "1.1.0", "1.2.0"]
    window_records: Literal[64]
    minimum_pairs: Literal[20]
    minimum_span_us: Literal[1000]
    maximum_span_us: Literal[250000]
    maximum_pair_gap_us: StrictInt = Field(ge=1, le=250000)


def load_fragment_rules(directory: Path | None = None) -> dict[str, FragmentRule]:
    root = directory or ACTIVE_FRAGMENT_RULES
    try:
        rules = {
            rule: FragmentRule.model_validate_json((root / f"{rule}.json").read_bytes())
            for rule in FRAGMENT_RULES
        }
        frozen = json.loads((root / "ipv4-fragments-freeze.json").read_bytes())
        serialized = {rule: config.model_dump(mode="json") for rule, config in rules.items()}
        if (
            (directory is None and frozen["version"] != "1.2.0")
            or any(
                config.id != rule or config.version != frozen["version"]
                for rule, config in rules.items()
            )
            or frozen["configs"] != serialized
            or frozen["config_hash"] != config_digest(serialized)
        ):
            raise ValueError("fragment rule configuration drift")
        return rules
    except (OSError, KeyError, TypeError, ValueError):
        raise FrozenRulesError("RULE_CONFIGURATION_DRIFT") from None


def disjoint_observed_cycles(
    records: list[NormalizedEvent], rule: FragmentRule
) -> list[tuple[str, str]]:
    """Recognize complete, disjoint record cycles under identifier reuse."""
    if len(records) < 4 or len(records) % 2:
        return []
    checkpoint(len(records))
    pairs = []
    last_terminal = None
    for first, tail in zip(records[::2], records[1::2], strict=True):
        initial, terminal = first.packet, tail.packet
        elapsed = (tail.event_time - first.event_time) // MICROSECOND
        if (
            initial is None
            or terminal is None
            or initial.fragment_offset_bytes != 0
            or not initial.more_fragments
            or terminal.fragment_offset_bytes == 0
            or terminal.more_fragments
            or not 0 <= elapsed <= rule.maximum_pair_gap_us
            or (last_terminal is not None and first.event_time <= last_terminal)
        ):
            return []
        last_terminal = tail.event_time
        if rule.id != "R12" or initial.tcp_flags == 16:
            pairs.append((first.event_id, tail.event_id))
    return pairs


def fragment_pairs(
    window: list[NormalizedEvent], rule: FragmentRule
) -> tuple[list[tuple[str, str]], int]:
    """Pair observations without asserting distinct datagrams or complete reassembly."""
    checkpoint(len(window))
    groups = defaultdict(list)
    for event in window:
        packet = event.packet
        if packet is not None and event.src is not None:
            groups[event.src.ip, packet.ip_id].append(event)
    pairs = []
    max_gap = timedelta(microseconds=rule.maximum_pair_gap_us)
    reused_id_pairs = 0
    for records in groups.values():
        cycles = disjoint_observed_cycles(records, rule) if rule.version != "1.0.0" else []
        if cycles:
            pairs.extend(cycles)
            reused_id_pairs += len(cycles)
            continue
        initials, tails, whole, middle = [], [], [], []
        for event in sorted(records, key=lambda row: row.event_time):
            packet = event.packet
            if packet.fragment_offset_bytes == 0:
                (initials if packet.more_fragments else whole).append(event)
            elif not packet.more_fragments:
                tails.append(event)
            else:
                middle.append(event)
        initial_times = [event.event_time for event in initials]
        tail_times = [event.event_time for event in tails]
        whole_times = [event.event_time for event in whole]
        for first in initials:
            checkpoint()
            if rule.id == "R12" and first.packet.tcp_flags != 16:
                continue
            low, high = first.event_time - max_gap, first.event_time + max_gap
            if bisect_right(initial_times, high) - bisect_left(initial_times, low) != 1:
                continue
            if bisect_left(whole_times, low) != bisect_right(whole_times, high):
                continue
            left, right = bisect_left(tail_times, low), bisect_right(tail_times, high)
            if right - left != 1:
                continue
            tail = tails[left]
            tail_low, tail_high = tail.event_time - max_gap, tail.event_time + max_gap
            if bisect_right(initial_times, tail_high) - bisect_left(initial_times, tail_low) != 1:
                continue
            if bisect_left(whole_times, tail_low) != bisect_right(whole_times, tail_high):
                continue
            checkpoint(len(middle))
            if any(
                max(low, tail_low) <= item.event_time <= min(high, tail_high)
                and item.packet.fragment_offset_bytes >= tail.packet.fragment_offset_bytes
                for item in middle
            ):
                continue
            pairs.append((first.event_id, tail.event_id))
    return pairs, reused_id_pairs


def detect_fragmentation(
    events: list[NormalizedEvent], session_id: str, rules: dict[str, FragmentRule]
) -> list[dict]:
    by_protocol = {FRAGMENT_RULES[rule.id][0]: rule for rule in rules.values()}
    collections = defaultdict(dict)
    for event in events:
        checkpoint()
        if (
            event.event_type != "network.packet"
            or event.packet is None
            or event.dst is None
            or event.packet.protocol_number not in by_protocol
        ):
            continue
        source = event.source_locators[0]
        key = (
            str(event.workspace_id),
            str(event.dataset_id),
            event.sensor.observation_domain,
            event.sensor.sensor_id,
            event.sensor.instance_id,
            str(source.object_id),
            str(event.dst.ip),
            event.packet.protocol_number,
        )
        collections[key][event.event_id] = event
    results = []
    for key, records in sorted(collections.items()):
        rule = by_protocol[key[-1]]
        ordered = sorted(
            records.values(),
            key=lambda e: (e.source_locators[0].record_start, e.event_id),
        )
        firsts = [0]
        terminals = [0]
        for event in ordered:
            checkpoint()
            packet = event.packet
            initial = packet.fragment_offset_bytes == 0 and packet.more_fragments
            eligible_first = initial and (rule.id != "R12" or packet.tcp_flags == 16)
            terminal = packet.fragment_offset_bytes > 0 and not packet.more_fragments
            firsts.append(firsts[-1] + int(eligible_first))
            terminals.append(terminals[-1] + int(terminal))
        for end in range(rule.window_records, len(ordered) + 1):
            checkpoint()
            start = end - rule.window_records
            if (
                min(firsts[end] - firsts[start], terminals[end] - terminals[start])
                < rule.minimum_pairs
            ):
                continue
            witness = ordered[start:end]
            checkpoint(len(witness))
            times = [event.event_time for event in witness]
            span = (max(times) - min(times)) // MICROSECOND
            if not rule.minimum_span_us <= span <= rule.maximum_span_us:
                continue
            pairs, reused_id_pairs = fragment_pairs(witness, rule)
            if len(pairs) < rule.minimum_pairs:
                continue
            subtype = FRAGMENT_RULES[rule.id][1]
            if rule.version == "1.2.0":
                subtype = merged_dos_subtype(subtype)
            results.append(
                finding(
                    rule,
                    witness,
                    session_id,
                    [*key[3:]],
                    "ipv4_fragment_burst",
                    attack_subtype=subtype,
                    maliciousness="unknown",
                    observed_pairs=len(pairs),
                    paired_evidence_ids=[list(pair) for pair in pairs],
                    observed_packets=len(witness),
                    matched_fragment_records=2 * len(pairs),
                    observation_span_us=span,
                    observed_packets_per_second=round(len(witness) * 1_000_000 / span, 3),
                    limitations=[
                        "命中仅说明同采集器观测到分片突发形态，配对不证明完整重组或真实数据报总数。",
                        "合法大报文和高并发业务也可能命中；未核实分布式来源、服务中断或操作者身份。",
                        *(
                            ["标识复用配对依据为物理顺序连续、时间不重叠的完整记录序列。"]
                            if reused_id_pairs
                            else []
                        ),
                    ],
                    **(
                        {"reused_id_observed_pairs": reused_id_pairs}
                        if rule.version != "1.0.0"
                        else {}
                    ),
                )
            )
            break
    return results
