"""Passive IPv4 burst candidates with bounded, replayable packet witnesses."""

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Literal

from pydantic import Field

from packages.contracts.models import Contract, FloodBehavior, NormalizedEvent
from packages.detection.common import finding, merged_dos_subtype, observe_flood
from packages.detection.fragmentation import MICROSECOND
from packages.detection.freeze import RULES, FrozenRulesError, config_digest
from packages.detection.limits import checkpoint

BURST_RULES = {
    "R15": "DDoS-PSHACK_Flood",
    "R16": "DDoS-RSTFINFlood",
    "R17": "DDoS-SynonymousIP_Flood",
    "R18": "DDoS-SYN_Flood",
    "R19": "DDoS-TCP_Flood",
    "R20": "DDoS-UDP_Flood",
    "R21": "DDoS-ICMP_Flood",
}
BURST_SCOPE_BEHAVIORS: dict[str, FloodBehavior] = {
    "R18": "SYN_Flood",
    "R19": "TCP_Flood",
    "R20": "UDP_Flood",
}
BURST_FREEZE = RULES / "ipv4-packet-bursts-v14-freeze.json"


class BurstRule(Contract):
    id: Literal["R15", "R16", "R17", "R18", "R19", "R20", "R21"]
    version: Literal["1.0.0", "1.1.0", "1.2.0", "1.3.0", "1.4.0"]
    window_records: Literal[64]
    minimum_matches: Literal[48]
    minimum_span_us: Literal[1000]
    maximum_span_us: Literal[250000]
    minimum_sockets: Literal[0, 16]
    uniform_udp_span_us: Literal[25000] | None = Field(
        default=None, exclude_if=lambda value: value is None
    )


def load_burst_rules(path: Path | None = None) -> dict[str, BurstRule]:
    try:
        frozen = json.loads((path or BURST_FREEZE).read_bytes())
        rules = {key: BurstRule.model_validate(value) for key, value in frozen["configs"].items()}
        values = {key: config.model_dump(mode="json") for key, config in rules.items()}
        version = frozen["version"]
        if (
            version not in {"1.0.0", "1.1.0", "1.2.0", "1.3.0", "1.4.0"}
            or (path is None and version != "1.4.0")
            or set(rules) != set(BURST_RULES)
            or any(
                rule.id != key
                or rule.version != (
                    "1.3.0" if version == "1.4.0" and key != "R18"
                    else "1.1.0" if version == "1.2.0" and key not in BURST_SCOPE_BEHAVIORS
                    else version
                )
                or rule.minimum_sockets != (16 if key in {"R18", "R20"} else 0)
                or rule.uniform_udp_span_us
                != (25000 if key == "R20" and rule.version != "1.0.0" else None)
                for key, rule in rules.items()
            )
            or config_digest(values) != frozen["config_hash"]
        ):
            raise ValueError("burst rule configuration drift")
        return rules
    except (OSError, KeyError, TypeError, ValueError):
        raise FrozenRulesError("RULE_CONFIGURATION_DRIFT") from None


def packet_shape(event: NormalizedEvent) -> str | None:
    packet, src, dst = event.packet, event.src, event.dst
    if (
        packet is None
        or src is None
        or dst is None
        or packet.more_fragments
        or packet.fragment_offset_bytes
    ):
        return None
    if packet.protocol_number == 6:
        flags = packet.tcp_flags
        if (
            flags == 24
            and packet.tcp_payload_bytes_captured == 0
            and packet.captured_length == packet.wire_length
        ):
            return "R15"
        if flags == 5:
            return "R16"
        if flags == 2:
            return "R17" if src.ip == dst.ip else "R18"
        if flags == 0:
            return "R19"
    if packet.protocol_number == 17 and src.port is not None and dst.port is not None:
        return "R20"
    if packet.protocol_number == 1 and (packet.icmp_type, packet.icmp_code) == (8, 0):
        return "R21"
    return None


def detect_bursts(
    events: list[NormalizedEvent], session_id: str, rules: dict[str, BurstRule]
) -> list[dict]:
    groups = defaultdict(dict)
    for event in events:
        checkpoint()
        if (
            event.packet is None
            or event.dst is None
            or event.packet.protocol_number not in {1, 6, 17}
        ):
            continue
        key = (
            str(event.workspace_id),
            str(event.dataset_id),
            event.sensor.observation_domain,
            event.sensor.sensor_id,
            event.sensor.instance_id,
            str(event.source_locators[0].object_id),
            str(event.dst.ip),
            event.packet.protocol_number,
        )
        groups[key][event.event_id] = event
    findings = []
    width = next(iter(rules.values())).window_records
    for key, records in sorted(groups.items()):
        ordered = sorted(
            records.values(),
            key=lambda event: (
                event.source_locators[0].record_start,
                event.event_id,
            ),
        )
        checkpoint(len(ordered))
        progressed_ports = set()
        if key[-1] == 6 and "R18" in rules and rules["R18"].version != "1.0.0":
            checkpoint(len(ordered))
            progressed_ports = {
                event.dst.port
                for event in ordered
                if event.dst.port is not None
                and not event.packet.fragment_offset_bytes
                and not event.packet.more_fragments
                and event.packet.tcp_flags is not None
                and event.packet.tcp_flags & 16
                and (event.packet.tcp_payload_bytes_captured or 0) > 0
            }
        shapes = []
        for event in ordered:
            shape = packet_shape(event)
            if shape == "R18" and event.dst.port in progressed_ports:
                shape = None
            if (
                shape == "R21"
                and "R21" in rules
                and rules["R21"].version != "1.0.0"
                and event.packet.icmp_echo_header_complete is not True
            ):
                shape = None
            shapes.append(shape)
        counts = Counter(shapes[: width - 1])
        for end in range(width - 1, len(ordered)):
            checkpoint()
            start = end - width + 1
            counts[shapes[end]] += 1
            winner = next(
                (rule for name, rule in rules.items() if counts[name] >= rule.minimum_matches), None
            )
            counts[shapes[start]] -= 1
            if winner is None:
                continue
            checkpoint(width)
            window = ordered[start : end + 1]
            times = [event.event_time for event in window]
            duration = (max(times) - min(times)) // MICROSECOND
            if not winner.minimum_span_us <= duration <= winner.maximum_span_us:
                continue
            matched = [
                event for index, event in enumerate(window, start) if shapes[index] == winner.id
            ]
            if winner.id == "R18" and winner.version == "1.4.0":
                ports = Counter(event.dst.port for event in matched if event.dst.port)
                port = max(ports, key=ports.__getitem__, default=None)
                if ports[port] < winner.minimum_matches:
                    continue
                matched = [event for event in matched if event.dst.port == port]
            sockets = {
                (event.src.ip, event.src.port, event.dst.port)
                for event in matched
                if event.src.port is not None and event.dst.port is not None
            }
            uniform = False
            if len(sockets) < winner.minimum_sockets:
                if winner.uniform_udp_span_us is None or duration > winner.uniform_udp_span_us:
                    continue
                complete_sizes = Counter(
                    event.packet.wire_length
                    for event in matched
                    if event.packet.captured_length == event.packet.wire_length
                )
                if max(complete_sizes.values(), default=0) < winner.minimum_matches:
                    continue
                uniform = True
            behavior = BURST_SCOPE_BEHAVIORS.get(winner.id)
            subtype = BURST_RULES[winner.id]
            classification = {}
            if winner.version in {"1.2.0", "1.3.0", "1.4.0"} and behavior is not None:
                classification["flood_observation"] = observe_flood(
                    matched, behavior, "flood_candidate"
                )
            if winner.version in {"1.3.0", "1.4.0"}:
                classification["attack_subtype"] = merged_dos_subtype(subtype)
            elif winner.version != "1.2.0" or behavior is None:
                classification["attack_subtype"] = subtype
            findings.append(
                finding(
                    winner,
                    window,
                    session_id,
                    list(key[3:]),
                    "ipv4_nonfragment_burst",
                    **classification,
                    maliciousness="unknown",
                    observed_packets=len(window),
                    observed_matches=len(matched),
                    distinct_observed_sockets=len(sockets),
                    observation_span_us=duration,
                    observed_packets_per_second=round(len(window) * 1_000_000 / duration, 3),
                    contributing_evidence_ids=[event.event_id for event in matched],
                    **(
                        {"burst_basis": "dense_uniform_udp" if uniform else "packet_shape"}
                        if winner.version != "1.0.0"
                        else {}
                    ),
                    limitations=[
                        "候选基于同探针的报文形态与速率，未核实分布式来源、服务中断或操作者。",
                        "单向窗不能完整验证握手、重传或应用进展，正常高负荷流量仍可能命中。",
                    ],
                )
            )
            break
    return findings
