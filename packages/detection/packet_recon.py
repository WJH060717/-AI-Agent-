"""Passive IPv4 reconnaissance candidates with bounded source evidence."""

import json
from collections import defaultdict, deque
from collections.abc import Callable
from datetime import timedelta
from ipaddress import IPv4Address
from typing import Literal

from packages.contracts.models import ArpRequestObservation, Contract, NormalizedEvent
from packages.detection.common import finding
from packages.detection.fragmentation import MICROSECOND
from packages.detection.freeze import RULES, FrozenRulesError, config_digest
from packages.detection.limits import checkpoint

PORT_SCAN_RULE = "R24"
PORT_SCAN_FREEZE = RULES / "ipv4-port-scan-freeze.json"
PING_SWEEP_RULE = "R25"
PING_SWEEP_FREEZE = RULES / "ipv4-ping-sweep-freeze.json"
HOST_DISCOVERY_RULE = "R26"
HOST_DISCOVERY_FREEZE = RULES / "ethernet-host-discovery-v11-freeze.json"
LIMITED_BROADCAST = IPv4Address("255.255.255.255")


class PortScanRule(Contract):
    id: Literal["R24"]
    version: Literal["1.0.0"]
    window_seconds: Literal[60]
    minimum_ports: Literal[20]


class PingSweepRule(Contract):
    id: Literal["R25"]
    version: Literal["1.0.0"]
    window_seconds: Literal[10]
    minimum_destinations: Literal[8]


class HostDiscoveryRule(Contract):
    id: Literal["R26"]
    version: Literal["1.0.0", "1.1.0"]
    window_seconds: Literal[10]
    minimum_destinations: Literal[8]


def load_host_discovery_rule() -> HostDiscoveryRule:
    try:
        frozen = json.loads(HOST_DISCOVERY_FREEZE.read_bytes())
        rule = HostDiscoveryRule.model_validate(frozen["config"])
        if (
            rule.version != "1.1.0"
            or config_digest(rule.model_dump(mode="json")) != frozen["config_hash"]
        ):
            raise ValueError("host discovery configuration drift")
        return rule
    except (OSError, KeyError, TypeError, ValueError):
        raise FrozenRulesError("RULE_CONFIGURATION_DRIFT") from None


def load_ping_sweep_rule() -> PingSweepRule:
    try:
        frozen = json.loads(PING_SWEEP_FREEZE.read_bytes())
        rule = PingSweepRule.model_validate(frozen["config"])
        if config_digest(rule.model_dump(mode="json")) != frozen["config_hash"]:
            raise ValueError("ping sweep configuration drift")
        return rule
    except (OSError, KeyError, TypeError, ValueError):
        raise FrozenRulesError("RULE_CONFIGURATION_DRIFT") from None


def load_port_scan_rule() -> PortScanRule:
    try:
        frozen = json.loads(PORT_SCAN_FREEZE.read_bytes())
        rule = PortScanRule.model_validate(frozen["config"])
        if config_digest(rule.model_dump(mode="json")) != frozen["config_hash"]:
            raise ValueError("port scan configuration drift")
        return rule
    except (OSError, KeyError, TypeError, ValueError):
        raise FrozenRulesError("RULE_CONFIGURATION_DRIFT") from None


def _capture_scope(event: NormalizedEvent) -> tuple[str, ...]:
    return (
        str(event.workspace_id),
        str(event.dataset_id),
        event.sensor.observation_domain,
        event.sensor.sensor_id,
        event.sensor.instance_id,
        str(event.source_locators[0].object_id),
    )


def _distinct_witness(
    records: dict[str, NormalizedEvent],
    seconds: int,
    minimum: int,
    destination_key: Callable[[NormalizedEvent], int | IPv4Address],
) -> list[NormalizedEvent]:
    checkpoint(len(records))
    ordered = sorted(
        records.values(),
        key=lambda event: (
            event.event_time, event.source_locators[0].record_start, event.event_id,
        ),
    )
    duration = timedelta(seconds=seconds)
    window: deque[tuple[int | IPv4Address, NormalizedEvent]] = deque()
    latest: dict[int | IPv4Address, NormalizedEvent] = {}
    for event in ordered:
        checkpoint()
        while window and event.event_time - window[0][1].event_time > duration:
            checkpoint()
            destination, expired = window.popleft()
            if latest[destination] is expired:
                del latest[destination]
        destination = destination_key(event)
        window.append((destination, event))
        latest[destination] = event
        if len(latest) == minimum:
            return sorted(latest.values(), key=lambda e: (e.event_time, e.event_id))
    return []


def detect_port_scans(
    events: list[NormalizedEvent], session_id: str, rule: PortScanRule
) -> list[dict]:
    groups: dict[tuple[str, ...], dict[str, NormalizedEvent]] = defaultdict(dict)
    for event in events:
        checkpoint()
        packet, src, dst = event.packet, event.src, event.dst
        if (
            packet is None
            or src is None
            or dst is None
            or not isinstance(src.ip, IPv4Address)
            or not isinstance(dst.ip, IPv4Address)
            or src.ip == dst.ip
            or src.port is None
            or not dst.port
            or packet.protocol_number != 6
            or packet.tcp_flags != 2
            or packet.tcp_payload_bytes_captured != 0
            or packet.more_fragments
            or packet.fragment_offset_bytes
            or packet.captured_length != packet.wire_length
        ):
            continue
        key = (*_capture_scope(event), str(src.ip), str(dst.ip))
        groups[key][event.event_id] = event

    results = []
    for key, records in sorted(groups.items()):
        witness = _distinct_witness(
            records, rule.window_seconds, rule.minimum_ports, lambda e: e.dst.port
        )
        if not witness:
            continue
        results.append(
            finding(
                rule, witness, session_id, list(key[3:]), "ipv4_destination_port_spread",
                attack_subtype="Recon-PortScan",
                maliciousness="unknown",
                distinct_observed_destination_ports=rule.minimum_ports,
                observation_span_us=(witness[-1].event_time - witness[0].event_time)
                // MICROSECOND,
                contributing_evidence_ids=[e.event_id for e in witness],
                limitations=[
                    "仅确认可见来源对同一目标的 TCP 目的端口覆盖形态。",
                    "授权、操作者、目标端口实际开放状态与漏洞证据仍未知。",
                ],
            )
        )
    return results


def _usable_ipv4(address: IPv4Address | None) -> bool:
    return (
        isinstance(address, IPv4Address)
        and not address.is_unspecified
        and not address.is_multicast
        and address != LIMITED_BROADCAST
    )


def detect_host_discovery(
    events: list[NormalizedEvent], session_id: str, rule: HostDiscoveryRule
) -> list[dict]:
    groups: dict[tuple[str, ...], dict[str, NormalizedEvent]] = defaultdict(dict)
    for event in events:
        checkpoint()
        packet, src, dst = event.packet, event.src, event.dst
        if (
            not isinstance(packet, ArpRequestObservation)
            or src is None
            or dst is None
            or not _usable_ipv4(src.ip)
            or not _usable_ipv4(dst.ip)
            or src.ip == dst.ip
        ):
            continue
        groups[(*_capture_scope(event), str(src.ip), packet.sender_mac)][event.event_id] = event

    results = []
    for key, records in sorted(groups.items()):
        witness = _distinct_witness(
            records, rule.window_seconds, rule.minimum_destinations, lambda e: e.dst.ip
        )
        if not witness:
            continue
        results.append(
            finding(
                rule, witness, session_id, list(key[3:]), "ethernet_arp_destination_spread",
                **({"attack_subtype": "Recon-HostDiscovery"} if rule.version == "1.0.0" else {}),
                maliciousness="unknown",
                distinct_observed_destination_ips=rule.minimum_destinations,
                observation_span_us=(witness[-1].event_time - witness[0].event_time)
                // MICROSECOND,
                contributing_evidence_ids=[e.event_id for e in witness],
                limitations=[
                    "仅确认同一可见来源向不同 IPv4 目标发送了 ARP 请求。",
                    "批量邻居解析可能符合相同行为。目标响应、探测授权和操作者仍未知。",
                ],
            )
        )
    return results


def detect_ping_sweeps(
    events: list[NormalizedEvent], session_id: str, rule: PingSweepRule
) -> list[dict]:
    groups: dict[tuple[str, ...], dict[str, NormalizedEvent]] = defaultdict(dict)
    for event in events:
        checkpoint()
        packet, src, dst = event.packet, event.src, event.dst
        if (
            packet is None
            or packet.protocol_number != 1
            or (packet.icmp_type, packet.icmp_code) != (8, 0)
            or packet.icmp_echo_header_complete is not True
            or packet.more_fragments
            or packet.fragment_offset_bytes
            or packet.captured_length != packet.wire_length
            or src is None
            or dst is None
            or not _usable_ipv4(src.ip)
            or not _usable_ipv4(dst.ip)
            or src.ip == dst.ip
        ):
            continue
        groups[(*_capture_scope(event), str(src.ip))][event.event_id] = event

    results = []
    for key, records in sorted(groups.items()):
        witness = _distinct_witness(
            records, rule.window_seconds, rule.minimum_destinations, lambda e: e.dst.ip
        )
        if not witness:
            continue
        results.append(
            finding(
                rule, witness, session_id, list(key[3:]), "ipv4_icmp_echo_destination_spread",
                attack_subtype="Recon-PingSweep",
                maliciousness="unknown",
                distinct_observed_destination_ips=rule.minimum_destinations,
                observation_span_us=(witness[-1].event_time - witness[0].event_time)
                // MICROSECOND,
                contributing_evidence_ids=[e.event_id for e in witness],
                limitations=[
                    "仅确认可见来源向不同 IPv4 目标发送 ICMP Echo 请求。",
                    "本规则未配对响应，目标是否在线、探测授权与操作者仍未知。",
                ],
            )
        )
    return results
