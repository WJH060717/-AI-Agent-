"""Bounded recognition of HTTP request header observations from passive PCAP."""

import json
from bisect import bisect_left
from collections import defaultdict
from heapq import heappop, heappush
from pathlib import Path
from typing import Literal

from packages.contracts.models import Contract, NormalizedEvent
from packages.detection.common import finding, merged_dos_subtype, observe_flood
from packages.detection.fragmentation import MICROSECOND
from packages.detection.freeze import RULES, FrozenRulesError, config_digest
from packages.detection.limits import checkpoint

HTTP_PACKET_RULES = {"R22": "DDoS-HTTP_Flood", "R23": "DDoS-SlowLoris"}
HTTP_PACKET_FREEZE = RULES / "http-packet-requests-v14-freeze.json"


class HttpBurstRule(Contract):
    id: Literal["R22"]
    version: Literal["1.0.0", "1.1.0", "1.2.0", "1.3.0"]
    connections: Literal[8]
    minimum_span_us: Literal[1000]
    maximum_span_us: Literal[250000]


class SlowHeaderRule(Contract):
    id: Literal["R23"]
    version: Literal["1.0.0", "1.1.0", "1.2.0", "1.3.0"]
    connections: Literal[8]
    minimum_progress_us: Literal[1000000]
    minimum_overlap_us: Literal[500000]
    maximum_span_us: Literal[20000000]
    maximum_segments: Literal[4]
    maximum_progress_bytes: Literal[128]


def http_packet_config(config: dict) -> HttpBurstRule | SlowHeaderRule:
    if config.get("id") == "R22":
        return HttpBurstRule.model_validate(config)
    return SlowHeaderRule.model_validate(config)


def load_http_packet_rules(path: Path | None = None) -> dict[str, HttpBurstRule | SlowHeaderRule]:
    try:
        frozen = json.loads((path or HTTP_PACKET_FREEZE).read_bytes())
        rules = {key: http_packet_config(value) for key, value in frozen["configs"].items()}
        configs = {key: rule.model_dump(mode="json") for key, rule in rules.items()}
        if (
            set(rules) != set(HTTP_PACKET_RULES)
            or (path is None and frozen["version"] != "1.4.0")
            or (rules["R22"].version, rules["R23"].version)
            != {
                "1.0.0": ("1.0.0", "1.0.0"),
                "1.1.0": ("1.0.0", "1.1.0"),
                "1.2.0": ("1.1.0", "1.2.0"),
                "1.3.0": ("1.2.0", "1.2.0"),
                "1.4.0": ("1.3.0", "1.3.0"),
            }.get(frozen["version"])
            or any(key != rule.id for key, rule in rules.items())
            or config_digest(configs) != frozen["config_hash"]
        ):
            raise ValueError("HTTP packet rule configuration drift")
        return rules
    except (OSError, KeyError, TypeError, ValueError):
        raise FrozenRulesError("RULE_CONFIGURATION_DRIFT") from None


def event_order(event: NormalizedEvent) -> tuple:
    return event.source_locators[0].record_start, event.event_id


def request_window(flows, rule: HttpBurstRule) -> tuple[list[NormalizedEvent], bool]:
    firsts = []
    for flow in flows:
        for event in flow:
            checkpoint()
            segment = event.packet.http_segment
            if (
                segment
                and segment.request_start
                and segment.text_prefix
                and segment.header_transitions[0] == 4
            ):
                firsts.append(event)
                break
    firsts.sort(key=lambda event: (event.event_time, event_order(event)))
    groups = []
    times = [event.event_time for event in firsts]
    for start in range(len(firsts) - rule.connections + 1):
        checkpoint()
        span = (times[start + rule.connections - 1] - times[start]) // MICROSECOND
        if rule.minimum_span_us <= span <= rule.maximum_span_us:
            if rule.version == "1.0.0":
                return firsts[start : start + rule.connections], True
            groups.append(start)
    if not groups:
        return [], False
    period = rule.maximum_span_us * MICROSECOND
    for index, first in enumerate(groups):
        checkpoint()
        earliest = bisect_left(times, times[first] + period, lo=first + rule.connections)
        next_group = bisect_left(groups, earliest, lo=index + 1)
        if next_group < len(groups):
            second = groups[next_group]
            if times[second] - times[first] <= 2 * period:
                return (
                    firsts[first : first + rule.connections]
                    + firsts[second : second + rule.connections],
                    True,
                )
    initial = groups[0]
    return firsts[initial : initial + rule.connections], False


def header_progress(flow: list[NormalizedEvent], rule: SlowHeaderRule) -> list[NormalizedEvent]:
    chain = []
    expected = state = 0
    legacy = rule.version == "1.0.0"
    for event in flow:
        checkpoint()
        packet = event.packet
        if packet.tcp_flags is not None and packet.tcp_flags & 7:
            chain = []
            continue
        if packet.tcp_payload_bytes_captured == 0:
            continue
        shape = packet.http_segment
        if shape is None or not shape.text_prefix:
            chain = []
            continue
        size = packet.tcp_payload_bytes_captured
        if shape.request_start:
            state = shape.header_transitions[0]
            chain = [event] if state != 4 else []
        elif chain:
            if (
                shape.sequence != expected
                or len(chain) >= rule.maximum_segments
                or event.event_time < chain[-1].event_time
            ):
                chain = []
                continue
            elapsed = (event.event_time - chain[0].event_time) // MICROSECOND
            state = shape.header_transitions[state]
            size_limited = legacy or elapsed >= rule.minimum_progress_us
            if (
                elapsed > rule.maximum_span_us
                or state == 4
                or (size_limited and size > rule.maximum_progress_bytes)
            ):
                chain = []
                continue
            interval = (
                elapsed if legacy else (event.event_time - chain[-1].event_time) // MICROSECOND
            )
            chain.append(event)
            if interval >= rule.minimum_progress_us:
                return chain
        expected = (shape.sequence + size) % (2**32)
    return []


def followup_progress(
    flow: list[NormalizedEvent], proof: list[NormalizedEvent], rule: SlowHeaderRule
) -> tuple[list[NormalizedEvent], bool]:
    state = 0
    for event in proof:
        state = event.packet.http_segment.header_transitions[state]
    delayed = proof[-1]
    packet = delayed.packet
    expected = (packet.http_segment.sequence + packet.tcp_payload_bytes_captured) % (2**32)
    chain = proof.copy()
    grace = rule.minimum_overlap_us * MICROSECOND
    delayed_order = event_order(delayed)
    for event in flow:
        checkpoint()
        if event_order(event) <= delayed_order:
            continue
        packet = event.packet
        if packet.tcp_flags is not None and packet.tcp_flags & 7:
            break
        if packet.tcp_payload_bytes_captured == 0:
            continue
        size, shape = packet.tcp_payload_bytes_captured, packet.http_segment
        if (
            shape is None
            or shape.request_start
            or not shape.text_prefix
            or shape.sequence != expected
            or event.event_time < chain[-1].event_time
            or event.event_time - proof[0].event_time > rule.maximum_span_us * MICROSECOND
            or len(chain) >= rule.maximum_segments
        ):
            break
        state = shape.header_transitions[state]
        since_progress = event.event_time - delayed.event_time
        if state == 4:
            return ([], False) if since_progress <= grace else (proof, False)
        if size > rule.maximum_progress_bytes:
            break
        chain.append(event)
        if since_progress >= grace:
            return chain, True
        expected = (shape.sequence + size) % (2**32)
    return proof, False


def overlap_window(
    proofs: list[list[NormalizedEvent]], rule: SlowHeaderRule
) -> list[NormalizedEvent]:
    proofs.sort(key=lambda proof: (proof[0].event_time, event_order(proof[0])))
    expires = []
    active = {}
    overlap = rule.minimum_overlap_us * MICROSECOND
    for index, proof in enumerate(proofs):
        checkpoint()
        ready_at = proof[0].event_time + overlap
        while expires and expires[0][0] < ready_at:
            checkpoint()
            _, expired = heappop(expires)
            del active[expired]
        heappush(expires, (proof[-1].event_time, index))
        active[index] = proof
        if len(active) == rule.connections:
            return [event for chain in active.values() for event in chain]
    return []


def slow_window(flows, rule: SlowHeaderRule) -> tuple[list[NormalizedEvent], bool]:
    initial = []
    confirmed = []
    for flow in flows:
        proof = header_progress(flow, rule)
        if not proof:
            continue
        if rule.version in {"1.0.0", "1.1.0"}:
            initial.append(proof)
            continue
        extended, supported = followup_progress(flow, proof, rule)
        if extended:
            initial.append(proof)
        if supported:
            confirmed.append(extended)
    if rule.version in {"1.2.0", "1.3.0"}:
        window = overlap_window(confirmed, rule)
        if window:
            return window, True
    return overlap_window(initial, rule), rule.version in {"1.0.0", "1.1.0"}


def detect_http_packets(events, session_id, rules) -> list[dict]:
    services = defaultdict(dict)
    for event in events:
        checkpoint()
        packet, src, dst = event.packet, event.src, event.dst
        if packet is None or packet.protocol_number != 6 or src is None or dst is None:
            continue
        if src.port is None or dst.port is None:
            continue
        service = (
            str(event.workspace_id),
            str(event.dataset_id),
            event.sensor.observation_domain,
            event.sensor.sensor_id,
            event.sensor.instance_id,
            str(event.source_locators[0].object_id),
            str(dst.ip),
            dst.port,
        )
        flows = services[service]
        flows.setdefault((str(src.ip), src.port), {})[event.event_id] = event
    results = []
    for service, records in sorted(services.items()):
        flows = [sorted(records[key].values(), key=event_order) for key in sorted(records)]
        for rule in rules.values():
            witness, classified = (
                request_window(flows, rule)
                if isinstance(rule, HttpBurstRule)
                else slow_window(flows, rule)
            )
            if not witness:
                continue
            times = [event.event_time for event in witness]
            classification = {}
            if rule.id == "R22" and rule.version in {"1.2.0", "1.3.0"}:
                classification["flood_observation"] = observe_flood(
                    witness, "HTTP_Flood", "flood_candidate" if classified else "request_burst_only"
                )
            if classified and (rule.id != "R22" or rule.version != "1.2.0"):
                subtype = HTTP_PACKET_RULES[rule.id]
                classification["attack_subtype"] = (
                    merged_dos_subtype(subtype) if rule.version == "1.3.0" else subtype
                )
            results.append(
                finding(
                    rule,
                    witness,
                    session_id,
                    list(service[3:]),
                    "http_request_observation" if classified else "http_request_unclassified",
                    maliciousness="unknown",
                    connection_count=(
                        len(witness) if isinstance(rule, HttpBurstRule) else rule.connections
                    ),
                    contributing_evidence_ids=[event.event_id for event in witness],
                    observation_span_us=(max(times) - min(times)) // MICROSECOND,
                    limitations=[
                        "只覆盖可见明文 HTTP 请求头形态，未核实业务负载、服务侧影响或恶意性。",
                        "时间和顺序只限定到该原件内的实际观测，不能从捕获结束推断连接状态。",
                        *([] if classified else ["当前证据保留 HTTP 形态观测，攻击子类型未知。"]),
                    ],
                    **classification,
                )
            )
    return results
