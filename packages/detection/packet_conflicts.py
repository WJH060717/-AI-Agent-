"""Same-capture ARP and DNS differences with immutable packet witnesses."""

import json
from collections import defaultdict
from datetime import timedelta
from itertools import pairwise
from pathlib import Path
from typing import Literal

from packages.contracts.models import (
    ArpSenderObservation,
    Contract,
    NormalizedEvent,
    PacketObservation,
)
from packages.detection.common import finding
from packages.detection.fragmentation import MICROSECOND
from packages.detection.freeze import RULES, FrozenRulesError, config_digest
from packages.detection.limits import checkpoint
from packages.detection.packet_recon import _capture_scope, _usable_ipv4

ARP_CONFLICT_RULE = "R28"
DNS_DIFFERENCE_RULE = "R29"
ARP_CONFLICT_FREEZE = RULES / "ethernet-arp-conflicts-freeze.json"
DNS_DIFFERENCE_FREEZE = RULES / "ipv4-dns-differences-freeze.json"


class ArpConflictRule(Contract):
    id: Literal["R28"]
    version: Literal["1.0.0"]
    window_seconds: Literal[10]


class DnsDifferenceRule(Contract):
    id: Literal["R29"]
    version: Literal["1.0.0"]
    window_seconds: Literal[3]
    maximum_message_bytes: Literal[1232]
    maximum_answers: Literal[16]


def _load[Rule: (ArpConflictRule, DnsDifferenceRule)](path: Path, model: type[Rule]) -> Rule:
    try:
        frozen = json.loads(path.read_bytes())
        rule = model.model_validate(frozen["config"])
        if config_digest(rule.model_dump(mode="json")) != frozen["config_hash"]:
            raise ValueError("packet difference configuration drift")
        return rule
    except (OSError, KeyError, TypeError, ValueError):
        raise FrozenRulesError("RULE_CONFIGURATION_DRIFT") from None


def _ordered(records: dict[str, NormalizedEvent]) -> list[NormalizedEvent]:
    checkpoint(len(records))
    return sorted(
        records.values(), key=lambda event: (event.source_locators[0].record_start, event.event_id)
    )


def detect_arp_conflicts(
    events: list[NormalizedEvent],
    session: str,
    rule: ArpConflictRule,
) -> list[dict]:
    groups: dict[tuple[str, ...], dict[str, NormalizedEvent]] = defaultdict(dict)
    for event in events:
        checkpoint()
        if (
            isinstance(event.packet, ArpSenderObservation)
            and event.src
            and event.dst
            and _usable_ipv4(event.src.ip)
            and _usable_ipv4(event.dst.ip)
            and event.src.ip != event.dst.ip
        ):
            key = (*_capture_scope(event), str(event.src.ip))
            groups[key][event.event_id] = event

    results = []
    window = timedelta(seconds=rule.window_seconds)
    for key, group in sorted(groups.items()):
        records = _ordered(group)
        for left, right in pairwise(records):
            checkpoint()
            elapsed = right.event_time - left.event_time
            different = left.packet.sender_mac != right.packet.sender_mac
            if different and timedelta(0) <= elapsed <= window:
                results.append(
                    finding(
                        rule,
                        [left, right],
                        session,
                        list(key[3:]),
                        "ethernet_arp_mapping_difference",
                        maliciousness="unknown",
                        observation_span_us=elapsed // MICROSECOND,
                        contributing_evidence_ids=[left.event_id, right.event_id],
                        limitations=[
                            "同一采集范围内，同一 IPv4 声明了两个以太网发送地址。",
                            "租约或高可用切换也可能产生该形态，授权、可信绑定和实际转发仍未知。",
                        ],
                    )
                )
                break
    return results


def _dns_witness(
    records: list[NormalizedEvent],
    window: timedelta,
) -> list[NormalizedEvent]:
    checkpoint(len(records))
    if any(left.event_time > right.event_time for left, right in pairwise(records)):
        return []
    request: NormalizedEvent | None = None
    first_reply: NormalizedEvent | None = None
    witness: list[NormalizedEvent] = []
    ambiguous = False
    for event in records:
        checkpoint()
        if request is not None and event.event_time - request.event_time > window:
            if witness and not ambiguous:
                return witness
            request, first_reply, witness, ambiguous = None, None, [], False
        message = event.packet.dns_message
        if message.message_type != "response":
            ambiguous = request is not None or message.message_type == "query_context"
            request, first_reply, witness = event, None, []
        elif request is not None and not ambiguous:
            if first_reply is None:
                first_reply = event
            elif (
                not witness
                and message.answer_set_sha256 != first_reply.packet.dns_message.answer_set_sha256
            ):
                witness = [request, first_reply, event]
    return [] if ambiguous else witness


def detect_dns_differences(
    events: list[NormalizedEvent],
    session: str,
    rule: DnsDifferenceRule,
) -> list[dict]:
    groups: dict[tuple[str, ...], dict[str, NormalizedEvent]] = defaultdict(dict)
    for event in events:
        checkpoint()
        if not isinstance(event.packet, PacketObservation) or event.packet.dns_message is None:
            continue
        message = event.packet.dns_message
        client, resolver = (
            (event.dst, event.src) if message.message_type == "response" else (event.src, event.dst)
        )
        if not _usable_ipv4(client.ip) or not _usable_ipv4(resolver.ip):
            continue
        key = (
            *_capture_scope(event),
            str(client.ip),
            str(client.port),
            str(resolver.ip),
            str(resolver.port),
            str(message.transaction_id),
            message.question_sha256,
            str(message.qtype),
        )
        groups[key][event.event_id] = event

    results = []
    for key, group in sorted(groups.items()):
        witness = _dns_witness(_ordered(group), timedelta(seconds=rule.window_seconds))
        if not witness:
            continue
        results.append(
            finding(
                rule,
                witness,
                session,
                list(key[3:]),
                "ipv4_dns_answer_difference",
                maliciousness="unknown",
                observation_span_us=(witness[-1].event_time - witness[0].event_time) // MICROSECOND,
                contributing_evidence_ids=[event.event_id for event in witness],
                limitations=[
                    "仅记录同一可配对 DNS 事务的两个不同直接地址集合。",
                    "分流、轮换或缓存差异仍需核查，解析可信性、授权与影响未知。",
                ],
            )
        )
    return results


def detect_packet_conflicts(events: list[NormalizedEvent], session: str) -> list[dict]:
    return detect_arp_conflicts(
        events, session, _load(ARP_CONFLICT_FREEZE, ArpConflictRule)
    ) + detect_dns_differences(events, session, _load(DNS_DIFFERENCE_FREEZE, DnsDifferenceRule))
