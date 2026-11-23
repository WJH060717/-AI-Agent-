"""Corroborate a captured fingerprint marker using two unique response pairs."""

import json
from bisect import bisect_left
from collections import defaultdict
from datetime import timedelta
from typing import Literal

from packages.contracts.models import Contract, NormalizedEvent, PacketObservation
from packages.detection.common import finding
from packages.detection.fragmentation import MICROSECOND
from packages.detection.freeze import RULES, FrozenRulesError, config_digest
from packages.detection.limits import checkpoint
from packages.detection.packet_recon import _capture_scope, _usable_ipv4

OS_FINGERPRINT_RULE = "R30"
OS_FINGERPRINT_FREEZE = RULES / "ipv4-os-fingerprint-freeze.json"
RESPONSE_ROLES = {"icmp_quote", "tcp_response"}


class OsFingerprintRule(Contract):
    id: Literal["R30"]
    version: Literal["1.0.0"]
    window_us: Literal[5_000_000]
    basis_sha256: Literal["46bc5a79d3c996399967ed1173d11395715cfaaa87a155e4af5d85ab827a699c"]


def load_os_fingerprint_rule() -> OsFingerprintRule:
    try:
        frozen = json.loads(OS_FINGERPRINT_FREEZE.read_bytes())
        rule = OsFingerprintRule.model_validate(frozen["config"])
        if config_digest(rule.model_dump(mode="json")) != frozen["config_hash"]:
            raise ValueError("fingerprint configuration drift")
        return rule
    except (OSError, KeyError, TypeError, ValueError):
        raise FrozenRulesError("RULE_CONFIGURATION_DRIFT") from None


def detect_os_fingerprints(
    events: list[NormalizedEvent],
    session: str,
    rule: OsFingerprintRule,
) -> list[dict]:
    keyed = []
    udp_scopes = set()
    for event in events:
        checkpoint()
        if not isinstance(event.packet, PacketObservation) or not event.packet.os_probe:
            continue
        probe = event.packet.os_probe
        response = probe.role in RESPONSE_ROLES
        client, target = (event.dst, event.src) if response else (event.src, event.dst)
        if not _usable_ipv4(client.ip) or not _usable_ipv4(target.ip) or client.ip == target.ip:
            continue
        scope = (*_capture_scope(event), str(client.ip), str(target.ip))
        family = "tcp" if probe.role.startswith("tcp_") else "udp"
        if probe.role == "udp_request":
            udp_scopes.add(scope)
        keyed.append((scope, family, probe.correlation_sha256, response, event))

    if not udp_scopes:
        return []
    groups = defaultdict(lambda: (dict(), dict()))
    for scope, family, key, response, event in keyed:
        checkpoint()
        if scope in udp_scopes:
            groups[scope, family, key][response][event.event_id] = event

    tcp = defaultdict(list)
    udp = []
    maximum_span = timedelta(microseconds=rule.window_us)
    for (scope, family, key), (requests, responses) in groups.items():
        checkpoint()
        if len(requests) != 1 or len(responses) != 1:
            continue
        request = next(iter(requests.values()))
        response = next(iter(responses.values()))
        if (
            not timedelta(0) < response.event_time - request.event_time <= maximum_span
            or request.source_locators[0].record_start >= response.source_locators[0].record_start
        ):
            continue
        if family == "tcp":
            if (request.src.port, request.dst.port) != (response.dst.port, response.src.port):
                continue
            tcp[scope].append((request.event_time, request.event_id, request, response))
        else:
            udp.append((scope, key, request, response))

    for exchanges in tcp.values():
        checkpoint(len(exchanges))
        exchanges.sort()

    results = []
    for scope, key, request, response in sorted(udp, key=lambda item: item[:2]):
        checkpoint()
        exchanges = tcp.get(scope, [])
        lower = response.event_time - maximum_span
        upper = request.event_time + maximum_span
        index = bisect_left(exchanges, lower, key=lambda item: item[0])
        for position in range(index, len(exchanges)):
            checkpoint()
            start, _, tcp_request, tcp_response = exchanges[position]
            if start > upper:
                break
            elapsed = max(response.event_time, tcp_response.event_time) - min(
                request.event_time, start
            )
            if elapsed > maximum_span:
                continue
            witnesses = [request, response, tcp_request, tcp_response]
            results.append(
                finding(
                    rule,
                    witnesses,
                    session,
                    [*scope[3:], key],
                    "ipv4_os_fingerprint_corroborated",
                    attack_subtype="Recon-OSScan",
                    maliciousness="unknown",
                    observation_span_us=elapsed // MICROSECOND,
                    paired_evidence_ids=[
                        [request.event_id, response.event_id],
                        [tcp_request.event_id, tcp_response.event_id],
                    ],
                    contributing_evidence_ids=[event.event_id for event in witnesses],
                    limitations=["仅确认被动指纹探测形态，目标系统版本、授权与操作者仍未知。"],
                )
            )
            break
    return results
