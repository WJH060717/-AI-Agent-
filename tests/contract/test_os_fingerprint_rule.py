import struct
from datetime import timedelta
from uuid import UUID

import pytest

from packages.contracts.models import NormalizedEvent
from packages.detection.registry import detect_all, reproduce
from packages.ingest.os_fingerprint import describe_os_probe
from tests.contract.test_fragment_rules import observations
from tests.integration.test_pcap_packet import ipv4_frame


def fingerprint_events() -> list[NormalizedEvent]:
    specs = (
        (17, "udp_request", "a", 0),
        (1, "icmp_quote", "a", 1),
        (6, "tcp_request", "b", 4_000_000),
        (6, "tcp_response", "b", 5_000_000),
    )
    result = []
    for index, (protocol, role, key, micros) in enumerate(specs):
        event = observations(protocol, fragmented=False)[index].model_dump(mode="json")
        event["schema_version"] = "1.9"
        event["event_time"] = observations(protocol, fragmented=False)[0].event_time + timedelta(
            microseconds=micros,
        )
        if role in {"icmp_quote", "tcp_response"}:
            event["src"], event["dst"] = event["dst"], event["src"]
        if role in {"udp_request", "tcp_request", "tcp_response"}:
            ports = (42000, 41000) if role == "tcp_response" else (41000, 42000)
            event["src"]["port"], event["dst"]["port"] = ports
        if role == "icmp_quote":
            event["packet"]["icmp_type"], event["packet"]["icmp_code"] = 3, 3
        elif role in {"tcp_request", "tcp_response"}:
            event["packet"]["tcp_flags"] = 2 if role == "tcp_request" else 18
            event["packet"]["tcp_payload_bytes_captured"] = 0
        event["packet"]["os_probe"] = {"role": role, "correlation_sha256": key * 64}
        result.append(NormalizedEvent.model_validate(event))
    return result


def test_passive_fingerprint_needs_both_unique_pairs_and_reproduces() -> None:
    packets = fingerprint_events()
    [match] = detect_all(packets[::-1], "session")
    assert (match["rule_id"], match["attack_subtype"]) == ("R30", "Recon-OSScan")
    assert match["observation_span_us"] == 5_000_000
    assert match["paired_evidence_ids"] == [
        [packets[0].event_id, packets[1].event_id],
        [packets[2].event_id, packets[3].event_id],
    ]
    assert reproduce(packets, "session", match) == [match]


@pytest.mark.parametrize(
    "gap",
    [
        "no_quote",
        "no_tcp_response",
        "wrong_key",
        "outside",
        "other_capture",
        "duplicate_reply",
        "wrong_direction",
        "wrong_ports",
    ],
)
def test_fingerprint_counterexamples_do_not_publish(gap: str) -> None:
    packets = fingerprint_events()
    last = packets[-1]
    if gap == "no_quote":
        packets.pop(1)
    elif gap == "no_tcp_response":
        packets.pop()
    elif gap == "wrong_key":
        last.packet.os_probe.correlation_sha256 = "c" * 64
    elif gap == "outside":
        last.event_time += timedelta(microseconds=1)
    elif gap == "other_capture":
        last.source_locators[0].object_id = UUID(int=4)
    elif gap == "duplicate_reply":
        duplicate = packets[1].model_copy(deep=True)
        duplicate.event_id = "d" * 64
        packets.append(duplicate)
    elif gap == "wrong_direction":
        last.src, last.dst = last.dst, last.src
    elif gap == "wrong_ports":
        last.src.port = 42001
    assert detect_all(packets, "session") == []


def test_incomplete_udp_quote_does_not_claim_fingerprint() -> None:
    udp = struct.pack("!4H", 41000, 42000, 308, 0) + bytes(300)
    original = ipv4_frame(17, udp)[14:]
    icmp = b"\x03\x03" + bytes(6) + original[:29]
    response = ipv4_frame(1, icmp)[14:]
    response = response[:12] + original[16:20] + original[12:16] + response[20:]
    assert describe_os_probe(response, icmp) is None
