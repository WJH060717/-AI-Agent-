"""Independent normalized packet observations."""

import pytest

from packages.detection.freeze import RULES
from packages.detection.packet_bursts import detect_bursts, load_burst_rules
from packages.detection.registry import detect_all, reproduce
from tests.contract.test_fragment_rules import observations


def burst(protocol, flags=None, *, same=False, gap_us=2500):
    events = observations(protocol, fragmented=False, gap_us=gap_us)
    for index, event in enumerate(events):
        if protocol in (6, 17):
            event.src.port, event.dst.port = 41000 + index, 443
        if protocol == 6:
            event.packet.tcp_flags = flags
            event.packet.tcp_payload_bytes_captured = 0
        if protocol == 1:
            event.packet.icmp_code = 0
            event.packet.icmp_echo_header_complete = True
        if same:
            event.src.ip = event.dst.ip
    return events


@pytest.mark.parametrize(
    ("proto", "flags", "same", "rule", "subtype"),
    [
        (6, 24, False, "R15", "PSHACK_Flood"),
        (6, 5, False, "R16", "RSTFINFlood"),
        (6, 2, True, "R17", "SynonymousIP_Flood"),
        (6, 2, False, "R18", "SYN_Flood"),
        (6, 0, False, "R19", "TCP_Flood"),
        (17, None, False, "R20", "UDP_Flood"),
        (1, None, False, "R21", "ICMP_Flood"),
    ],
)
def test_burst_is_unique_and_reproducible(proto, flags, same, rule, subtype):
    packets = burst(proto, flags, same=same)
    historical = load_burst_rules(RULES / "ipv4-packet-bursts-v11-freeze.json")
    [finding] = detect_bursts(packets[::-1], "session", historical)
    assert (finding["rule_id"], finding["attack_subtype"]) == (rule, f"DDoS-{subtype}")
    assert len(finding["evidence_ids"]) == 64
    assert set(finding["contributing_evidence_ids"]) == set(finding["evidence_ids"])
    assert finding["maliciousness"] == "unknown"
    assert reproduce(packets, "session", finding) == [finding]
    assert reproduce(packets[:-1], "session", finding) == []


@pytest.mark.parametrize(
    "variant",
    [
        "tcp_data",
        "separate_close",
        "syn_retry",
        "udp_single_flow",
        "icmp_reply",
        "slow_zero_flags",
        "zero_span",
        "truncated_push",
        "mixed_syn",
    ],
)
def test_counterexamples(variant):
    proto = 17 if variant == "udp_single_flow" else 1 if variant == "icmp_reply" else 6
    flags = {
        "tcp_data": 24,
        "separate_close": 5,
        "syn_retry": 2,
        "truncated_push": 24,
        "mixed_syn": 2,
    }.get(variant, 0)
    packets = burst(
        proto, flags, gap_us={"slow_zero_flags": 10000, "zero_span": 0}.get(variant, 2500)
    )
    for index, event in enumerate(packets):
        if variant == "tcp_data":
            event.packet.tcp_payload_bytes_captured = 40
        elif variant == "separate_close":
            event.packet.tcp_flags = 1 if index % 2 else 4
        elif variant in {"syn_retry", "udp_single_flow"}:
            event.src.port = 41000
        elif variant == "icmp_reply":
            event.packet.icmp_type = 0
        elif variant == "truncated_push":
            event.packet.wire_length = 120
        elif variant == "mixed_syn" and index % 2:
            event.src.ip = event.dst.ip
    assert detect_all(packets, "session") == []


def test_same_service_application_progress_withholds_syn_label():
    packets = burst(6, 2)
    progressed = packets[-1].model_copy(deep=True)
    progressed.event_id = "e" * 64
    progressed.source_locators[0].record_start = 65
    progressed.source_locators[0].record_end = 65
    progressed.packet.tcp_flags = 24
    progressed.packet.tcp_payload_bytes_captured = 40
    assert detect_all([*packets, progressed], "session") == []


def test_dense_uniform_udp_can_match_with_limited_socket_diversity():
    packets = burst(17, gap_us=250)
    for event in packets:
        event.src.port = 41000
    [finding] = detect_all(packets, "session")
    assert finding["rule_id"] == "R20"
    assert reproduce(packets, "session", finding) == [finding]
    for index, event in enumerate(packets):
        event.packet.wire_length += index
    assert detect_all(packets, "session") == []


@pytest.mark.parametrize("complete", [None, False])
def test_echo_header_must_be_proven_complete(complete):
    packets = burst(1)
    for event in packets:
        event.packet.icmp_echo_header_complete = complete
    assert detect_all(packets, "session") == []


@pytest.mark.parametrize(("matching", "expected"), [(47, False), (48, True)])
def test_nonfragment_threshold_keeps_fragment_packets_in_the_denominator(matching, expected):
    packets = burst(6, 0)
    for event in packets[matching:]:
        event.packet.more_fragments = True
    assert bool(detect_all(packets, "session")) is expected


@pytest.mark.parametrize(("ports", "expected"), [(15, False), (16, True)])
def test_udp_secondary_evidence_threshold_is_explicit(ports, expected):
    packets = burst(17)
    for index, event in enumerate(packets):
        event.src.port = 41000 + index % ports
    assert bool(detect_all(packets, "session")) is expected
