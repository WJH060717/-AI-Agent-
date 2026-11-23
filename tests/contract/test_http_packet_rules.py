"""Independent normalized observations for HTTP request timing."""

from datetime import timedelta

import pytest

from packages.contracts.models import HttpSegmentObservation
from packages.detection.freeze import RULES
from packages.detection.http_packets import detect_http_packets, load_http_packet_rules
from packages.detection.registry import detect_all, reproduce
from packages.ingest.pcap_packet import describe_http_segment
from tests.contract.test_packet_bursts import burst


def mark(event, seq, starts, complete=False):
    event.packet.tcp_flags = 24
    event.packet.tcp_payload_bytes_captured = 32
    event.packet.http_segment = HttpSegmentObservation(
        sequence=seq,
        request_start=starts,
        text_prefix=True,
        header_transitions=(4, 4, 4, 4) if complete else (0, 0, 0, 0),
    )


def test_completed_http_headers_create_single_replayable_burst():
    packets = burst(6, 16)
    for i, packet in enumerate(packets[:16]):
        mark(packet, 500 + i, True, True)
    legacy = load_http_packet_rules(RULES / "http-packet-requests-freeze.json")
    [hit] = detect_http_packets(packets[::-1], "session", legacy)
    assert hit["attack_subtype"] == "DDoS-HTTP_Flood"
    assert reproduce(packets, "session", hit) == [hit]
    for packet in packets[:16]:
        packet.src.port = 41000
        packet.packet.http_segment.sequence = 500
    assert not detect_all(packets, "session")


@pytest.mark.parametrize("variant", ["valid", "short", "missing_progress", "gap", "completed"])
def test_slow_header_requires_contiguous_delayed_positive_progress(variant):
    events = burst(6, 16)[:16]
    for i in range(8):
        start, later = events[i], events[i + 8]
        later.src.port = start.src.port
        later.event_time = start.event_time + timedelta(seconds=2 if variant != "short" else 0.1)
        mark(start, 500, True)
        if variant != "missing_progress":
            mark(later, 532 if variant != "gap" else 533, False, variant == "completed")
    legacy = load_http_packet_rules(RULES / "http-packet-requests-v11-freeze.json")
    results = detect_http_packets(events, "session", legacy)
    if variant == "valid":
        [hit] = results
        assert hit["attack_subtype"] == "DDoS-SlowLoris"
        assert len(hit["evidence_ids"]) == 16
        assert reproduce(events[::-1], "session", hit) == [hit]
    else:
        assert results == []


def test_header_terminator_across_segment_boundary_and_no_content_projection():
    payload = b"GET /foo HTTP/1.1\r\nX-Test: bar\r\n\r"
    start = describe_http_segment(700, payload)
    end = describe_http_segment(700 + len(payload), b"\n")
    assert start.request_start and start.text_prefix
    assert start.header_transitions[0] == 3
    assert end.header_transitions[start.header_transitions[0]] == 4
    assert set(start.model_dump()) == {
        "sequence", "request_start", "text_prefix", "header_transitions"
    }


def test_delayed_progress_without_common_overlap_creates_no_candidate():
    events = burst(6, 16)
    for index in range(8):
        start, later = events[index], events[index + 8]
        start.event_time += timedelta(seconds=3 * index)
        later.src.port = start.src.port
        later.event_time = start.event_time + timedelta(seconds=2)
        mark(start, 500, True)
        mark(later, 532, False)
    assert detect_all(events, "session") == []



@pytest.mark.parametrize(
    "variant",
    ["valid", "late_large", "short_gap", "completed", "initial_gap", "late_large_initial"],
)
def test_slow_header_distinguishes_initial_segments_from_delayed_progress(variant):
    events = burst(6, 24)
    for i in range(8):
        start, initial, delayed = events[i], events[i + 8], events[i + 16]
        initial.src.port = delayed.src.port = start.src.port
        first_gap = {"short_gap": 0.6, "late_large_initial": 1.1}.get(variant, 0.05)
        initial.event_time = start.event_time + timedelta(seconds=first_gap)
        delayed.event_time = start.event_time + timedelta(seconds=first_gap + 1.25)
        if variant == "short_gap":
            delayed.event_time = start.event_time + timedelta(seconds=1.2)
        mark(start, 800, True)
        mark(initial, 833 if variant == "initial_gap" else 832, False)
        initial.packet.tcp_payload_bytes_captured = 256
        mark(delayed, 1088, False, variant == "completed")
        if variant == "late_large":
            delayed.packet.tcp_payload_bytes_captured = 256
    revised = load_http_packet_rules(RULES / "http-packet-requests-v11-freeze.json")
    hits = detect_http_packets(events[::-1], "session", revised)
    if variant == "valid":
        [hit] = hits
        assert hit["rule_version"] == "1.1.0"
        assert hit["attack_subtype"] == "DDoS-SlowLoris"
        assert len(hit["evidence_ids"]) == 24
        assert reproduce(events, "session", hit) == hits
        legacy = load_http_packet_rules(RULES / "http-packet-requests-freeze.json")
        assert not detect_http_packets(events, "session", legacy)
    else:
        assert hits == []


def test_legacy_slow_header_finding_reproduces_with_its_saved_version():
    events = burst(6, 16)
    for i in range(8):
        start, later = events[i], events[i + 8]
        later.src.port = start.src.port
        later.event_time = start.event_time + timedelta(seconds=2)
        mark(start, 700, True)
        mark(later, 732, False)
    legacy = load_http_packet_rules(RULES / "http-packet-requests-freeze.json")
    [old] = detect_http_packets(events, "session", legacy)
    assert old["rule_version"] == "1.0.0"
    assert reproduce(events, "session", old) == [old]



@pytest.mark.parametrize(
    "offset,classified", [(None, False), (150, False), (300, True), (550, False)]
)
def test_http_burst_needs_separate_recurrence(offset, classified):
    packets = burst(6, 24)[:8 if offset is None else 16]
    for index, packet in enumerate(packets):
        mark(packet, 500 + index, True, True)
        if index >= 8:
            packet.event_time += timedelta(milliseconds=offset)
    historical = load_http_packet_rules(RULES / "http-packet-requests-v12-freeze.json")
    [hit] = detect_http_packets(packets[::-1], "session", historical)
    assert hit["rule_version"] == "1.1.0"
    assert hit.get("attack_subtype") == ("DDoS-HTTP_Flood" if classified else None)
    assert len(hit["evidence_ids"]) == (16 if classified else 8)
    assert reproduce(packets, "session", hit) == [hit]


@pytest.mark.parametrize(
    "variant,classified",
    [
        ("missing", False),
        ("completes", False),
        ("continues", True),
        ("gap", False),
        ("ack", False),
        ("late_completion", False),
    ],
)
def test_slow_header_checks_what_follows_first_delayed_progress(variant, classified):
    events = burst(6, 24)[:16 if variant == "missing" else 24]
    for i in range(8):
        start, delayed = events[i], events[i + 8]
        delayed.src.port = start.src.port
        delayed.event_time = start.event_time + timedelta(seconds=1.3)
        mark(start, 500, True)
        mark(delayed, 532, False)
        if variant != "missing":
            followup = events[i + 16]
            followup.src.port = start.src.port
            extra = 0.3 if variant == "completes" else 0.6
            followup.event_time = delayed.event_time + timedelta(seconds=extra)
            mark(
                followup, 565 if variant == "gap" else 564, False,
                variant in {"completes", "late_completion"},
            )
            if variant == "ack":
                followup.packet.http_segment = None
                followup.packet.tcp_payload_bytes_captured = 0
                followup.packet.tcp_flags = 16
    found = detect_all(events[::-1], "session")
    if variant == "completes":
        assert found == []
        return
    [hit] = found
    assert hit["rule_version"] == "1.3.0"
    assert hit.get("attack_subtype") == ("DoS/DDoS-SlowLoris" if classified else None)
    assert len(hit["evidence_ids"]) == (24 if classified else 16)
    assert reproduce(events, "session", hit) == found
