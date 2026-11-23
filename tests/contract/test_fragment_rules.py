"""Synthetic normalized observations only. Independent of CICIoT2023 captures."""

import hashlib
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from packages.contracts.models import NormalizedEvent
from packages.detection.registry import detect_all, reproduce


def observations(protocol, *, fragmented=True, ack=True, gap_us=2500, missing_initial=False):
    workspace, dataset, original = (UUID(int=value) for value in (1, 2, 3))
    epoch = datetime(2026, 1, 1, tzinfo=UTC)
    events = []
    for index in range(64):
        ticks = index * gap_us
        first = index % 2 == 0 and not missing_initial
        offset = (0 if first else 256) if fragmented else 0
        flags = (16 if ack else 24) if protocol == 6 and offset == 0 else None
        time = epoch + timedelta(microseconds=ticks)
        events.append(
            NormalizedEvent(
                schema_version="1.6",
                workspace_id=workspace,
                dataset_id=dataset,
                event_id=hashlib.sha256(f"{protocol}-{index}".encode()).hexdigest(),
                event_type="network.packet",
                event_time=time,
                ingested_at=time,
                time_quality={
                    "original": time.isoformat(),
                    "timezone": "UTC",
                    "offset_ms": 0,
                    "uncertainty_ms": 0,
                    "basis": "synthetic",
                },
                sensor={
                    "sensor_id": "probe",
                    "type": "pcap",
                    "instance_id": "test-a",
                    "observation_domain": "test-scope",
                },
                source_locators=[
                    {
                        "object_id": original,
                        "record_start": index + 1,
                        "record_end": index + 1,
                        "raw_sha256": "0" * 64,
                        "pcap": {"byte_start": 24 + index * 96, "byte_end": 24 + (index + 1) * 96},
                    }
                ],
                parser_version="pcap-packet@1.0.0",
                src={"ip": "192.0.2.1"},
                dst={"ip": "192.0.2.2"},
                packet={
                    "protocol_number": protocol,
                    "captured_length": 80,
                    "wire_length": 80,
                    "ip_id": index // 2,
                    "fragment_offset_bytes": offset,
                    "more_fragments": fragmented and first,
                    "tcp_flags": flags,
                    "icmp_type": 8 if protocol == 1 and offset == 0 else None,
                },
            )
        )
    return events


@pytest.mark.parametrize(
    ("protocol", "rule", "subtype"),
    [
        (6, "R12", "DoS/DDoS-ACK_Fragmentation"),
        (17, "R13", "DoS/DDoS-UDP_Fragmentation"),
        (1, "R14", "DoS/DDoS-ICMP_Fragmentation"),
    ],
)
def test_frozen_fragmentation_witness_is_reproducible(protocol, rule, subtype):
    packets = observations(protocol)
    [finding] = detect_all(list(reversed(packets)), "session")
    assert (finding["rule_id"], finding["attack_subtype"]) == (rule, subtype)
    assert finding["observed_pairs"] == 32
    assert len(finding["evidence_ids"]) == 64
    assert finding["maliciousness"] == "unknown"
    assert reproduce(packets, "session", finding) == [finding]
    assert reproduce(packets[1:], "session", finding) == []


@pytest.mark.parametrize(
    ("protocol", "variant"),
    [
        (6, {"missing_initial": True}),
        (6, {"ack": False}),
        (6, {"fragmented": False}),
        (17, {"gap_us": 15000}),
        (17, {"fragmented": False}),
        (1, {"gap_us": 15000}),
        (1, {"fragmented": False}),
        (1, {"gap_us": 0}),
    ],
)
def test_ordinary_fragments_or_missing_fragment_evidence_do_not_trigger(protocol, variant):
    assert detect_all(observations(protocol, **variant), "session") == []


@pytest.mark.parametrize(
    ("gap_us", "triggers"), [(15, False), (16, True), (3968, True), (3969, False)]
)
def test_fragment_window_requires_a_bounded_observed_span(gap_us, triggers):
    assert bool(detect_all(observations(17, gap_us=gap_us), "session")) is triggers


def test_fragment_pairing_rejects_duplicate_and_cross_capture_observations():
    events = observations(6)
    assert detect_all(events[:32] * 2, "session") == []
    for packet in events[1::2]:
        packet.source_locators[0].object_id = UUID(int=4)
    assert detect_all(events, "session") == []


def test_fragment_pairing_rejects_overlapping_firsts_with_same_identity():
    events = observations(6)
    for index, event in enumerate(events):
        packet = event.packet
        assert packet is not None
        initial = index % 4 < 2
        packet.fragment_offset_bytes = 0 if initial else 256
        packet.more_fragments = initial
        packet.tcp_flags = 16 if initial else None
        packet.ip_id = index // 4
    assert detect_all(events, "session") == []


def test_fragment_configuration_drift_is_rejected(tmp_path):
    import shutil

    from packages.detection.fragmentation import load_fragment_rules
    from packages.detection.freeze import RULES, FrozenRulesError

    for filename in ("R12.json", "R13.json", "R14.json", "ipv4-fragments-freeze.json"):
        shutil.copyfile(RULES / filename, tmp_path / filename)
    assert len(load_fragment_rules(tmp_path)) == 3
    config = tmp_path / "R12.json"
    config.write_text(config.read_text().replace("100000", "99999"), encoding="utf-8")
    with pytest.raises(FrozenRulesError, match="RULE_CONFIGURATION_DRIFT"):
        load_fragment_rules(tmp_path)


def test_rule_window_does_not_skip_a_late_timestamp_record_inside_the_physical_window():
    events = observations(17)
    intervening = events[31].model_copy(deep=True)
    intervening.event_time += timedelta(seconds=1)
    intervening.event_id = "7" * 64
    for event in events[31:]:
        event.source_locators[0].record_start += 1
        event.source_locators[0].record_end += 1
    events.insert(31, intervening)
    assert detect_all(events, "session") == []


def test_competing_terminal_invalidates_a_previously_possible_pair():
    events = observations(17)
    for event in events[40:]:
        packet = event.packet
        assert packet is not None
        packet.more_fragments = False
        packet.fragment_offset_bytes = 0
    assert detect_all(events, "session")[0]["observed_pairs"] == 20
    competitor = events[40].packet
    assert competitor is not None
    competitor.ip_id = 0
    competitor.fragment_offset_bytes = 256
    assert detect_all(events, "session") == []


def test_unique_fragment_match_can_have_the_terminal_observed_first():
    events = observations(1)
    for event in events[1::2]:
        event.event_time -= timedelta(microseconds=4000)
    [finding] = detect_all(events, "session")
    assert finding["observed_pairs"] == 32


def test_terminal_with_two_possible_initials_does_not_match_either():
    events = observations(17)
    for event in events[42:]:
        packet = event.packet
        assert packet is not None
        packet.more_fragments = False
        packet.fragment_offset_bytes = 0
    # Two initial records with a shared ID flank one terminal, each within the gap.
    first, terminal, competing = events[0], events[1], events[42]
    terminal.event_time = first.event_time + timedelta(microseconds=70_000)
    competing.event_time = first.event_time + timedelta(microseconds=140_000)
    assert competing.packet is not None
    competing.packet.ip_id = 0
    competing.packet.more_fragments = True
    [finding] = detect_all(events, "session")
    assert finding["observed_pairs"] == 20
    assert all(terminal.event_id not in pair for pair in finding["paired_evidence_ids"])


def test_middle_fragment_at_or_after_terminal_offset_is_a_conflict():
    events = observations(17)
    for event in events[40:]:
        packet = event.packet
        assert packet is not None
        packet.more_fragments = False
        packet.fragment_offset_bytes = 0
    assert detect_all(events, "session")[0]["observed_pairs"] == 20
    packet = events[40].packet
    assert packet is not None
    packet.ip_id = 0
    packet.more_fragments = True
    packet.fragment_offset_bytes = 256
    assert detect_all(events, "session") == []


def test_reused_id_with_disjoint_observed_cycles_is_versioned():
    events = observations(6)
    for event in events:
        assert event.packet is not None
        event.packet.ip_id = 900
    [finding] = detect_all(events, "session")
    assert finding["rule_version"] == "1.2.0"
    assert finding["reused_id_observed_pairs"] == 32
    assert reproduce(events, "session", finding) == [finding]
    legacy = {
        **finding,
        "rule_version": "1.0.0",
        "config": {**finding["config"], "version": "1.0.0"},
    }
    assert reproduce(events, "session", legacy) == []


@pytest.mark.parametrize("conflict", ["duplicate_terminal", "overlapping_time", "partial_cycle"])
def test_reused_id_cycles_fail_on_competing_or_overlapping_records(conflict):
    events = observations(6)
    for event in events:
        assert event.packet is not None
        event.packet.ip_id = 900
    assert events[4].packet is not None
    assert events[63].packet is not None
    if conflict == "duplicate_terminal":
        events[4].packet.more_fragments = False
        events[4].packet.fragment_offset_bytes = 256
        events[4].packet.tcp_flags = None
    elif conflict == "overlapping_time":
        events[1].event_time = events[2].event_time + timedelta(microseconds=5)
    else:
        events[63].packet.more_fragments = True
    assert detect_all(events, "session") == []
