"""Reconnaissance must be supported by distinct, in-scope packet evidence."""

from datetime import timedelta
from ipaddress import IPv4Address
from uuid import uuid4

import pytest

from packages.contracts.models import ArpRequestObservation, NormalizedEvent
from packages.detection.registry import detect_all, reproduce
from tests.contract.test_packet_bursts import burst


def port_observations():
    packets = burst(6, 2)[:24]
    for index, packet in enumerate(packets):
        packet.dst.port = 20000 + index
    return packets


def test_classifies_one_observed_source_testing_distinct_destination_ports():
    packets = port_observations()
    [hit] = detect_all(packets[::-1], "session")
    assert (hit["rule_id"], hit["attack_subtype"]) == ("R24", "Recon-PortScan")
    assert len(hit["evidence_ids"]) == hit["distinct_observed_destination_ports"] == 20
    assert set(hit["contributing_evidence_ids"]) == set(hit["evidence_ids"])
    proof = [event for event in packets if event.event_id in hit["evidence_ids"]]
    assert reproduce(proof, "session", hit) == [hit]
    assert reproduce(proof[:-1], "session", hit) == []


@pytest.mark.parametrize(
    "variant", ["same_port", "responses", "over_time", "second_sensor", "second_source_file",
                "second_target", "capture_truncated", "same_address"],
)
def test_other_observations_do_not_supply_the_port_threshold(variant):
    packets = port_observations()
    for index, packet in enumerate(packets):
        if variant == "same_port":
            packet.dst.port = 443
        elif variant == "responses":
            packet.packet.tcp_flags = 18
        elif variant == "over_time" and index >= 12:
            packet.event_time += timedelta(seconds=61)
        elif variant == "second_sensor" and index >= 12:
            packet.sensor.sensor_id = "other"
        elif variant == "second_source_file" and index >= 12:
            packet.source_locators[0].object_id = uuid4()
        elif variant == "second_target" and index >= 12:
            packet.dst.ip = IPv4Address("192.0.2.15")
        elif variant == "capture_truncated":
            packet.packet.wire_length += 1
        elif variant == "same_address":
            packet.dst.ip = packet.src.ip
    assert detect_all(packets, "session") == []


def ping_observations():
    packets = burst(1)[:8]
    start = packets[0].event_time
    for index, packet in enumerate(packets):
        packet.dst.ip = IPv4Address(f"198.51.100.{index + 1}")
        packet.event_time = start + timedelta(seconds=index * 10 / 7)
    return packets


def test_ping_sweep_uses_only_distinct_echo_requests_at_inclusive_time_limit():
    packets = ping_observations()
    [hit] = detect_all(packets[::-1] + [packets[0]], "session")
    assert (hit["rule_id"], hit["attack_subtype"]) == ("R25", "Recon-PingSweep")
    assert hit["distinct_observed_destination_ips"] == len(hit["evidence_ids"]) == 8
    assert hit["observation_span_us"] == 10_000_000
    assert set(hit["contributing_evidence_ids"]) == set(hit["evidence_ids"])
    assert hit["maliciousness"] == "unknown"
    assert reproduce(packets, "session", hit) == [hit]
    assert reproduce(packets[:-1], "session", hit) == []


@pytest.mark.parametrize(
    "variant",
    [
        "same_target", "alone_below_threshold", "reply", "over_time", "second_sensor",
        "second_instance", "second_domain", "second_file", "second_sender", "missing_echo",
        "truncated", "fragment", "self", "multicast", "broadcast", "unspecified",
    ],
)
def test_ping_sweep_requires_complete_requests_in_the_same_scope(variant):
    packets = ping_observations()
    for packet in packets:
        if variant == "same_target":
            packet.dst.ip = packets[0].dst.ip
    last = packets[-1]
    if variant == "alone_below_threshold":
        packets.pop()
    elif variant == "reply":
        last.packet.icmp_type = 0
    elif variant == "over_time":
        last.event_time += timedelta(microseconds=1)
    elif variant == "second_sensor":
        last.sensor.sensor_id = "other"
    elif variant == "second_instance":
        last.sensor.instance_id = "other-instance"
    elif variant == "second_domain":
        last.sensor.observation_domain = "other-domain"
    elif variant == "second_file":
        last.source_locators[0].object_id = uuid4()
    elif variant == "second_sender":
        last.src.ip = IPv4Address("192.0.2.50")
    elif variant == "missing_echo":
        last.packet.icmp_echo_header_complete = None
    elif variant == "truncated":
        last.packet.wire_length += 1
    elif variant == "fragment":
        last.packet.more_fragments = True
    elif variant == "self":
        last.dst.ip = last.src.ip
    elif variant == "multicast":
        last.dst.ip = IPv4Address("224.0.0.1")
    elif variant == "broadcast":
        last.dst.ip = IPv4Address("255.255.255.255")
    elif variant == "unspecified":
        last.dst.ip = IPv4Address("0.0.0.0")
    assert detect_all(packets, "session") == []


@pytest.mark.parametrize(
    "case", ["inclusive", "outside", "duplicate_destination", "sender_mac",
             "cross_sensor", "source_file", "arp_address_probe", "self_announcement"],
)
def test_arp_host_discovery_checks_evidence_window_and_capture_scope(case):
    packets = []
    for echo in ping_observations():
        data = echo.model_dump(mode="json")
        data["schema_version"] = "1.7"
        data["packet"] = ArpRequestObservation(
            arp_operation=1, sender_mac="020000000001", captured_length=42, wire_length=42,
        )
        packets.append(NormalizedEvent.model_validate(data))
    last = packets[-1]
    if case == "outside":
        last.event_time += timedelta(microseconds=1)
    elif case == "duplicate_destination":
        last.dst.ip = packets[0].dst.ip
    elif case == "sender_mac":
        last.packet.sender_mac = "020000000009"
    elif case == "cross_sensor":
        last.sensor.sensor_id = "another"
    elif case == "source_file":
        last.source_locators[0].object_id = uuid4()
    elif case == "arp_address_probe":
        last.src.ip = IPv4Address("0.0.0.0")
    elif case == "self_announcement":
        last.dst.ip = last.src.ip
    matches = detect_all(packets, "session")
    if case == "inclusive":
        [hit] = matches
        assert hit["rule_id"] == "R26" and "attack_subtype" not in hit
        assert hit["observation_span_us"] == 10_000_000
        assert reproduce(packets, "session", hit) == [hit]
    elif case == "sender_mac":
        [hit] = matches
        assert hit["rule_id"] == "R28" and "attack_subtype" not in hit
    else:
        assert matches == []
