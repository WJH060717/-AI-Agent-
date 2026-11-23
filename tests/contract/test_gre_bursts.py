"""Counterexamples for limited GRE shape and burst observations."""

from datetime import timedelta
from ipaddress import IPv4Address
from uuid import uuid4

import pytest

from packages.detection.registry import detect_all, reproduce
from packages.ingest.pcap_packet import gre_encapsulation
from tests.contract.test_packet_bursts import burst


@pytest.mark.parametrize("variant", ["slow", "mixed", "missing", "two_targets", "two_files"])
def test_confounded_gre_windows_stay_unclassified(variant):
    rows = burst(47)
    for i, row in enumerate(rows):
        row.packet.gre_encapsulation = "ip"
        if variant == "slow":
            row.event_time += timedelta(seconds=i)
        if variant == "mixed" and i >= 32:
            row.packet.gre_encapsulation = "ethernet"
        if variant == "missing" and i >= 32:
            row.packet.gre_encapsulation = None
        if variant == "two_targets" and i >= 32:
            row.dst.ip = IPv4Address("198.51.100.3")
        if variant == "two_files" and i >= 32:
            row.source_locators[0].object_id = uuid4()
    assert detect_all(rows, "gre-session") == []


def test_valid_witness_replays_without_malware_family_attribution():
    rows = burst(47)
    for row in rows:
        row.packet.gre_encapsulation = "ip"
    [hit] = detect_all(rows, "gre-session")
    assert hit["rule_id"] == "R27" and "attack_subtype" not in hit
    assert hit["gre_encapsulation"] == "ip"
    assert reproduce(rows, "gre-session", hit) == [hit]
    assert reproduce(rows[:-1], "gre-session", hit) == []


@pytest.mark.parametrize("payload", [
    bytes.fromhex("00000800"),
    bytes.fromhex("00006558") + bytes(14),
    bytes.fromhex("000086dd") + bytes(39),
    bytes.fromhex("80000800") + bytes(20),
])
def test_unreadable_gre_has_no_inner_summary(payload):
    assert gre_encapsulation(payload) is None
