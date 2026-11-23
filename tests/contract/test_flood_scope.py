"""Separate observed packet addresses from campaign distribution."""

from datetime import timedelta
from ipaddress import IPv4Address

import pytest

from packages.detection.registry import detect_all, reproduce
from tests.contract.test_http_packet_rules import mark
from tests.contract.test_packet_bursts import burst


@pytest.mark.parametrize(
    "protocol,flags,rule,behavior",
    [(6, 2, "R18", "SYN_Flood"), (6, 0, "R19", "TCP_Flood"), (17, None, "R20", "UDP_Flood")],
)
@pytest.mark.parametrize("multiple", [False, True])
def test_flood_reports_only_visible_contributing_sources(protocol, flags, rule, behavior, multiple):
    packets = burst(protocol, flags)
    if multiple:
        packets[-1].src.ip = IPv4Address("192.0.2.50")
    [hit] = detect_all(packets, "flood-session")
    assert hit["rule_id"] == rule
    assert hit["attack_subtype"] == f"DoS/DDoS-{behavior}"
    assert hit["flood_observation"] == {
        "behavior": behavior,
        "observed_source_ip_count": 2 if multiple else 1,
        "campaign_scope": "unknown",
        "support": "flood_candidate",
    }
    assert reproduce(packets, "flood-session", hit) == [hit]


def test_other_flood_shapes_use_the_same_family():
    [hit] = detect_all(burst(6, 5), "flood-session")
    assert hit["attack_subtype"] == "DoS/DDoS-RSTFINFlood"


def test_background_packet_does_not_add_an_observed_source():
    packets = burst(6, 0)
    packets[-1].src.ip = IPv4Address("192.0.2.50")
    packets[-1].packet.tcp_flags = 16
    [hit] = detect_all(packets, "flood-session")
    assert hit["flood_observation"]["observed_source_ip_count"] == 1


@pytest.mark.parametrize("repeated", [False, True])
def test_http_distinguishes_one_burst_from_recurrence_without_campaign_guessing(repeated):
    packets = burst(6, 24)[:16 if repeated else 8]
    for index, packet in enumerate(packets):
        mark(packet, 500 + index, True, True)
        if index >= 8:
            packet.event_time += timedelta(milliseconds=300)
            packet.src.ip = IPv4Address("192.0.2.50")
    [hit] = detect_all(packets, "flood-session")
    assert hit["rule_id"] == "R22"
    assert hit.get("attack_subtype") == ("DoS/DDoS-HTTP_Flood" if repeated else None)
    assert hit["flood_observation"] == {
        "behavior": "HTTP_Flood",
        "observed_source_ip_count": 2 if repeated else 1,
        "campaign_scope": "unknown",
        "support": "flood_candidate" if repeated else "request_burst_only",
    }
    assert reproduce(packets, "flood-session", hit) == [hit]


def test_dev33_observation_reproduces_without_merged_label():
    packets = burst(6, 2)
    [current] = detect_all(packets, "flood-session")
    saved = {
        **current,
        "rule_version": "1.2.0",
        "config": {**current["config"], "version": "1.2.0"},
    }
    [historical] = reproduce(packets, "flood-session", saved)
    assert historical["rule_version"] == "1.2.0"
    assert "attack_subtype" not in historical
    assert historical["flood_observation"] == current["flood_observation"]
    assert historical["id"] != current["id"]


@pytest.mark.parametrize("same_service", [0, 47, 48, 64])
def test_syn_flood_uses_only_same_service_contributions(same_service):
    packets = burst(6, 2)
    for index, packet in enumerate(packets[same_service:]):
        packet.dst.port = 20000 + index
    hits = detect_all(packets, "flood-session")
    syn = [hit for hit in hits if hit["rule_id"] == "R18"]
    if same_service < 48:
        assert syn == []
        return
    [hit] = syn
    assert hit["attack_subtype"] == "DoS/DDoS-SYN_Flood"
    assert hit["observed_matches"] == len(hit["contributing_evidence_ids"]) == same_service
    assert set(hit["contributing_evidence_ids"]) == {p.event_id for p in packets[:same_service]}
    assert reproduce(packets, "flood-session", hit) == [hit]
