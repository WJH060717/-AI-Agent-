import struct
from ipaddress import IPv4Address, ip_address

import pytest
from fastapi.testclient import TestClient

from apps.api.main import create_app
from packages.storage.analysis import AnalysisService
from scripts.verify_fragment_rules import capture_case, repeat_and_replay
from tests.integration.test_pcap_packet import (
    arp_request_frame,
    events,
    ipv4_frame,
    one_dataset,
    upload,
)


def capture(*records: tuple[int, bytes]) -> bytes:
    return struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1) + b"".join(
        struct.pack("<IIII", 1000 + us // 1_000_000, us % 1_000_000, len(frame), len(frame)) + frame
        for us, frame in records
    )


def dns_frame(
    *answers: str,
    xid: int = 42,
    label: bytes = b"demo",
    qtype: int = 1,
    ttl: int = 1,
    truncated: bool = False,
    client_port: int = 46000,
    edns: bool = False,
) -> bytes:
    flags = 0x8180 if answers else 0x0100
    if truncated:
        flags |= 0x0200
    question = bytes((len(label),)) + label + b"\x07example\x00" + struct.pack("!HH", qtype, 1)
    message = struct.pack("!HHHHHH", xid, flags, 1, len(answers), 0, int(edns)) + question
    for address in map(ip_address, answers):
        message += b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, ttl, len(address.packed))
        message += address.packed
    if edns:
        message += b"\x00" + struct.pack("!HHIH", 41, 1232, 0, 0)
    client, resolver = IPv4Address("192.0.2.1").packed, IPv4Address("192.0.2.2").packed
    src, dst, src_port, dst_port = (
        (resolver, client, 53, client_port) if answers else (client, resolver, client_port, 53)
    )
    frame = ipv4_frame(
        17, struct.pack("!HHHH", src_port, dst_port, 8 + len(message), 0) + message, destination=dst
    )
    return frame[:26] + src + frame[30:]


def arp_reply() -> bytes:
    sender = bytes.fromhex("020000000009")
    target = bytes.fromhex("020000000002")
    return (
        target
        + sender
        + bytes.fromhex("0806")
        + struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2)
        + sender
        + bytes((192, 0, 2, 1))
        + target
        + bytes((192, 0, 2, 2))
    )


@pytest.mark.parametrize(
    "rule,raw,witness",
    [
        ("R28", capture((0, arp_request_frame(2)), (10_000_000, arp_reply())), [1, 2]),
        (
            "R29",
            capture(
                (0, dns_frame(label=b"DEMO")),
                (1_000_000, dns_frame("203.0.113.1")),
                (3_000_000, dns_frame("203.0.113.2")),
            ),
            [1, 2, 3],
        ),
        (
            "R29",
            capture(
                (0, dns_frame(qtype=28)),
                (1_000_000, dns_frame("2001:db8::1", qtype=28)),
                (3_000_000, dns_frame("2001:db8::2", qtype=28)),
            ),
            [1, 2, 3],
        ),
    ],
)
def test_conflict_observation_survives_report_evidence_and_replay(context, rule, raw, witness):
    settings, _, service, workspace, tokens = context
    actor = service.system_actor(workspace)
    dataset = one_dataset(service, actor)
    headers = {"Authorization": f"Bearer {tokens['admin']}"}
    with TestClient(create_app(settings)) as client:
        row = capture_case(client, service, headers, dataset, raw, "neutral-case")
        assert not row["candidate_subtypes"] and not row["verification_failures"]
        [candidate] = row["unclassified_candidates"]
        assert candidate["rule"] == rule and candidate["verified"]
        assert [packet["packet"] for packet in candidate["window_records"]] == witness
        [behavior] = candidate["behavior_assessments"]
        assert behavior["behavior"] == {
            "R28": "arp_spoofing_suspected",
            "R29": "dns_spoofing_suspected",
        }[rule]
        assert behavior["trace_status"] == "unsuccessful"
        assert behavior["trace_reason"] and behavior["trace_scope"]
        assert {
            ref["event_id"] for ref in behavior["evidence_refs"]
        } == {packet["event_id"] for packet in candidate["contributing_packets"]}
        assert candidate["behavior_report_verified"]
        assert repeat_and_replay(client, service, headers, dataset, raw, candidate["finding_id"])[
            "same_witness"
        ]
    assert "demo.example" not in str(events(service, actor, dataset))
    if rule == "R29":
        assert "203.0.113." not in str(events(service, actor, dataset))


@pytest.mark.parametrize(
    "raw",
    [
        capture((0, arp_request_frame(2)), (10_000_001, arp_reply())),
        capture((0, arp_request_frame(2)), (1, arp_request_frame(3))),
        capture(
            (0, arp_request_frame(2)),
            (1, arp_request_frame(1, sender=bytes.fromhex("020000000009"))),
        ),
        capture((0, arp_request_frame(2)), (1, arp_reply()[:38])),
        capture((0, dns_frame("203.0.113.1")), (1, dns_frame("203.0.113.2"))),
        capture(
            (0, dns_frame()),
            (1, dns_frame("203.0.113.1", "203.0.113.2")),
            (2, dns_frame("203.0.113.2", "203.0.113.1", "203.0.113.2", ttl=15)),
        ),
        capture(
            (0, dns_frame()), (1, dns_frame("203.0.113.1")), (3_000_001, dns_frame("203.0.113.2"))
        ),
        capture(
            (0, dns_frame()), (1, dns_frame("203.0.113.1")), (2, dns_frame("203.0.113.2", xid=43))
        ),
        capture(
            (0, dns_frame()),
            (1, dns_frame("203.0.113.1")),
            (2, dns_frame("203.0.113.2", client_port=46001)),
        ),
        capture(
            (0, dns_frame()),
            (1, dns_frame("203.0.113.1")),
            (2, dns_frame("203.0.113.2", label=b"another")),
        ),
        capture(
            (0, dns_frame()),
            (1, dns_frame("203.0.113.1")),
            (2, dns_frame("203.0.113.2", truncated=True)),
        ),
        capture(
            (0, dns_frame()),
            (1, dns_frame("203.0.113.1")),
            (2, dns_frame()),
            (3, dns_frame("203.0.113.2")),
        ),
        capture(
            (0, dns_frame()),
            (1, dns_frame("203.0.113.1")),
            (2, dns_frame("203.0.113.2")),
            (3, dns_frame()),
        ),
        capture((0, dns_frame()), (10, dns_frame("203.0.113.1")), (9, dns_frame("203.0.113.2"))),
    ],
)
def test_controls_do_not_publish_difference(context, raw):
    _, _, service, workspace, _ = context
    actor = service.system_actor(workspace)
    dataset = one_dataset(service, actor)
    batch = upload(service, actor, dataset, raw, "input")
    assert service.process_one()
    assert service.get_batch(actor, batch)["status"] == "succeeded"
    assert not AnalysisService(service).list_incidents(
        actor, dataset["dataset_id"], dataset["default_session_id"]
    )


def test_scope_never_pairs_distinct_raw_objects(context):
    _, _, service, workspace, _ = context
    actor = service.system_actor(workspace)
    dataset = one_dataset(service, actor)
    inputs = [
        capture((0, dns_frame()), (1, dns_frame("203.0.113.1")), (0, arp_request_frame(2))),
        capture((2, dns_frame("203.0.113.2")), (2, arp_reply())),
    ]
    for number, raw in enumerate(inputs):
        batch = upload(service, actor, dataset, raw, str(number))
        assert service.process_one()
        assert service.get_batch(actor, batch)["accepted"] == (3, 2)[number]
    assert not AnalysisService(service).list_incidents(
        actor, dataset["dataset_id"], dataset["default_session_id"]
    )


def test_normal_control_coverage_counts_only_parsed_protocols() -> None:
    from eval.ciciot_extension import conflict_control_coverage

    raw = capture(
        (0, arp_request_frame(2)),
        (1, arp_reply()),
        (2, dns_frame()),
        (3, dns_frame("203.0.113.1")),
        (4, dns_frame("203.0.113.2", truncated=True)),
    )
    assert conflict_control_coverage(raw, 5) == {
        "arp_request": 1,
        "arp_reply": 1,
        "udp_port_53": 3,
        "dns_query": 1,
        "dns_response": 1,
    }
    with pytest.raises(ValueError, match="record count"):
        conflict_control_coverage(raw, 4)


@pytest.mark.parametrize(
    "extra_records",
    [
        [(1_900_000, dns_frame(edns=True)), (2_000_000, dns_frame("203.0.113.2"))],
        [
            (2_000_000, dns_frame("203.0.113.2")),
            (4_000_000, dns_frame("203.0.113.2")),
            (2_500_000, dns_frame()),
        ],
    ],
)
def test_dns_window_does_not_skip_readable_retry_or_late_timestamp_regression(
    context, extra_records
):
    _, _, service, workspace, _ = context
    actor = service.system_actor(workspace)
    dataset = one_dataset(service, actor)
    raw = capture((0, dns_frame()), (1_000_000, dns_frame("203.0.113.1")), *extra_records)
    batch = upload(service, actor, dataset, raw)
    assert service.process_one()
    assert service.get_batch(actor, batch)["status"] == "succeeded"
    assert not AnalysisService(service).list_incidents(
        actor, dataset["dataset_id"], dataset["default_session_id"]
    )
