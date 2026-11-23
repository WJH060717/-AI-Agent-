import struct

from packages.storage.analysis import AnalysisService


def ipv4_frame(protocol, body, *, fragment=0, destination=bytes((192, 0, 2, 2))):
    ethernet = bytes(12) + b"\x08\x00"
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        len(body) + 20,
        5,
        fragment,
        64,
        protocol,
        0,
        bytes((192, 0, 2, 1)),
        destination,
    )
    return ethernet + ip + body


def pcap(*frames, gap_us=1):
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    records = []
    for index, (frame, length) in enumerate(frames):
        records.append(struct.pack("<IIII", 1000, index * gap_us, len(frame), length) + frame)
    return header + b"".join(records)


def one_dataset(service, actor, key="dataset"):
    return service.create_dataset(actor, {"name": key, "provenance_type": "synthetic"}, key)


def upload(service, actor, dataset, raw, key="capture"):
    return service.stage_bytes(
        actor, dataset["dataset_id"], "pcap_packet", "probe", "UTC", raw, key
    )["batch_id"]


def events(service, actor, dataset):
    return service.list_events(actor, dataset["dataset_id"], dataset["default_session_id"], 20)[
        "items"
    ]


def test_pcap_packet_import_counts_fragments_and_capture_truncation(context):
    settings, _, service, workspace, _ = context
    settings.detection_event_limit = 2
    actor = service.system_actor(workspace)
    dataset = one_dataset(service, actor)
    tcp = struct.pack("!HHIIHHHH", 4321, 80, 1, 2, 0x5010, 0, 0, 0)
    first = ipv4_frame(6, tcp + bytes(12), fragment=0x2000)
    tail = ipv4_frame(6, b"tail", fragment=4)
    full = ipv4_frame(6, tcp + b"OBSERVATION_ONLY")
    background = bytes(12) + b"\x08\x06" + bytes(28)
    raw = pcap(
        (first, len(first)),
        (tail, len(tail)),
        (full[:-4], len(full)),
        (background, len(background)),
    )
    batch = upload(service, actor, dataset, raw)
    assert service.process_one()
    status = service.get_batch(actor, batch)
    assert status["status"] == "succeeded"
    assert (
        status["raw_records"],
        status["accepted"],
        status["skipped"],
        status["quarantined"],
    ) == (4, 3, 1, 0)
    observed = events(service, actor, dataset)
    assert [e["event_type"] for e in observed] == ["network.packet"] * 3
    assert observed[0]["packet"]["tcp_flags"] == 16
    assert observed[1]["packet"]["tcp_flags"] is None
    assert observed[1]["dst"]["port"] is None
    assert "capture_truncated" in observed[2]["quality_flags"]
    assert observed[2]["packet"]["tcp_payload_bytes_captured"] == len(b"OBSERVATION_ONLY") - 4
    assert "OBSERVATION_ONLY" not in str(observed)
    assert not AnalysisService(service).list_incidents(
        actor, dataset["dataset_id"], dataset["default_session_id"]
    )
    overview = service.overview(actor, dataset["dataset_id"], dataset["default_session_id"])
    assert overview["event_count"] == 3 and overview["detection_status"] == "complete"
    assert overview["warnings"] == []
    repeat = upload(service, actor, dataset, raw, "repeat")
    assert service.process_one()
    repeated = service.get_batch(actor, repeat)
    assert (repeated["accepted"], repeated["duplicate"], repeated["skipped"]) == (0, 3, 1)


def test_packet_evidence_rechecks_capture_and_scope(context):
    import json

    import pytest
    from sqlalchemy import select

    from packages.storage import schema_v6 as tables
    from packages.storage.service import DomainError

    settings, db, service, workspace, tokens = context
    actor = service.system_actor(workspace)
    dataset = one_dataset(service, actor)
    tcp = struct.pack("!HHIIHHHH", 4321, 80, 1, 2, 0x5010, 0, 0, 0)
    frame = ipv4_frame(6, tcp + b"OBSERVATION_ONLY" + bytes(4), fragment=0x2000)
    raw = pcap((frame, len(frame)))
    legacy = one_dataset(service, actor, "legacy-capture")
    legacy_batch = service.stage_bytes(
        actor, legacy["dataset_id"], "pcap", "probe", "UTC", raw, "legacy-upload"
    )["batch_id"]
    assert service.process_one()
    assert service.get_batch(actor, legacy_batch)["quarantined"] > 0
    upload(service, actor, dataset, raw)
    assert service.process_one()
    [packet] = events(service, actor, dataset)
    # Synthetic connect events create an ordinary investigation snapshot in the same time window.
    network = b"".join(
        json.dumps(
            {
                "ts": 1000,
                "id.orig_h": "192.0.2.1",
                "id.orig_p": 40000,
                "id.resp_h": "192.0.2.2",
                "id.resp_p": port,
                "proto": "tcp",
            }
        ).encode()
        + b"\n"
        for port in range(100, 130)
    )
    service.stage_bytes(actor, dataset["dataset_id"], "zeek", "logs", "UTC", network, "logs")
    assert service.process_one()
    analysis = AnalysisService(service)
    [incident] = analysis.list_incidents(
        actor, dataset["dataset_id"], dataset["default_session_id"]
    )
    settings.snapshot_event_limit = 30
    run = analysis.create_run(actor, incident["id"], "run")
    with pytest.raises(DomainError, match="EVIDENCE_OUT_OF_SCOPE"):
        analysis.evidence(actor, packet["event_id"], run["snapshot_id"])
    packet_scope = service.list_events(
        actor, dataset["dataset_id"], dataset["default_session_id"], 100
    )["packet_evidence_scope"]
    from fastapi.testclient import TestClient

    from apps.api.main import create_app

    with TestClient(create_app(settings)) as client:
        auth = {"Authorization": f"Bearer {tokens['viewer']}"}
        page = client.get(
            "/api/v1/events",
            params={
                "dataset_id": dataset["dataset_id"],
                "session_id": dataset["default_session_id"],
                "limit": 100,
            },
            headers=auth,
        ).json()
        status = client.get(
            f"/api/v1/evidence/{packet['event_id']}",
            params={"packet_scope": page["packet_evidence_scope"]},
            headers=auth,
        )
        assert status.status_code == 200 and status.json()["verified"]
        [fragment] = status.json()["fragments"]
        address = f"/api/v1/raw-objects/{fragment['object_id']}/download"
        assert client.get(address, headers=auth).status_code == 403
        download = client.get(address, headers={"Authorization": f"Bearer {tokens['admin']}"})
        assert download.status_code == 200
        assert download.headers["Content-Disposition"].endswith('.pcap"')
        assert download.content == pcap((frame, len(frame)))
    assert fragment["pcap_record"]["record_number"] == 1
    assert fragment["pcap_record"]["packet"]["tcp_flags"] == 16
    assert "OBSERVATION_ONLY" not in json.dumps(fragment)
    another, _ = service.init_workspace("another")
    with pytest.raises(DomainError, match="NOT_FOUND"):
        analysis.evidence(service.system_actor(another), packet["event_id"], run["snapshot_id"])
    second = one_dataset(service, actor, "another-dataset")
    upload(service, actor, second, pcap((frame, len(frame))), "another-capture")
    # The investigation may be claimed before the second import.
    while service.process_one():
        pass
    [outside] = events(service, actor, second)
    with pytest.raises(DomainError, match="EVIDENCE_OUT_OF_SCOPE"):
        analysis.evidence(actor, outside["event_id"], run["snapshot_id"])
    locator = packet["source_locators"][0]
    corrupt = dict(packet)
    corrupt["source_locators"] = [
        {**locator, "pcap": {"byte_start": 25, "byte_end": locator["pcap"]["byte_end"]}}
    ]
    with db.engine.begin() as conn:
        conn.execute(
            tables.events.update()
            .where(tables.events.c.event_id == packet["event_id"])
            .values(payload=corrupt)
        )
        obj = (
            conn.execute(select(tables.objects).where(tables.objects.c.id == locator["object_id"]))
            .mappings()
            .one()
        )
    with pytest.raises(DomainError, match="EVIDENCE_RANGE_INVALID"):
        analysis.packet_evidence(actor, packet["event_id"], packet_scope)
    corrupt["source_locators"][0]["pcap"]["byte_start"] = 23
    with db.engine.begin() as conn:
        conn.execute(
            tables.events.update()
            .where(tables.events.c.event_id == packet["event_id"])
            .values(payload=corrupt)
        )
    with pytest.raises(DomainError, match="EVIDENCE_RANGE_INVALID"):
        analysis.packet_evidence(actor, packet["event_id"], packet_scope)
    with db.engine.begin() as conn:
        conn.execute(
            tables.events.update()
            .where(tables.events.c.event_id == packet["event_id"])
            .values(payload=packet)
        )
    path = service.archive_path(obj["storage_key"])
    path.write_bytes(path.read_bytes() + b"x")
    with pytest.raises(DomainError, match="ARCHIVE_INTEGRITY_FAILED"):
        analysis.packet_evidence(actor, packet["event_id"], packet_scope)


def test_capture_with_broken_record_boundary_publishes_no_prefix(context):
    import pytest

    from packages.ingest.pcap_packet import PcapReadError

    settings, _, service, workspace, _ = context
    settings.import_chunk_lines = 1
    actor = service.system_actor(workspace)
    dataset = one_dataset(service, actor)
    frame = ipv4_frame(1, bytes(8))
    good = pcap((frame, len(frame)))
    raw = good + struct.pack("<IIII", 1000, 0, 99, 99) + bytes(8)
    batch = upload(service, actor, dataset, raw)
    with pytest.raises(PcapReadError, match="PCAP_INVALID_RECORD_BOUNDARY"):
        service.process_one()
    status = service.get_batch(actor, batch)
    assert status["status"] == "failed"
    assert status["raw_records"] == 1
    assert status["capture_failure"] == {"byte_offset": len(good), "record": 2}
    assert events(service, actor, dataset) == []
    header_batch = upload(service, actor, dataset, b"INVALID" * 5, "header")
    with pytest.raises(PcapReadError, match="PCAP_INVALID_HEADER"):
        service.process_one()
    assert service.get_batch(actor, header_batch)["capture_failure"] == {
        "byte_offset": 0,
        "record": None,
    }


def test_packet_import_resume_and_fixed_watermark_replay(context):
    from datetime import UTC, datetime, timedelta

    import pytest

    from packages.contracts.replay import ReplayCreate
    from packages.storage.queue import LeaseLost, Queue
    from packages.storage.replay import ReplayRunner, ReplayService
    from packages.storage.worker import ImportRunner

    settings, db, service, workspace, _ = context
    settings.import_chunk_lines = 1
    actor = service.system_actor(workspace)
    dataset = one_dataset(service, actor)
    frame = ipv4_frame(1, bytes(8))
    raw = pcap((frame, len(frame)), (frame, len(frame)), (frame, len(frame)))
    batch = upload(service, actor, dataset, raw)
    queue = Queue(db, settings)
    importer = ImportRunner(service, queue)
    current = datetime.now(UTC)
    first = queue.claim("first", at=current)
    assert not importer.step(first)
    assert events(service, actor, dataset) == []
    from sqlalchemy import select

    from packages.storage import schema_v6 as tables
    from packages.storage.service import DomainError

    with db.engine.connect() as conn:
        unpublished_id = conn.execute(
            select(tables.events.c.event_id).where(
                tables.events.c.workspace_id == workspace,
                tables.events.c.dataset_id == dataset["dataset_id"],
            )
        ).scalar_one()
    with pytest.raises(DomainError, match="NOT_FOUND"):
        service.get_event(actor, unpublished_id)
    recovered = queue.claim(
        "recovered", at=current + timedelta(seconds=settings.worker_lease_seconds + 1)
    )
    assert recovered and recovered.job_id == first.job_id and recovered.version > first.version
    with pytest.raises(LeaseLost):
        importer.step(first)
    while not importer.step(recovered):
        pass
    status = service.get_batch(actor, batch)
    assert (status["raw_records"], status["accepted"], status["duplicate"]) == (3, 3, 0)
    original = [e["event_id"] for e in events(service, actor, dataset)]
    assert len(set(original)) == 3
    repeat = upload(service, actor, dataset, raw, "after-recovery")
    assert service.process_one()
    assert service.get_batch(actor, repeat)["duplicate"] == 3

    replay = ReplayService(service)
    created = replay.create(
        actor,
        dataset["dataset_id"],
        ReplayCreate(source_session_id=dataset["default_session_id"], rate_eps=1000),
        "replay",
    )
    lease = queue.claim("replayer")
    clock = [datetime.now(UTC)]
    runner = ReplayRunner(service, queue, clock=lambda: clock[0])
    while runner.step(lease) is not None:
        clock[0] += timedelta(seconds=1)
    restored = service.list_events(actor, dataset["dataset_id"], created["session_id"], 20)
    assert [e["event_id"] for e in restored["items"]] == original
    assert [e["event_id"] for e in events(service, actor, dataset)] == original


def test_standalone_capture_evidence_is_bound_to_actor_session_and_watermark(context):
    from fastapi.testclient import TestClient

    from apps.api.main import create_app

    settings, _, service, workspace, tokens = context
    actor = service.system_actor(workspace)
    dataset = one_dataset(service, actor)
    frame = ipv4_frame(1, bytes(8))
    raw = pcap((frame, len(frame)))
    upload(service, actor, dataset, raw)
    assert service.process_one()
    with TestClient(create_app(settings)) as client:
        auth = {"Authorization": f"Bearer {tokens['viewer']}"}
        filters = {"dataset_id": dataset["dataset_id"], "session_id": dataset["default_session_id"]}
        page = client.get("/api/v1/events", params=filters, headers=auth).json()
        evidence_filter = {"packet_scope": page["packet_evidence_scope"]}
        [packet] = page["items"]
        url = f"/api/v1/evidence/{packet['event_id']}"
        response = client.get(url, params=evidence_filter, headers=auth)
        assert response.status_code == 200
        assert response.json()["fragments"][0]["pcap_record"]["record_number"] == 1
        assert (
            client.get(
                url, params=evidence_filter, headers={"Authorization": f"Bearer {tokens['admin']}"}
            ).status_code
            == 422
        )
        assert (
            client.get(
                url, params={"packet_scope": evidence_filter["packet_scope"] + "0"}, headers=auth
            ).status_code
            == 422
        )
        changed = ipv4_frame(1, bytes((8,)) + bytes(7))
        upload(service, actor, dataset, pcap((changed, len(changed))), "newer")
        assert service.process_one()
        after = client.get("/api/v1/events", params=filters, headers=auth).json()
        later = next(event for event in after["items"] if event["event_id"] != packet["event_id"])
        later_url = f"/api/v1/evidence/{later['event_id']}"
        assert client.get(later_url, params=evidence_filter, headers=auth).status_code == 404
        other = one_dataset(service, actor, "other")
        upload(service, actor, other, raw, "other-upload")
        assert service.process_one()
        [outside] = events(service, actor, other)
        assert (
            client.get(
                f"/api/v1/evidence/{outside['event_id']}", params=evidence_filter, headers=auth
            ).status_code
            == 404
        )


def test_invalid_transport_and_fragment_header_are_quarantined(context):
    _, _, service, workspace, _ = context
    actor = service.system_actor(workspace)
    dataset = one_dataset(service, actor)
    udp = ipv4_frame(17, struct.pack("!HHHH", 1024, 53, 7, 0))
    malformed = ipv4_frame(1, bytes(9), fragment=0x2000)
    impossible_udp = ipv4_frame(17, bytes(6))
    raw = pcap(
        (udp, len(udp)), (malformed, len(malformed)), (impossible_udp[:-2], len(impossible_udp))
    )
    batch = upload(service, actor, dataset, raw)
    assert service.process_one()
    status = service.get_batch(actor, batch)
    assert status["quarantined"] == 3 and status["accepted"] == 0
    assert status["packet_issue_counts"] == {
        "PCAP_INVALID_UDP_LENGTH": 1,
        "PCAP_INVALID_FRAGMENT": 1,
        "PCAP_INVALID_TRANSPORT_HEADER": 1,
    }
    assert events(service, actor, dataset) == []


def test_ethernet_padding_does_not_complete_a_short_echo_header(context):
    _, _, service, workspace, _ = context
    actor = service.system_actor(workspace)
    dataset = one_dataset(service, actor)
    frame = ipv4_frame(1, bytes((8, 0, 0, 0))) + bytes(20)
    upload(service, actor, dataset, pcap((frame, len(frame))))
    assert service.process_one()
    [event] = events(service, actor, dataset)
    assert event["packet"]["icmp_type"] == 8
    assert event["packet"]["icmp_echo_header_complete"] is False


def test_ping_sweep_import_report_and_replay_keep_evidence_locations(context):
    from fastapi.testclient import TestClient

    from apps.api.main import create_app
    from scripts.verify_fragment_rules import capture_case, repeat_and_replay

    settings, _, service, workspace, tokens = context
    actor = service.system_actor(workspace)
    dataset = one_dataset(service, actor)
    frames = [
        ipv4_frame(1, bytes((8, 0)) + bytes(6), destination=bytes((198, 51, 100, target)))
        for target in range(1, 9)
    ]
    raw = pcap(*((frame, len(frame)) for frame in frames))
    headers = {"Authorization": f"Bearer {tokens['admin']}"}
    with TestClient(create_app(settings)) as client:
        result = capture_case(client, service, headers, dataset, raw, "offline-capture")
        assert result["import_status"] == "succeeded"
        assert result["record_counts"] == {
            "raw_records": 8, "accepted": 8, "duplicate": 0, "skipped": 0, "quarantined": 0,
        }
        assert result["candidate_subtypes"] == ["Recon-PingSweep"]
        assert not result["verification_failures"]
        [candidate] = result["verified_candidates"]
        assert candidate["verified"] and candidate["evidence_count"] == 8
        assert [record["packet"] for record in candidate["window_records"]] == list(range(1, 9))
        replay = repeat_and_replay(client, service, headers, dataset, raw, candidate["finding_id"])
        assert replay == {"duplicates": 8, "replay_members": 8, "same_witness": True}


def arp_request_frame(target, *, sender=b"\x02\x00\x00\x00\x00\x01", operation=1):
    return (
        bytes.fromhex("ffffffffffff") + sender + bytes.fromhex("0806")
        + struct.pack("!HHBBH", 1, 0x0800, 6, 4, operation)
        + sender + bytes((192, 0, 2, 1)) + bytes(6) + bytes((192, 0, 2, target))
    )


def test_host_discovery_packet_evidence_survives_import_report_and_replay(context):
    from fastapi.testclient import TestClient

    from apps.api.main import create_app
    from scripts.verify_fragment_rules import capture_case, repeat_and_replay

    settings, _, service, workspace, tokens = context
    dataset = one_dataset(service, service.system_actor(workspace))
    frames = [arp_request_frame(target) for target in range(2, 10)]
    raw = pcap(*((frame, len(frame)) for frame in frames))
    headers = {"Authorization": f"Bearer {tokens['admin']}"}
    with TestClient(create_app(settings)) as client:
        row = capture_case(client, service, headers, dataset, raw, "offline-capture")
        assert row["record_counts"]["accepted"] == 8
        assert row["candidate_subtypes"] == []
        assert not row["verification_failures"]
        [candidate] = row["unclassified_candidates"]
        assert candidate["rule"] == "R26" and candidate["subtype"] is None
        assert candidate["verified"] and candidate["evidence_count"] == 8
        replay = repeat_and_replay(client, service, headers, dataset, raw, candidate["finding_id"])
        assert replay == {"duplicates": 8, "replay_members": 8, "same_witness": True}


def test_arp_reply_malformed_sender_and_repeated_neighbour_stay_out_of_host_discovery(context):
    _, _, service, workspace, _ = context
    actor = service.system_actor(workspace)
    dataset = one_dataset(service, actor)
    request = arp_request_frame(2)
    variants = [
        arp_request_frame(3, operation=2),
        request[:6] + bytes(6) + request[12:],
    ]
    raw = pcap(*((frame, len(frame)) for frame in [request] * 8 + variants))
    batch = upload(service, actor, dataset, raw)
    assert service.process_one()
    status = service.get_batch(actor, batch)
    assert (status["accepted"], status["skipped"]) == (8, 2)
    assert not AnalysisService(service).list_incidents(
        actor, dataset["dataset_id"], dataset["default_session_id"]
    )


def test_gre_direct_ip_and_ethernet_are_verified_as_distinct_observations(context):
    from fastapi.testclient import TestClient

    from apps.api.main import create_app
    from scripts.verify_fragment_rules import capture_case, repeat_and_replay

    settings, _, service, workspace, tokens = context
    actor = service.system_actor(workspace)
    inner = ipv4_frame(17, struct.pack("!HHHH", 1000, 2000, 8, 0))
    headers = {"Authorization": f"Bearer {tokens['admin']}"}
    with TestClient(create_app(settings)) as client:
        for kind, protocol, payload in [
            ("ip", 0x0800, inner[14:]), ("ethernet", 0x6558, inner),
        ]:
            dataset = one_dataset(service, actor, kind)
            frame = ipv4_frame(47, struct.pack("!HH", 0, protocol) + payload)
            raw = pcap(*[(frame, len(frame))] * 64, gap_us=2000)
            result = capture_case(client, service, headers, dataset, raw, "neutral-" + kind)
            assert not result["candidate_subtypes"] and not result["verification_failures"]
            [found] = result["unclassified_candidates"]
            assert found["rule"] == "R27" and found["verified"]
            assert found["gre_encapsulation"] == kind
            replay = repeat_and_replay(client, service, headers, dataset, raw, found["finding_id"])
            assert replay["same_witness"]
