import json
import struct
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import select

from packages.contracts.context import DatasetContext
from packages.storage import schema_v5 as t
from packages.storage.analysis import AnalysisService
from packages.storage.context import ContextService
from packages.storage.service import digest
from tests.integration.d4_helpers import HOST, auth_record, context_payload, raw_lines
from tests.integration.test_d4_pipeline import setup as host_setup


def pcap_at(stamp: datetime, frame: bytes) -> bytes:
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    record = struct.pack("<IIII", int(stamp.timestamp()), 0, len(frame), len(frame)) + frame
    return header + record


def ipv4_tcp(src: str, sport: int, dst: str, dport: int) -> bytes:
    tcp = struct.pack("!HHIIHHHH", sport, dport, 1, 2, 0x5010, 0, 0, 0)
    import socket

    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        len(tcp) + 20,
        1,
        0,
        64,
        6,
        0,
        socket.inet_aton(src),
        socket.inet_aton(dst),
    )
    return bytes(12) + b"\x08\x00" + ip + tcp


def test_snapshot_keeps_packet_seed_and_cross_source_host_context(context):
    settings, db, service, workspace, _ = context
    actor = service.system_actor(workspace)
    dataset = service.create_dataset(actor, {"name": "cross", "provenance_type": "synthetic"}, "d")
    cfg = context_payload()
    cfg["assets"][0]["addresses"].append(
        {
            "ip": "192.0.2.10",
            "observation_domain": "lab-a",
            "valid_from": "2026-11-14T00:00:00Z",
            "valid_to": "2026-11-15T00:00:00Z",
        }
    )
    cfg["sensors"].append(
        {
            "sensor_id": "probe",
            "source_type": "pcap",
            "instance_id": "probe",
            "observation_domain": "lab-a",
            "clock_basis": "synthetic_clock",
            "uncertainty_ms": 0,
        }
    )
    ContextService(service).configure(
        actor, dataset["dataset_id"], DatasetContext.model_validate(cfg), "ctx"
    )
    stamp = datetime(2026, 11, 14, 1, 0, 10, tzinfo=UTC)
    service.stage_bytes(
        actor,
        dataset["dataset_id"],
        "pcap_packet",
        "probe",
        "UTC",
        pcap_at(stamp, ipv4_tcp("10.10.0.20", 50000, "192.0.2.10", 80)),
        "pcap",
    )
    service.stage_bytes(
        actor,
        dataset["dataset_id"],
        "linux_auth",
        "auth-a",
        "UTC",
        raw_lines([auth_record(6, "failure")]),
        "auth",
    )
    audit = raw_lines(
        [
            {
                "timestamp": "2026-11-14T01:00:07Z",
                "host": "host-a",
                "boot_id": "boot-a",
                "audit_serial": "7",
                "record_type": "SYSCALL",
                "process": {
                    "pid": 42,
                    "action": "create",
                    "start_ticks": 100,
                    "identity_basis": "lifecycle_record",
                    "executable": "/lab/client",
                },
                "synthetic": True,
            },
            {
                "timestamp": "2026-11-14T01:00:07Z",
                "host": "host-a",
                "boot_id": "boot-a",
                "audit_serial": "7",
                "record_type": "EOE",
                "synthetic": True,
            },
        ]
    )
    service.stage_bytes(
        actor, dataset["dataset_id"], "linux_audit", "audit-a", "UTC", audit, "audit"
    )
    while service.process_one():
        pass
    events = service.list_events(
        actor, dataset["dataset_id"], dataset["default_session_id"], 100
    )["items"]
    packet = next(e for e in events if e["event_type"] == "network.packet")
    auth = next(e for e in events if e["event_type"] == "auth.login")
    process = next(e for e in events if e["event_type"] == "host.process")
    assert packet["dst"]["asset_id"] == HOST and auth["asset_id"] == HOST
    assert process["process"]["entity_id"]

    finding_id = "f" * 64
    with db.engine.begin() as conn:
        conn.execute(
            t.findings.insert().values(
                workspace_id=workspace,
                id=finding_id,
                dataset_id=dataset["dataset_id"],
                session_id=dataset["default_session_id"],
                payload={
                    "id": finding_id,
                    "rule_id": "R12",
                    "rule_version": "test",
                    "dataset_id": dataset["dataset_id"],
                    "session_id": dataset["default_session_id"],
                    "evidence_ids": [packet["event_id"]],
                },
            )
        )
        conn.execute(
            t.incidents.insert().values(
                workspace_id=workspace,
                id=str(uuid4()),
                dataset_id=dataset["dataset_id"],
                session_id=dataset["default_session_id"],
                finding_id=finding_id,
                title="cross-source",
                start_time="2026-11-14T01:00:05+00:00",
                end_time="2026-11-14T01:00:15+00:00",
                created_at="2026-11-14T01:00:15+00:00",
            )
        )
        incident_id = conn.execute(
            select(t.incidents.c.id).where(t.incidents.c.finding_id == finding_id)
        ).scalar_one()
        conn.execute(
            t.details.insert().values(
                workspace_id=workspace,
                id=incident_id,
                payload={"finding_ids": [finding_id], "reasons": []},
            )
        )
    analysis = AnalysisService(service)
    with db.engine.begin() as conn:
        wrong_domain = json.loads(json.dumps(auth))
        wrong_domain["event_id"] = "a" * 64
        wrong_domain["sensor"]["observation_domain"] = "lab-b"
        wrong_domain["sensor"]["sensor_id"] = "auth-b"
        wrong_asset = json.loads(json.dumps(auth))
        wrong_asset["event_id"] = "b" * 64
        wrong_asset["asset_id"] = "44444444-4444-4444-8444-444444444444"
        wrong_asset["host"]["asset_id"] = "44444444-4444-4444-8444-444444444444"
        for payload in (wrong_domain, wrong_asset):
            conn.execute(
                t.events.insert().values(
                    workspace_id=workspace,
                    event_id=payload["event_id"],
                    dataset_id=dataset["dataset_id"],
                    event_time=payload["event_time"],
                    event_type=payload["event_type"],
                    payload=payload,
                )
            )
            conn.execute(
                t.members.insert().values(
                    workspace_id=workspace,
                    session_id=dataset["default_session_id"],
                    event_id=payload["event_id"],
                )
            )
    run = analysis.create_run(actor, incident_id, "run")
    with db.engine.connect() as conn:
        ids = conn.execute(
            select(t.snapshots.c.event_ids).where(t.snapshots.c.id == run["snapshot_id"])
        ).scalar_one()
    assert packet["event_id"] in ids and auth["event_id"] in ids and process["event_id"] in ids
    assert "a" * 64 not in ids and "b" * 64 not in ids
    status = analysis.get_run(actor, run["run_id"])
    manifest = status["snapshot_manifest"]
    assert manifest["seed_event_count"] == 1 and manifest["coverage"]["status"] == "complete"
    assert manifest["reason_counts"]["seed"] == 1
    assert manifest["type_counts"]["auth.login"] == 1
    assert manifest["type_counts"]["host.process"] == 1