from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from packages.contracts.models import InvestigationScope, SourceLocator
from packages.graph.service import evidence_graph
from packages.ingest.linux import parse_audit_group
from packages.ingest.parsers import ParseContext, parse_record
from tests.integration.d4_helpers import (
    OTHER,
    audit_record,
    auth_record,
    context_payload,
    parse_context,
    raw_lines,
)


def process(ctx, pid, birth, timestamp, parent=None, boot="boot-a"):
    raw_process = {
        "pid": pid,
        "action": "create",
        "start_ticks": birth,
        "identity_basis": "lifecycle_record",
    }
    if parent:
        raw_process.update(ppid=parent[0], parent_start_ticks=parent[1])
    rows = [
        audit_record("SYSCALL", str(pid), process=raw_process, timestamp=timestamp, boot_id=boot),
        audit_record("EOE", str(pid), timestamp=timestamp, boot_id=boot),
    ]
    raw = raw_lines(rows)
    from hashlib import sha256

    refs = [
        SourceLocator(
            object_id=uuid4(),
            raw_sha256=sha256(raw).hexdigest(),
            record_start=i + 1,
            record_end=i + 1,
        )
        for i in range(2)
    ]
    return parse_audit_group(list(zip(raw.splitlines(), refs, strict=True)), ctx)


def test_pid_reuse_and_boot_reuse_do_not_create_parent_edges():
    ctx = parse_context("linux_audit", b"test")
    parent = process(ctx, 10, 10, "2026-11-14T01:00:01Z")
    child = process(ctx, 42, 20, "2026-11-14T01:00:05Z", (10, 10))
    scope = InvestigationScope(
        workspace_id=ctx.workspace_id,
        dataset_id=ctx.dataset_id,
        session_id=uuid4(),
        snapshot_id=uuid4(),
        start="2026-11-14T00:59:50Z",
        end="2026-11-14T01:01:00Z",
    )
    assert "spawned" in {e.relation for e in evidence_graph([parent, child], scope)["edges"]}
    later_exec = parent.model_copy(deep=True)
    later_exec.event_id = "e" * 64
    later_exec.event_time += timedelta(seconds=1)
    later_exec.process.action = "exec"
    assert "spawned" in {
        e.relation for e in evidence_graph([parent, later_exec, child], scope)["edges"]
    }
    reused = process(ctx, 10, 11, "2026-11-14T01:00:01Z")
    reboot = process(ctx, 10, 10, "2026-11-14T01:00:01Z", boot="boot-b")
    assert reused.process.entity_id != parent.process.entity_id != reboot.process.entity_id
    for wrong in (reused, reboot):
        assert "spawned" not in {e.relation for e in evidence_graph([wrong, child], scope)["edges"]}
    parent.time_quality.uncertainty_ms = child.time_quality.uncertainty_ms = 3000
    assert "spawned" not in {e.relation for e in evidence_graph([parent, child], scope)["edges"]}


def test_ip_validity_is_half_open_and_time_uncertainty_prevents_false_asset_resolution():
    metadata = context_payload()
    metadata["assets"][0]["addresses"][0]["valid_to"] = "2026-11-14T01:00:10Z"
    metadata["assets"].append(
        {
            "asset_id": OTHER,
            "hostnames": ["host-b"],
            "addresses": [
                {
                    "ip": "10.10.0.20",
                    "observation_domain": "lab-a",
                    "valid_from": "2026-11-14T01:00:10Z",
                    "valid_to": "2026-11-15T00:00:00Z",
                }
            ],
        }
    )
    metadata["sensors"].append(
        {
            "sensor_id": "zeek",
            "source_type": "zeek",
            "instance_id": "cap",
            "observation_domain": "lab-a",
            "clock_basis": "synthetic",
            "uncertainty_ms": 0,
            "offset_ms": 1000,
        }
    )
    import hashlib
    import json

    raw = (
        json.dumps(
            {
                "ts": datetime(2026, 11, 14, 1, 0, 9, tzinfo=UTC).timestamp(),
                "proto": "tcp",
                "id.orig_h": "192.0.2.10",
                "id.orig_p": 40000,
                "id.resp_h": "10.10.0.20",
                "id.resp_p": 22,
            }
        )
    ).encode()
    ctx = ParseContext(
        str(uuid4()),
        str(uuid4()),
        str(uuid4()),
        hashlib.sha256(raw).hexdigest(),
        "zeek",
        "zeek",
        "UTC",
        metadata=metadata,
    )
    event = parse_record(raw, 1, ctx)
    assert event.event_time.second == 10 and event.dst.asset_id == UUID(OTHER)
    metadata["sensors"][-1]["uncertainty_ms"] = 1000
    event = parse_record(raw, 1, ctx)
    assert event.dst.asset_id is None and event.dst.resolution_quality == "ambiguous"


def test_network_auth_match_requires_domain_tuple_asset_and_bounded_time():
    import hashlib
    import json

    metadata = context_payload()
    metadata["sensors"].append(
        {
            "sensor_id": "zeek",
            "source_type": "zeek",
            "instance_id": "capture",
            "observation_domain": "lab-a",
            "uncertainty_ms": 0,
            "offset_ms": 0,
            "clock_basis": "synthetic",
        }
    )
    raw = json.dumps(
        {
            "ts": datetime(2026, 11, 14, 1, 0, 9, tzinfo=UTC).timestamp(),
            "proto": "tcp",
            "id.orig_h": "192.0.2.10",
            "id.orig_p": 42010,
            "id.resp_h": "10.10.0.20",
            "id.resp_p": 22,
        }
    ).encode()
    ctx = ParseContext(
        str(uuid4()),
        str(uuid4()),
        str(uuid4()),
        hashlib.sha256(raw).hexdigest(),
        "zeek",
        "zeek",
        "UTC",
        metadata=metadata,
    )
    network = parse_record(raw, 1, ctx)
    auth_raw = raw_lines([auth_record(10, "success") | {"dest_ip": "10.10.0.20", "dest_port": 22}])
    auth_ctx = ParseContext(
        ctx.workspace_id,
        ctx.dataset_id,
        str(uuid4()),
        hashlib.sha256(auth_raw).hexdigest(),
        "auth-a",
        "linux_auth",
        "UTC",
        metadata=metadata,
        identity_salt="a" * 64,
    )
    auth = parse_record(auth_raw, 1, auth_ctx)
    scope = InvestigationScope(
        workspace_id=ctx.workspace_id,
        dataset_id=ctx.dataset_id,
        session_id=uuid4(),
        snapshot_id=uuid4(),
        start="2026-11-14T00:59:50Z",
        end="2026-11-14T01:01:00Z",
    )
    matches = [
        e for e in evidence_graph([network, auth], scope)["edges"] if e.relation == "corresponds_to"
    ]
    assert (
        len(matches) == 1 and matches[0].kind == "inferred" and len(matches[0].evidence_refs) == 2
    )
    for case in ("port", "domain", "asset", "reverse", "gap"):
        altered = network.model_copy(deep=True)
        if case == "port":
            altered.src.port = 42011
        elif case == "domain":
            altered.sensor.observation_domain = "outside"
        elif case == "asset":
            altered.dst.asset_id = None
        elif case == "reverse":
            altered.event_time = auth.event_time + timedelta(seconds=1)
        else:
            altered.event_time = auth.event_time - timedelta(seconds=11)
        assert not [
            e
            for e in evidence_graph([altered, auth], scope)["edges"]
            if e.relation == "corresponds_to"
        ]
