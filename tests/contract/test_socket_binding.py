import hashlib
import json
from datetime import UTC, datetime
from uuid import uuid4

from packages.contracts.models import InvestigationScope
from packages.graph.paths import analyze_paths
from packages.graph.service import evidence_graph
from packages.ingest.linux import parse_audit_group
from packages.ingest.parsers import ParseContext, parse_record
from tests.integration.d4_helpers import HOST, audit_record, context_payload, raw_lines

WORKSPACE = str(uuid4())
DATASET = str(uuid4())


def metadata():
    value = context_payload()
    value["sensors"].extend(
        [
            {
                "sensor_id": "sock-a",
                "source_type": "linux_socket",
                "asset_id": HOST,
                "instance_id": "collector-a",
                "observation_domain": "lab-a",
                "realm": "local",
                "realm_type": "local",
                "offset_ms": 0,
                "uncertainty_ms": 0,
                "clock_basis": "synthetic_clock",
            },
            {
                "sensor_id": "net-a",
                "source_type": "zeek",
                "instance_id": "collector-a",
                "observation_domain": "lab-a",
                "offset_ms": 0,
                "uncertainty_ms": 0,
                "clock_basis": "synthetic_clock",
            },
        ]
    )
    return value


def parse_ctx(source, raw, sensor):
    return ParseContext(
        WORKSPACE,
        DATASET,
        str(uuid4()),
        hashlib.sha256(raw).hexdigest(),
        sensor,
        source,
        "UTC",
        metadata=metadata(),
        identity_salt="a" * 64,
    )


def process_event(timestamp="2026-11-14T01:00:05Z", pid=42, ticks=100, boot="boot-a"):
    rows = [
        audit_record(
            "SYSCALL",
            str(pid),
            timestamp=timestamp,
            boot_id=boot,
            process={
                "pid": pid,
                "action": "create",
                "start_ticks": ticks,
                "identity_basis": "lifecycle_record",
            },
        ),
        audit_record("EOE", str(pid), timestamp=timestamp, boot_id=boot),
    ]
    raw = raw_lines(rows)
    ctx = parse_ctx("linux_audit", raw, "audit-a")
    from packages.contracts.models import SourceLocator

    refs = [
        SourceLocator(
            object_id=uuid4(),
            raw_sha256=hashlib.sha256(raw).hexdigest(),
            record_start=i + 1,
            record_end=i + 1,
        )
        for i in range(2)
    ]
    return parse_audit_group(list(zip(raw.splitlines(), refs, strict=True)), ctx)


def socket_event(
    *,
    pid=42,
    ticks=100,
    boot="boot-a",
    connected="2026-11-14T01:00:10.500Z",
    observed="2026-11-14T01:00:10.600Z",
    local_port=50000,
    remote_ip="192.0.2.10",
):
    raw = json.dumps(
        {
            "timestamp": observed,
            "host": "host-a",
            "boot_id": boot,
            "process": {
                "pid": pid,
                "start_ticks": ticks,
                "identity_basis": "verified_proc",
                "executable": "/lab/client",
            },
            "socket": {
                "inode": 12345,
                "state": "established",
                "role": "client",
                "transport": "tcp",
                "connected_at": connected,
                "local_ip": "10.10.0.20",
                "local_port": local_port,
                "remote_ip": remote_ip,
                "remote_port": 443,
            },
            "synthetic": True,
        }
    ).encode()
    return parse_record(raw, 1, parse_ctx("linux_socket", raw, "sock-a"))


def network_event(timestamp=None, local_port=50000, remote_ip="192.0.2.10"):
    raw = json.dumps(
        {
            "ts": timestamp or datetime(2026, 11, 14, 1, 0, 11, tzinfo=UTC).timestamp(),
            "proto": "tcp",
            "id.orig_h": "10.10.0.20",
            "id.orig_p": local_port,
            "id.resp_h": remote_ip,
            "id.resp_p": 443,
        }
    ).encode()
    return parse_record(raw, 1, parse_ctx("zeek", raw, "net-a"))


def scope(event):
    return InvestigationScope(
        workspace_id=event.workspace_id,
        dataset_id=event.dataset_id,
        session_id=uuid4(),
        snapshot_id=uuid4(),
        start="2026-11-14T00:59:00Z",
        end="2026-11-14T01:01:00Z",
    )


def test_socket_evidence_links_process_to_connection_and_breaks_without_it():
    process = process_event()
    socket = socket_event()
    network = network_event()
    scope_value = scope(network)
    graph = evidence_graph([process, socket, network], scope_value)
    assert {"opened"}.issubset({edge.relation for edge in graph["edges"]})
    paths = analyze_paths([process, socket, network], scope_value, {network.event_id})
    assert paths.paths
    assert any(link.relation == "opened" for link in paths.links)
    assert not [
        gap for gap in paths.breakpoints if gap.reason == "missing_socket_binding" and gap.to_event_id == network.event_id
    ]
    broken = analyze_paths([process, network], scope_value, {network.event_id})
    assert [gap for gap in broken.breakpoints if gap.reason == "missing_socket_binding"]


def test_pid_reuse_boot_and_port_mismatch_do_not_link():
    process = process_event()
    reused = socket_event(ticks=101)
    reboot = socket_event(boot="boot-b")
    wrong_port = socket_event(local_port=50001)
    network = network_event()
    scope_value = scope(network)
    for socket in (reused, reboot, wrong_port):
        graph = evidence_graph([process, socket, network], scope_value)
        opened = [edge for edge in graph["edges"] if edge.relation == "opened"]
        if socket is wrong_port:
            assert not [
                edge for edge in opened if edge.target == "connection:" + network.event_id
            ]
        else:
            assert not [edge for edge in opened if edge.source == process.process.entity_id]


def test_weak_process_never_claims_ownership():
    raw = json.dumps(
        {
            "timestamp": "2026-11-14T01:00:10.600Z",
            "host": "host-a",
            "boot_id": "boot-a",
            "process": {"pid": 42, "identity_basis": "pid_only"},
            "socket": {
                "inode": "1",
                "state": "established",
                "role": "client",
                "transport": "tcp",
                "connected_at": "2026-11-14T01:00:10.500Z",
                "local_ip": "10.10.0.20",
                "local_port": 50000,
                "remote_ip": "192.0.2.10",
                "remote_port": 443,
            },
            "synthetic": True,
        }
    ).encode()
    weak = parse_record(raw, 1, parse_ctx("linux_socket", raw, "sock-a"))
    assert weak.process.entity_id is None and "identity_weak" in weak.quality_flags
    network = network_event()
    graph = evidence_graph([weak, network], scope(network))
    assert not [edge for edge in graph["edges"] if edge.relation == "opened"]