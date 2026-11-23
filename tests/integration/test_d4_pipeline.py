import asyncio
import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import select

from apps.api.main import create_app
from packages.contracts.context import DatasetContext
from packages.storage import schema_v3 as t
from packages.storage.analysis import AnalysisService
from packages.storage.context import ContextService
from packages.storage.queue import Queue
from packages.storage.service import DomainError
from packages.storage.worker import ImportRunner
from tests.integration.d4_helpers import audit_record, auth_record, context_payload, raw_lines


def setup(context):
    settings, db, service, workspace, tokens = context
    actor = service.system_actor(workspace)
    dataset = service.create_dataset(
        actor, {"name": "host", "provenance_type": "synthetic"}, "dataset"
    )
    ContextService(service).configure(
        actor, dataset["dataset_id"], DatasetContext.model_validate(context_payload()), "ctx"
    )
    return actor, dataset


def test_auth_audit_r02_report_and_private_fields_are_scoped(context):
    settings, db, service, workspace, tokens = context
    actor, dataset = setup(context)
    auth = raw_lines([auth_record(i) for i in range(5)] + [auth_record(10, "success")])
    service.stage_bytes(actor, dataset["dataset_id"], "linux_auth", "auth-a", "UTC", auth, "auth")
    service.process_one()
    audit = raw_lines(
        [
            audit_record(kind, timestamp="2026-11-14T01:00:20Z")
            for kind in ("SYSCALL", "EXECVE", "EOE")
        ]
    )
    batch = service.stage_bytes(
        actor, dataset["dataset_id"], "linux_audit", "audit-a", "UTC", audit, "audit"
    )
    service.process_one()
    counts = service.get_batch(actor, batch["batch_id"])
    assert (counts["raw_records"], counts["aggregated_records"], counts["accepted"]) == (3, 3, 1)
    analysis = AnalysisService(service)
    incidents = analysis.list_incidents(actor, dataset["dataset_id"], dataset["default_session_id"])
    assert len(incidents) == 1 and incidents[0]["title"].startswith("R02")
    run = analysis.create_run(actor, incidents[0]["id"], "run")
    service.process_one()
    state = analysis.get_run(actor, run["run_id"])
    assert state["state"] == "completed"
    report = analysis.get_report(actor, state["report_id"])
    assert "R02" in report["summary"] and "alice" not in json.dumps(report)
    graph = analysis.get_graph(actor, run["run_id"])
    assert {"authenticated", "associated_process"}.issubset(
        {edge["relation"] for edge in graph["edges"]}
    )
    assert "spawned" not in {edge["relation"] for edge in graph["edges"]}
    event = next(
        e
        for e in service.list_events(
            actor, dataset["dataset_id"], dataset["default_session_id"], 100
        )["items"]
        if e["event_type"] == "host.process"
    )
    projection = analysis.evidence(actor, event["event_id"], run["snapshot_id"])
    assert len(projection["fragments"]) == 3 and "alice" not in json.dumps(projection)
    before = service.list_events(actor, dataset["dataset_id"], dataset["default_session_id"], 100)
    service.stage_bytes(
        actor, dataset["dataset_id"], "linux_audit", "audit-a", "UTC", audit, "audit-again"
    )
    service.process_one()
    assert (
        service.list_events(actor, dataset["dataset_id"], dataset["default_session_id"], 100)
        == before
    )


def test_audit_pending_locations_survive_lease_reclaim(context):
    settings, db, service, _, _ = context
    actor, dataset = setup(context)
    records = (
        [audit_record("SYSCALL")]
        + [{"not": "audit"}] * 499
        + [audit_record("EXECVE"), audit_record("EOE")]
    )
    batch = service.stage_bytes(
        actor, dataset["dataset_id"], "linux_audit", "audit-a", "UTC", raw_lines(records), "u"
    )
    queue = Queue(db, settings)
    lease = queue.claim("before")
    assert ImportRunner(service, queue).step(lease) is False
    with db.engine.connect() as conn:
        checkpoint = conn.execute(
            select(t.jobs.c.checkpoint).where(t.jobs.c.id == lease.job_id)
        ).scalar_one()
    assert "alice" not in json.dumps(checkpoint) and "process" not in json.dumps(checkpoint)
    assert service.get_batch(actor, batch["batch_id"])["accepted"] == 0
    resumed = queue.claim("after", at=datetime.now(UTC) + timedelta(seconds=61))
    assert ImportRunner(service, queue).step(resumed) is True
    counts = service.get_batch(actor, batch["batch_id"])
    assert (
        counts["raw_records"],
        counts["aggregated_records"],
        counts["quarantined"],
        counts["accepted"],
    ) == (502, 3, 499, 1)
    event = service.list_events(actor, dataset["dataset_id"], dataset["default_session_id"], 10)[
        "items"
    ][0]
    assert [ref["record_start"] for ref in event["source_locators"]] == [1, 501, 502]


def test_audit_evidence_pages_and_partial_eof(context):
    _, _, service, _, _ = context
    actor, dataset = setup(context)
    service.stage_bytes(
        actor,
        dataset["dataset_id"],
        "linux_auth",
        "auth-a",
        "UTC",
        raw_lines([auth_record(i) for i in range(5)] + [auth_record(10, "success")]),
        "auth",
    )
    service.process_one()
    parts = [audit_record("SYSCALL")] + [audit_record("PATH")] * 21
    batch = service.stage_bytes(
        actor, dataset["dataset_id"], "linux_audit", "audit-a", "UTC", raw_lines(parts), "audit"
    )
    service.process_one()
    assert service.get_batch(actor, batch["batch_id"])["status"] == "partial"
    analysis = AnalysisService(service)
    incident = analysis.list_incidents(actor, dataset["dataset_id"], dataset["default_session_id"])[
        0
    ]
    run = analysis.create_run(actor, incident["id"], "r")
    service.process_one()
    event = next(
        e
        for e in service.list_events(
            actor, dataset["dataset_id"], dataset["default_session_id"], 100
        )["items"]
        if e["event_type"] == "host.process"
    )
    assert event["process"]["entity_id"] is None
    first = analysis.evidence(actor, event["event_id"], run["snapshot_id"])
    assert sum(len(f["lines"]) for f in first["fragments"]) == 20
    assert first["next_cursor"]
    second = analysis.evidence(actor, event["event_id"], run["snapshot_id"], first["next_cursor"])
    assert [line["line"] for f in second["fragments"] for line in f["lines"]] == [21, 22]
    assert second["next_cursor"] is None
    with pytest.raises(DomainError, match="CURSOR"):
        analysis.evidence(actor, event["event_id"], run["snapshot_id"], first["next_cursor"] + "x")


def test_context_is_immutable_and_host_import_requires_profile(context):
    settings, db, service, workspace, tokens = context
    actor = service.system_actor(workspace)
    dataset = service.create_dataset(actor, {"name": "ctx", "provenance_type": "synthetic"}, "d")
    with pytest.raises(DomainError, match="LINUX_CONTEXT_REQUIRED"):
        service.stage_bytes(
            actor,
            dataset["dataset_id"],
            "linux_auth",
            "auth-a",
            "UTC",
            raw_lines([auth_record()]),
            "u",
        )
    metadata = context_payload()
    contexts = ContextService(service)
    first = contexts.configure(
        actor, dataset["dataset_id"], DatasetContext.model_validate(metadata), "c"
    )
    assert (
        contexts.configure(
            actor, dataset["dataset_id"], DatasetContext.model_validate(metadata), "c"
        )
        == first
    )
    metadata["sensors"][0]["offset_ms"] = 1000
    with pytest.raises(DomainError, match="IMMUTABLE"):
        contexts.configure(
            actor, dataset["dataset_id"], DatasetContext.model_validate(metadata), "c2"
        )

    async def scenario():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_app(settings)), base_url="http://test"
        ) as client:
            response = await client.post(
                f"/api/v1/datasets/{dataset['dataset_id']}/context",
                json=context_payload(),
                headers={
                    "Authorization": f"Bearer {tokens['viewer']}",
                    "Idempotency-Key": "viewer",
                },
            )
            assert response.status_code == 403

    asyncio.run(scenario())


def test_complete_non_exec_audit_groups_release_pending_capacity(context):
    _, _, service, _, _ = context
    actor, dataset = setup(context)
    records = []
    for i in range(257):
        call = audit_record("SYSCALL", str(i))
        call["process"]["action"] = "create"
        call["process"]["pid"] = 1000 + i
        records.extend([call, audit_record("EOE", str(i))])
    batch = service.stage_bytes(
        actor, dataset["dataset_id"], "linux_audit", "audit-a", "UTC", raw_lines(records), "create"
    )
    service.process_one()
    counts = service.get_batch(actor, batch["batch_id"])
    assert (counts["accepted"], counts["quarantined"], counts["aggregated_records"]) == (
        257,
        0,
        514,
    )
    assert counts["status"] == "succeeded"


def test_native_audit_identity_collision_is_quarantined_not_counted_duplicate(context):
    _, db, service, _, _ = context
    actor, dataset = setup(context)
    first = [audit_record(kind) for kind in ("SYSCALL", "EXECVE", "EOE")]
    second = [audit_record(kind) for kind in ("SYSCALL", "EXECVE", "EOE")]
    second[0]["process"]["pid"] = 999
    batch = service.stage_bytes(
        actor,
        dataset["dataset_id"],
        "linux_audit",
        "audit-a",
        "UTC",
        raw_lines(first + second),
        "conflict",
    )
    service.process_one()
    counts = service.get_batch(actor, batch["batch_id"])
    assert (counts["accepted"], counts["duplicate"], counts["quarantined"]) == (1, 0, 3)
    assert counts["raw_records"] == counts["aggregated_records"] + counts["quarantined"] == 6
    assert counts["status"] == "partial"
    with db.engine.connect() as conn:
        conflicts = (
            conn.execute(
                select(t.quarantine).where(
                    t.quarantine.c.workspace_id == actor.workspace_id,
                    t.quarantine.c.batch_id == batch["batch_id"],
                )
            )
            .mappings()
            .all()
        )
    assert {row["line"] for row in conflicts} == {4, 5, 6}
    assert {row["error_code"] for row in conflicts} == {"NATIVE_ID_CONTENT_CONFLICT"}
    event = service.list_events(actor, dataset["dataset_id"], dataset["default_session_id"], 10)[
        "items"
    ][0]
    assert event["process"]["pid"] == 42
    assert [ref["record_start"] for ref in event["source_locators"]] == [1, 2, 3]
