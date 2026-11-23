from pathlib import Path
from threading import Event, Thread

import pytest

from packages.storage.analysis import AnalysisService
from packages.storage.queue import LeaseLost, Queue
from packages.storage.service import Actor, DomainError
from packages.storage.worker import Worker
from tests.integration.test_d3_analysis import scan_bytes


def prepare(context):
    settings, db, service, workspace, tokens = context
    actor = service.authenticate(tokens["analyst"])
    admin = service.system_actor(workspace)
    dataset = service.create_dataset(admin, {"name": "safety", "provenance_type": "synthetic"}, "d")
    service.stage_bytes(admin, dataset["dataset_id"], "zeek", "s", "UTC", scan_bytes(), "u")
    service.process_one()
    analysis = AnalysisService(service)
    incident = analysis.list_incidents(actor, dataset["dataset_id"], dataset["default_session_id"])[
        0
    ]
    return actor, admin, incident, analysis


def test_cancel_fences_investigation_publication_and_other_analyst(context):
    settings, db, service, _, _ = context
    actor, admin, incident, analysis = prepare(context)
    run = analysis.create_run(actor, incident["id"], "run")
    queue = Queue(db, settings)
    lease = queue.claim("late-publisher")
    with pytest.raises(DomainError, match="FORBIDDEN"):
        queue.cancel(Actor(actor.workspace_id, "analyst", "different-actor"), run["job_id"])
    queue.cancel(actor, run["job_id"])
    with pytest.raises(LeaseLost):
        analysis.process(lease, queue)
    assert analysis.get_run(actor, run["run_id"])["report_id"] is None
    assert analysis.get_run(actor, run["run_id"])["state"] == "cancelled"


def test_report_integrity_downgrades_and_unknown_snapshot_cannot_retrieve(context):
    _, _, service, _, _ = context
    actor, _, incident, analysis = prepare(context)
    run = analysis.create_run(actor, incident["id"], "run")
    service.process_one()
    report_id = analysis.get_run(actor, run["run_id"])["report_id"]
    report = analysis.get_report(actor, report_id)
    assert report["validation"] == "passed"
    path = next(service.settings.raw_store.rglob("*.jsonl"))
    path.write_bytes(b"corrupted\n")
    assert analysis.get_report(actor, report_id)["validation"] == "partial"
    with pytest.raises(DomainError, match="INTEGRITY"):
        analysis.evidence(actor, report["timeline"][0], run["snapshot_id"])


def test_heartbeat_keeps_a_long_task_owned(context):
    settings, db, service, workspace, _ = context
    settings.worker_lease_seconds, settings.worker_heartbeat_seconds = 5, 1
    actor = service.system_actor(workspace)
    dataset = service.create_dataset(
        actor, {"name": "heartbeat", "provenance_type": "synthetic"}, "h"
    )
    service.stage_bytes(
        actor,
        dataset["dataset_id"],
        "zeek",
        "s",
        "UTC",
        Path("data/fixtures/d1/zeek.jsonl").read_bytes(),
        "u",
    )
    queue = Queue(db, settings)
    lease = queue.claim("alive")
    done = Event()
    thread = Thread(target=Worker(service, queue)._heartbeats, args=(lease, done), daemon=True)
    thread.start()
    try:
        done.wait(5.5)
        assert queue.claim("contender") is None
        assert queue.status(actor, lease.job_id)["state"] == "running"
    finally:
        done.set()
        thread.join(timeout=2)
        queue.cancel(actor, lease.job_id)
