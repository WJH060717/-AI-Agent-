from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from packages.storage.queue import LeaseLost, Queue
from packages.storage.worker import ImportRunner, Worker


def upload(context, content=None):
    _, _, service, workspace, _ = context
    actor = service.system_actor(workspace)
    dataset = service.create_dataset(
        actor, {"name": "queue", "provenance_type": "synthetic"}, str(uuid4())
    )
    batch = service.stage_bytes(
        actor,
        dataset["dataset_id"],
        "zeek",
        "s",
        "UTC",
        content or Path("data/fixtures/d1/zeek.jsonl").read_bytes(),
        str(uuid4()),
    )
    return actor, dataset, batch


def test_lease_reclaim_fences_old_owner_and_heartbeat(context):
    settings, db, _, _, _ = context
    _, _, batch = upload(context)
    queue = Queue(db, settings)
    start = datetime.now(UTC)
    first = queue.claim("worker-a", at=start)
    assert first.job_id == batch["job_id"] and first.attempt == 1
    assert queue.claim("worker-b", at=start + timedelta(seconds=59)) is None
    second = queue.claim("worker-b", at=start + timedelta(seconds=61))
    assert second.attempt == 2 and second.version > first.version
    with pytest.raises(LeaseLost):
        queue.heartbeat(first, at=start + timedelta(seconds=62))
    queue.heartbeat(second, at=start + timedelta(seconds=62))


def test_expired_final_attempt_is_terminal_not_fourth_attempt(context):
    settings, db, service, _, _ = context
    actor, _, batch = upload(context)
    queue = Queue(db, settings)
    start = datetime.now(UTC)
    for n in range(3):
        lease = queue.claim(f"w{n}", at=start + timedelta(seconds=61 * n))
        assert lease.attempt == n + 1
    assert queue.claim("w4", at=start + timedelta(seconds=184)) is None
    assert queue.status(actor, batch["job_id"])["state"] == "failed"
    assert service.get_batch(actor, batch["batch_id"])["status"] == "failed"


def test_checkpoint_resume_publishes_only_complete_batch(context):
    settings, db, service, _, _ = context
    line = Path("data/fixtures/d1/zeek.jsonl").read_bytes().splitlines()[0] + b"\n"
    actor, dataset, batch = upload(context, line * 1001)
    queue = Queue(db, settings)
    first = queue.claim("before-crash")
    runner = ImportRunner(service, queue)
    assert runner.step(first) is False
    assert queue.status(actor, batch["job_id"])["cursor_line"] == 500
    assert (
        service.list_events(actor, dataset["dataset_id"], dataset["default_session_id"], 1)["items"]
        == []
    )
    # The abandoned process is replaced after lease expiry; committed checkpoint survives.
    later = datetime.now(UTC) + timedelta(seconds=61)
    second = queue.claim("after-crash", at=later)
    with pytest.raises(LeaseLost):
        runner.step(first)
    while not runner.step(second):
        pass
    result = service.get_batch(actor, batch["batch_id"])
    assert (result["accepted"], result["duplicate"], result["quarantined"]) == (1001, 0, 0)


def test_retry_backoff_cancellation_and_continuous_consume(context):
    settings, db, service, _, _ = context
    actor, _, batch = upload(context)
    queue = Queue(db, settings)
    start = datetime.now(UTC)
    lease = queue.claim("w", at=start)
    queue.fail(lease, "TRANSIENT_IO", retryable=True, at=start)
    assert queue.claim("too-soon", at=start + timedelta(seconds=1)) is None
    retry = queue.claim("retry", at=start + timedelta(seconds=4))
    assert retry.attempt == 2
    queue.cancel(actor, retry.job_id)
    with pytest.raises(LeaseLost):
        ImportRunner(service, queue).step(retry)
    assert queue.status(actor, retry.job_id)["state"] == "cancelled"
    # The continuous worker has a bounded run mode for CLI/batch environments as well.
    actor2, _, batch2 = upload((settings, db, service, actor.workspace_id, {}))
    Worker(service, queue).run(max_jobs=1)
    assert queue.status(actor2, batch2["job_id"])["state"] == "succeeded"
