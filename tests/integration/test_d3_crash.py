import os
import subprocess
import sys
import time
from pathlib import Path

from packages.storage.queue import Queue
from packages.storage.worker import ImportRunner


def test_real_process_exit_then_real_lease_expiry_resumes_checkpoint(context):
    settings, db, service, workspace, _ = context
    settings.worker_lease_seconds = 5
    settings.worker_heartbeat_seconds = 1
    actor = service.system_actor(workspace)
    dataset = service.create_dataset(
        actor, {"name": "crash", "provenance_type": "synthetic"}, "crash"
    )
    line = Path("data/fixtures/d1/zeek.jsonl").read_bytes().splitlines()[0] + b"\n"
    batch = service.stage_bytes(actor, dataset["dataset_id"], "zeek", "s", "UTC", line * 1001, "u")
    env = os.environ.copy()
    env.update(
        DATABASE_URL=settings.database_url.get_secret_value(),
        RAW_STORE=str(settings.raw_store),
        STAGING_STORE=str(settings.staging_store),
        WORKER_LEASE_SECONDS="5",
        WORKER_HEARTBEAT_SECONDS="1",
    )
    code = """import os
from packages.config import Settings
from packages.storage.database import Database
from packages.storage.service import DataService
from packages.storage.queue import Queue
from packages.storage.worker import ImportRunner
s=Settings(_env_file=None); d=Database(s); q=Queue(d,s)
lease=q.claim('process-that-dies')
ImportRunner(DataService(d,s),q).step(lease)
os._exit(19)
"""
    result = subprocess.run([sys.executable, "-c", code], env=env, timeout=20, capture_output=True)
    assert result.returncode == 19, result.stderr.decode(errors="replace")
    queue = Queue(db, settings)
    assert queue.status(actor, batch["job_id"])["cursor_line"] == 500
    assert (
        service.list_events(actor, dataset["dataset_id"], dataset["default_session_id"], 1)["items"]
        == []
    )
    lease = None
    deadline = time.monotonic() + 8
    while lease is None and time.monotonic() < deadline:
        lease = queue.claim("surviving-process")
        if lease is None:
            time.sleep(0.05)
    assert lease is not None and lease.attempt == 2
    runner = ImportRunner(service, queue)
    while not runner.step(lease):
        pass
    final = service.get_batch(actor, batch["batch_id"])
    assert (final["accepted"], final["duplicate"], final["quarantined"]) == (1001, 0, 0)
