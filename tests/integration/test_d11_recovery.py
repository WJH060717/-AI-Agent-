import json
import os
import subprocess
import sys
import time

from sqlalchemy import select

from packages.storage import schema_v6 as t
from packages.storage.analysis import AnalysisService
from packages.storage.queue import Queue
from tests.integration.d6_helpers import ModelStub
from tests.integration.d7_helpers import pending_d7


def test_real_agent_process_exit_preserves_before_reservation_and_single_report(context):
    settings, db, service, workspace, _ = context
    settings.worker_lease_seconds = 5
    settings.worker_heartbeat_seconds = 1
    with ModelStub() as stub:
        stub.configure(settings)
        actor, _, run, _ = pending_d7(context)
        env = os.environ.copy()
        env.update(
            DATABASE_URL=settings.database_url.get_secret_value(),
            RAW_STORE=str(settings.raw_store),
            STAGING_STORE=str(settings.staging_store),
            APP_ENV="test",
            MODEL_PROVIDER="compatible",
            MODEL_BASE_URL=settings.model_base_url,
            MODEL_NAME=settings.model_name,
            MODEL_API_KEY="local-test-dummy",
            MODEL_TEST_STUB="true",
            WORKER_LEASE_SECONDS="5",
            WORKER_HEARTBEAT_SECONDS="1",
        )
        code = """import os
from packages.config import Settings
from packages.storage.database import Database
from packages.storage.service import DataService
from packages.storage.queue import Queue
from packages.agent.runtime import AgentRuntime
s=Settings(_env_file=None); d=Database(s); q=Queue(d,s)
lease=q.claim('d11-crash-child'); runtime=AgentRuntime(DataService(d,s),q,lease)
for _ in range(4): runtime.step()
runtime.reserve('model','draft',{'phase':'draft'},input_tokens=10,output_tokens=10,wait_ms=1)
os._exit(23)
"""
        child = subprocess.run(
            [sys.executable, "-c", code],
            env=env,
            timeout=30,
            capture_output=True,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        assert child.returncode == 23, child.stderr.decode(errors="replace")
        with db.engine.connect() as conn:
            initial = conn.execute(
                select(t.agent_states.c.payload).where(
                    t.agent_states.c.workspace_id == workspace, t.agent_states.c.id == run["run_id"]
                )
            ).scalar_one()
        before = json.loads(json.dumps(initial["assessment_before"]))
        assert before is not None and initial["pending_action"] is not None
        queue = Queue(db, settings)
        lease = None
        deadline = time.monotonic() + 8
        while lease is None and time.monotonic() < deadline:
            lease = queue.claim("d11-recovery")
            if lease is None:
                time.sleep(0.05)
        assert lease is not None and lease.job_id == run["job_id"] and lease.attempt == 2
        AnalysisService(service).process(lease, queue)
        with db.engine.connect() as conn:
            final = conn.execute(
                select(t.agent_states.c.payload).where(
                    t.agent_states.c.workspace_id == workspace, t.agent_states.c.id == run["run_id"]
                )
            ).scalar_one()
            actions = (
                conn.execute(
                    select(t.agent_actions).where(
                        t.agent_actions.c.workspace_id == workspace,
                        t.agent_actions.c.run_id == run["run_id"],
                    )
                )
                .mappings()
                .all()
            )
            reports = (
                conn.execute(
                    select(t.reports.c.id).where(
                        t.reports.c.workspace_id == workspace, t.reports.c.run_id == run["run_id"]
                    )
                )
                .scalars()
                .all()
            )
        assert final["assessment_before"] == before
        assert final["used"]["model_calls"] >= initial["used"]["model_calls"]
        assert final["used"]["input_tokens"] >= 10
        abandoned = [a for a in actions if a["seq"] == initial["pending_action"]]
        assert len(abandoned) == 1 and abandoned[0]["status"] == "abandoned"
        assert abandoned[0]["error_code"] == "INTERRUPTED_CALL_REMAINS_CHARGED"
        assert len({a["seq"] for a in actions}) == len(actions) and len(reports) == 1
        state = AnalysisService(service).get_run(actor, run["run_id"])
        assert state["state"] in {"completed", "partial"}
