import json
import threading

import pytest
from sqlalchemy import select

from packages.contracts.models import AgentBudget
from packages.storage.analysis import AnalysisService
from packages.storage.queue import Queue
from tests.integration.d6_helpers import ModelStub, pending


def test_agent_uses_two_real_tools_and_persists_phases_usage_and_new_evidence(context):
    settings, db, service, _, _ = context
    with ModelStub() as stub:
        stub.configure(settings)
        actor, _, run = pending(context)
        service.process_one()
    analysis = AnalysisService(service)
    state = analysis.get_run(actor, run["run_id"])
    assert state["state"] == "completed", state
    assert state["phase"] == "completed" and state["state_version"] > 5
    assert state["budget_used"]["model_calls"] == 3
    assert state["budget_used"]["tool_calls"] == 2
    assert state["retrieved_count"] == 2
    calls = analysis.tool_call_page(actor, run["run_id"])["items"]
    assert {call["name"] for call in calls if call["kind"] == "tool"} == {
        "search_events",
        "get_event_evidence",
    }
    assert any(call["new_evidence_count"] == 2 for call in calls)
    report = analysis.get_report(actor, state["report_id"])
    assert (
        report["mode"] == "live" and report["provenance"]["model_execution"] == "protocol_test_stub"
    )
    assert "local-test-dummy" not in json.dumps(stub.requests) + json.dumps(calls) + json.dumps(
        report
    )


@pytest.mark.parametrize(
    "behavior,reason",
    [
        ("invalid", "INVALID_MODEL"),
        ("unknown", "TOOL_NOT_ALLOWED"),
        ("wrong_fact", "DRAFT_VALIDATION"),
        ("slow", "TIMEOUT"),
    ],
)
def test_model_or_policy_failure_is_partial_fallback_not_fake_live(context, behavior, reason):
    settings, _, service, _, _ = context
    with ModelStub(behavior) as stub:
        stub.configure(settings)
        if behavior == "slow":
            settings.model_timeout_seconds = 0.05
        actor, _, run = pending(context)
        service.process_one()
    analysis = AnalysisService(service)
    state = analysis.get_run(actor, run["run_id"])
    assert state["state"] == "partial", state
    report = analysis.get_report(actor, state["report_id"])
    assert report["mode"] == "deterministic_fallback"
    assert reason in " ".join(report["gaps"])
    assert state["budget_used"]["model_calls"] <= 4
    if behavior == "unknown":
        assert state["budget_used"]["tool_calls"] == 1
        from packages.storage import schema_v5 as t

        with service.db.engine.connect() as conn:
            payload = conn.execute(
                select(t.agent_states.c.payload).where(t.agent_states.c.id == run["run_id"])
            ).scalar_one()
            actions = (
                conn.execute(
                    select(t.agent_actions.c.result_payload).where(
                        t.agent_actions.c.run_id == run["run_id"]
                    )
                )
                .scalars()
                .all()
            )
        assert "dump token" not in json.dumps(payload) + json.dumps(actions)


def test_complete_tool_result_is_reused_within_same_snapshot(context):
    settings, _, service, _, _ = context
    with ModelStub("repeat") as stub:
        stub.configure(settings)
        actor, _, run = pending(context)
        service.process_one()
    state = AnalysisService(service).get_run(actor, run["run_id"])
    assert state["state"] == "completed" and state["budget_used"]["tool_calls"] == 1
    assert state["cache_hits"] == 1 and len(stub.requests) == 3


def test_budget_zero_prevents_external_call_and_repeat_tool_is_cached(context):
    settings, _, service, _, _ = context
    with ModelStub("repeat") as stub:
        stub.configure(settings)
        actor, _, run = pending(context, budget=AgentBudget(max_model_calls=0))
        service.process_one()
        assert stub.requests == []
    state = AnalysisService(service).get_run(actor, run["run_id"])
    assert state["state"] == "partial" and state["budget_used"]["model_calls"] == 0


def test_cancelled_model_late_response_cannot_publish_report(context):
    settings, _, service, _, _ = context
    with ModelStub("slow") as stub:
        stub.configure(settings)
        actor, _, run = pending(context)
        errors = []

        def work():
            try:
                service.process_one()
            except Exception as exc:
                errors.append(type(exc).__name__)

        worker = threading.Thread(target=work)
        worker.start()
        assert stub.entered.wait(5)
        Queue(service.db, settings).cancel(actor, run["job_id"])
        worker.join(timeout=5)
        assert not worker.is_alive()
    state = AnalysisService(service).get_run(actor, run["run_id"])
    assert state["state"] == state["phase"] == "cancelled" and state["report_id"] is None


def test_interrupted_reserved_tool_keeps_budget_and_resumes_from_checkpoint(context):
    from datetime import UTC, datetime, timedelta

    from packages.agent.runtime import AgentRuntime
    from packages.storage import schema_v5 as t

    settings, db, service, _, _ = context
    with ModelStub() as stub:
        stub.configure(settings)
        actor, _, run = pending(context)
        queue = Queue(db, settings)
        first = queue.claim("before-restart")
        runtime = AgentRuntime(service, queue, first)
        assert not runtime.step()  # queued -> preparing
        assert not runtime.step()  # preparing -> planning
        assert not runtime.step()  # model planned -> querying
        decision = runtime.payload["pending_tool"]
        seq, _ = runtime.reserve("tool", decision["tool"], decision["arguments"])
        resumed = queue.claim("after-restart", at=datetime.now(UTC) + timedelta(seconds=61))
        from packages.storage.analysis import AnalysisService

        AnalysisService(service).process(resumed, queue)
    state = AnalysisService(service).get_run(actor, run["run_id"])
    assert state["state"] == "completed" and state["budget_used"]["tool_calls"] == 3
    with db.engine.connect() as conn:
        row = (
            conn.execute(
                select(t.agent_actions).where(
                    t.agent_actions.c.workspace_id == actor.workspace_id,
                    t.agent_actions.c.run_id == run["run_id"],
                    t.agent_actions.c.seq == seq,
                )
            )
            .mappings()
            .one()
        )
    assert row["status"] == "abandoned"


def test_expired_wallclock_cannot_complete_a_stale_validation_checkpoint(context):
    from datetime import UTC, datetime, timedelta

    from packages.agent.runtime import AgentRuntime
    from packages.storage import schema_v5 as t

    settings, db, service, _, _ = context
    actor, _, run = pending(context, mode="deterministic")
    queue = Queue(db, settings)
    lease = queue.claim("deadline")
    runtime = AgentRuntime(service, queue, lease)
    for _ in range(3):
        runtime.step()
    assert runtime.phase == "validating"
    payload = runtime.payload
    payload["started_at"] = (datetime.now(UTC) - timedelta(seconds=91)).isoformat()
    with db.engine.begin() as conn:
        conn.execute(
            t.agent_states.update()
            .where(
                t.agent_states.c.workspace_id == actor.workspace_id,
                t.agent_states.c.id == run["run_id"],
            )
            .values(payload=payload)
        )
    outcome = runtime.run()
    assert outcome["terminal"] == "partial" and "WALLCLOCK" in outcome["stop_reason"]


@pytest.mark.parametrize(
    "budget",
    [
        AgentBudget(max_input_tokens=1),
        AgentBudget(max_output_tokens=0),
        AgentBudget(max_tool_calls=0),
    ],
)
def test_remaining_budget_blocks_calls_before_execution(context, budget):
    settings, _, service, _, _ = context
    with ModelStub() as stub:
        stub.configure(settings)
        actor, _, run = pending(context, budget=budget)
        service.process_one()
    state = AnalysisService(service).get_run(actor, run["run_id"])
    assert state["state"] == "partial"
    assert state["budget_used"]["tool_calls"] == 0
    if budget.max_tool_calls != 0:
        assert stub.requests == []


def test_real_worker_exit_after_model_reservation_preserves_budget(context):
    import os
    import subprocess
    import sys
    import time
    from pathlib import Path

    settings, _, service, _, _ = context
    settings.worker_lease_seconds = 5
    settings.worker_heartbeat_seconds = 1
    with ModelStub() as stub:
        stub.configure(settings)
        actor, _, run = pending(context)
        env = os.environ.copy()
        env.update(
            DATABASE_URL=settings.database_url.get_secret_value(),
            RAW_STORE=str(settings.raw_store),
            STAGING_STORE=str(settings.staging_store),
            APP_ENV="test",
            WORKER_LEASE_SECONDS="5",
            WORKER_HEARTBEAT_SECONDS="1",
            MODEL_PROVIDER="compatible",
            MODEL_BASE_URL=settings.model_base_url,
            MODEL_NAME=settings.model_name,
            MODEL_API_KEY="local-test-dummy",
            MODEL_TEST_STUB="true",
        )
        code = """import os
from packages.config import Settings
from packages.storage.database import Database
from packages.storage.service import DataService
from packages.agent.runtime import AgentRuntime
AgentRuntime.bounded = lambda *args, **kwargs: os._exit(29)
settings = Settings()
DataService(Database(settings), settings).process_one()
"""
        result = subprocess.run(
            [sys.executable, "-c", code],
            cwd=Path(__file__).resolve().parents[2],
            env=env,
            capture_output=True,
            timeout=15,
        )
        assert result.returncode == 29
        state = AnalysisService(service).get_run(actor, run["run_id"])
        assert state["budget_used"]["model_calls"] == 1 and state["budget_used"]["input_tokens"] > 0
        charged = state["budget_used"]["input_tokens"]
        time.sleep(5.2)
        service.process_one()
    state = AnalysisService(service).get_run(actor, run["run_id"])
    assert state["state"] == "partial"
    assert (
        state["budget_used"]["input_tokens"] >= charged and state["budget_used"]["model_calls"] <= 4
    )
