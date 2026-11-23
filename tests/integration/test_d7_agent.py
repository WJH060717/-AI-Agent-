import json

import pytest
from sqlalchemy import select

from packages.agent import evidence_state
from packages.agent.runtime import AgentRuntime
from packages.contracts.models import AgentBudget
from packages.storage import schema_v5 as t
from packages.storage.analysis import AnalysisService
from packages.storage.queue import Queue
from scripts.build_d4_fixture import START
from tests.integration.d6_helpers import ModelStub
from tests.integration.d7_helpers import pending_d7


def test_tools_change_analysis_with_cited_normal_countercontext_and_explicit_loop_stop(context):
    settings, db, service, _, _ = context
    with ModelStub("d7") as stub:
        stub.configure(settings)
        actor, dataset, run, _ = pending_d7(context)
        service.process_one()
    analysis = AnalysisService(service)
    status = analysis.get_run(actor, run["run_id"])
    assert status["state"] == "completed", status
    assert status["query_stop_reason"] == "ACTIONABLE_GAPS_RESOLVED"
    report = analysis.get_report(actor, status["report_id"])
    comparison = report["investigation_analysis"]
    assert {h["status"] for h in comparison["before"]["hypotheses"]} == {"open"}
    assert {h["status"] for h in comparison["after"]["hypotheses"]} == {"weakened"}
    assert len(comparison["changes"]) == 2
    assert all(c["action_seq"] == 2 and c["evidence_refs"] for c in comparison["changes"])
    assert all(
        h["counterevidence_kind"] == "context_only" for h in comparison["after"]["hypotheses"]
    )
    assert any(
        g["code"] == "process_socket_binding" and g["status"] == "unavailable"
        for g in comparison["after"]["gaps"]
    )
    assert status["budget_used"]["model_calls"] == 3 and status["budget_used"]["tool_calls"] == 2
    assert stub.requests[0]["untrusted_context"]["investigation"]["gaps"]
    assert "local-test-dummy" not in json.dumps(comparison)
    with db.engine.connect() as conn:
        payload = conn.execute(
            select(t.agent_states.c.payload).where(t.agent_states.c.id == run["run_id"])
        ).scalar_one()
    assert payload["assessment_before"] == comparison["before"]
    # Late imports cannot silently rewrite this run's comparison or evidence set.
    service.stage_bytes(
        actor,
        dataset["dataset_id"],
        "zeek",
        "net-a",
        "UTC",
        (
            json.dumps(
                {
                    "ts": START.timestamp() + 900,
                    "uid": "late-context",
                    "id.orig_h": "10.10.0.20",
                    "id.orig_p": 50000,
                    "id.resp_h": "198.51.100.33",
                    "id.resp_p": 80,
                    "proto": "tcp",
                }
            )
            + "\n"
        ).encode(),
        "late",
    )
    service.process_one()
    assert analysis.get_report(actor, status["report_id"])["investigation_analysis"] == comparison


@pytest.mark.parametrize(
    "behavior,expected",
    [
        ("empty", "NO_NEW_EVIDENCE"),
        ("draft", "MODEL_REQUESTED_DRAFT"),
        ("repeat", "MAX_PLANNING_ROUNDS"),
    ],
)
def test_loop_terminates_without_inventing_queries_or_evidence(context, behavior, expected):
    settings, _, service, _, _ = context
    with ModelStub(behavior) as stub:
        stub.configure(settings)
        actor, _, run, _ = pending_d7(context)
        service.process_one()
    analysis = AnalysisService(service)
    status = analysis.get_run(actor, run["run_id"])
    assert status["state"] == "completed", status
    assert status["query_stop_reason"] == expected
    assert status["budget_used"]["model_calls"] <= 3 and status["budget_used"]["tool_calls"] <= 2
    comparison = analysis.get_report(actor, status["report_id"])["investigation_analysis"]
    if behavior in {"empty", "draft"}:
        assert comparison["changes"] == [] and comparison["before"] == comparison["after"]


def test_budget_failure_keeps_before_after_and_does_not_claim_successful_supplement(context):
    settings, _, service, _, _ = context
    with ModelStub("d7") as stub:
        stub.configure(settings)
        actor, _, run, _ = pending_d7(context, AgentBudget(max_tool_calls=0))
        service.process_one()
    analysis = AnalysisService(service)
    status = analysis.get_run(actor, run["run_id"])
    assert status["state"] == "partial" and status["budget_used"]["tool_calls"] == 0
    comparison = analysis.get_report(actor, status["report_id"])["investigation_analysis"]
    assert comparison["before"] == comparison["after"] and comparison["changes"] == []
    assert comparison["stop_reason"] == "TOOL_CALL_BUDGET_EXHAUSTED"


def test_resume_keeps_before_and_frozen_policy_without_duplicate_changes(context, monkeypatch):
    settings, db, service, _, _ = context
    with ModelStub("d7") as stub:
        stub.configure(settings)
        actor, _, run, _ = pending_d7(context)
        queue = Queue(db, settings)
        lease = queue.claim("d7-checkpoint")
        runtime = AgentRuntime(service, queue, lease)
        monkeypatch.setattr(
            evidence_state,
            "policy",
            lambda: (_ for _ in ()).throw(AssertionError("must use frozen policy")),
        )
        for _ in range(5):
            runtime.step()
        before = runtime.payload["assessment_before"]
        assert len(runtime.payload["assessment_changes"]) == 2
        outcome = AgentRuntime(service, queue, lease).run()
        assert outcome["assessment_before"] == before
        assert len(outcome["assessment_changes"]) == 2 and outcome["used"]["tool_calls"] == 2
