"""Real read-only tools + local model protocol; zero paid-model acceptance claims."""

import json

import pytest

from packages.agent.executor import ToolExecutor
from packages.agent.executor import summary as event_summary
from packages.agent.model import CompatibleModel
from packages.agent.runtime import AgentRuntime
from packages.storage.analysis import AnalysisService
from packages.storage.queue import Queue
from packages.storage.service import DomainError
from tests.integration.d6_helpers import ModelStub
from tests.integration.d7_helpers import pending_d7
from tests.integration.test_p1_context import create_s1


def test_s1_strategy_executes_distinct_tools_and_retrieves_outside_seed(context):
    settings, _, service, _, _ = context
    with ModelStub("retrieval") as stub:
        stub.configure(settings)
        actor, analysis, incident = create_s1(context)
        run = analysis.create_run(actor, incident["id"], "retrieval-s1", "live")
        executor = ToolExecutor(service, actor, run["run_id"])
        seed = set(executor.membership["evidence_ids"])
        helper = next(
            e for e in executor.events if e.process and e.process.executable == "/lab/helper"
        )
        assert helper.event_id not in seed
        service.process_one()
    status = analysis.get_run(actor, run["run_id"])
    assert status["state"] == "completed", json.dumps(
        {
            "status": status,
            "contexts": [
                {
                    "phase": r["phase"],
                    "bytes": len(json.dumps(r["untrusted_context"]).encode()),
                    "facts": len(r["untrusted_context"]["facts"]),
                    "hints": r["untrusted_context"].get("retrieval"),
                }
                for r in stub.requests
            ],
        }
    )
    calls = analysis.tool_call_page(actor, run["run_id"])["items"]
    tools = [a for a in calls if a["kind"] == "tool"]
    assert {a["name"] for a in tools} == {"get_process_context", "get_asset_timeline"}
    assert sum(a["new_evidence_count"] for a in tools) >= 1
    report = analysis.get_report(actor, status["report_id"])
    comparison = report["investigation_analysis"]
    assert set(comparison["before"]["known_evidence_ids"]) == seed
    added = set(comparison["after"]["known_evidence_ids"]) - seed
    assert helper.event_id in added
    assert added <= {eid for action in tools for eid in action["evidence_ids"]}
    drafts = [r["untrusted_context"] for r in stub.requests if r["phase"] == "draft"]
    assert helper.event_id in {e["event_id"] for e in drafts[0]["facts"]}, json.dumps(
        {
            "available_input": 12000
            - sum(
                a["usage"]["input_tokens"]
                for a in calls
                if a["kind"] == "model" and a["name"] == "plan"
            ),
            "one_helper_bytes": len(
                CompatibleModel(settings).request(
                    "draft",
                    drafts[0]
                    | {"facts": [event_summary(helper)], "retrieved_event_ids": [helper.event_id]},
                    768,
                )
            ),
            "budget": status["budget_used"],
            "requests": [
                {
                    "phase": r["phase"],
                    "facts": len(r["untrusted_context"]["facts"]),
                    "bytes": len(json.dumps(r["untrusted_context"]).encode()),
                    "data_bytes": [
                        len(json.dumps(t["data"]).encode())
                        for t in r["untrusted_context"]["tool_results"]
                    ],
                }
                for r in stub.requests
            ],
        }
    )
    assert "retrieval" not in drafts[0]
    assert report["mode"] == "live" and report["validation"] == "passed"
    assert report["provenance"]["model_execution"] == "protocol_test_stub"
    assert status["budget_used"]["model_calls"] == 3
    assert status["budget_used"]["input_tokens"] <= 12000
    assert any(
        g["code"] == "process_socket_binding" and g["status"] == "unavailable"
        for g in comparison["after"]["gaps"]
    )
    assert "local-test-dummy" not in json.dumps(stub.requests)


def test_gap_strategy_finds_countercontext_with_two_tools_without_claiming_flow_ownership(context):
    settings, _, service, _, _ = context
    with ModelStub("retrieval") as stub:
        stub.configure(settings)
        actor, _, run, _ = pending_d7(context)
        service.process_one()
    analysis = AnalysisService(service)
    status = analysis.get_run(actor, run["run_id"])
    assert status["state"] == "completed", status
    calls = analysis.tool_call_page(actor, run["run_id"])["items"]
    assert {a["name"] for a in calls if a["kind"] == "tool"} == {
        "search_events",
        "get_process_context",
    }
    report = analysis.get_report(actor, status["report_id"])
    comparison = report["investigation_analysis"]
    assert {h["status"] for h in comparison["before"]["hypotheses"]} == {"open"}
    assert {h["status"] for h in comparison["after"]["hypotheses"]} == {"weakened"}
    assert all(
        h["counterevidence_kind"] == "context_only" for h in comparison["after"]["hypotheses"]
    )
    assert all(c["action_seq"] == 2 and c["evidence_refs"] for c in comparison["changes"])


def test_runtime_planning_hints_do_not_expose_unretrieved_snapshot_event(context):
    _, db, service, _, _ = context
    actor, analysis, incident = create_s1(context)
    analysis.create_run(actor, incident["id"], "hint-boundary", "deterministic")
    queue = Queue(db, context[0])
    runtime = AgentRuntime(service, queue, queue.claim("hint-boundary"))
    runtime.step()
    runtime.step()
    unseen = next(
        e for e in runtime.tools.events if e.process and e.process.executable == "/lab/helper"
    )
    plan = runtime.context()
    assert "retrieval" in plan
    assert unseen.event_id not in json.dumps(plan)
    assert unseen.process.entity_id not in json.dumps(plan)
    assert plan["retrieval"]["seed_count"] == 34
    assert plan["retrieval"]["new_evidence_count"] == 0


def test_plan_uses_facts_instead_of_duplicate_result_body_without_changing_stored_result(context):
    settings, db, service, _, _ = context
    with ModelStub("retrieval") as stub:
        stub.configure(settings)
        actor, analysis, incident = create_s1(context)
        analysis.create_run(actor, incident["id"], "plan-details", "live")
        queue = Queue(db, settings)
        runtime = AgentRuntime(service, queue, queue.claim("plan-details"))
        for _ in range(4):
            runtime.step()
        before = runtime.actions()[-1]["result_payload"]
        assert before["data"]["items"]
        plan = runtime.context("plan")
        assert plan["tool_results"][0]["data"] == "omitted_for_planning; see facts"
        assert runtime.actions()[-1]["result_payload"] == before
        assert (
            runtime.context("draft")["tool_results"][0]["data"] != plan["tool_results"][0]["data"]
        )


def test_discovery_pagination_keeps_original_query_and_counts_only_new_returned_events(context):
    settings, _, service, _, _ = context
    with ModelStub("retrieval_paged") as stub:
        stub.configure(settings)
        actor, _, run, _ = pending_d7(context)
        service.process_one()
    analysis = AnalysisService(service)
    status = analysis.get_run(actor, run["run_id"])
    assert status["state"] == "completed", status
    actions = analysis.tool_call_page(actor, run["run_id"])["items"]
    tools = [a for a in actions if a["kind"] == "tool"]
    assert [a["name"] for a in tools] == ["search_events", "search_events"]
    first, second = [a["args_payload"] for a in tools]
    assert first["cursor"] is None and second["cursor"]
    assert {k: v for k, v in first.items() if k != "cursor"} == {
        k: v for k, v in second.items() if k != "cursor"
    }
    assert first["limit"] == second["limit"] == 1
    assert tools[0]["evidence_ids"] != tools[1]["evidence_ids"]
    assert sum(a["new_evidence_count"] for a in tools) == 2
    assert status["query_stop_reason"] == "MAX_PLANNING_ROUNDS"


def test_cursor_from_a_different_run_is_rejected_even_for_the_same_query(context):
    _, _, service, _, _ = context
    actor, analysis, incident = create_s1(context)
    first = analysis.create_run(actor, incident["id"], "cursor-first", "deterministic")
    second = analysis.create_run(actor, incident["id"], "cursor-second", "deterministic")
    args = {"types": ["host.process"], "limit": 1}
    page = ToolExecutor(service, actor, first["run_id"]).call("search_events", args)
    assert page.next_cursor
    with pytest.raises(DomainError, match="CURSOR"):
        ToolExecutor(service, actor, second["run_id"]).call(
            "search_events",
            args | {"cursor": page.next_cursor},
        )


def test_resume_recomputes_hints_from_completed_results_without_repeating_changes(context):
    settings, db, service, _, _ = context
    with ModelStub("retrieval") as stub:
        stub.configure(settings)
        pending_d7(context)
        queue = Queue(db, settings)
        lease = queue.claim("retrieval-resume")
        runtime = AgentRuntime(service, queue, lease)
        for _ in range(4):
            runtime.step()
        before = runtime.payload["assessment_before"]
        changes = runtime.payload["assessment_changes"]
        assert len(changes) == 2
        resumed = AgentRuntime(service, queue, lease)
        result = resumed.run()
    assert result["terminal"] == "completed"
    assert result["assessment_before"] == before and result["assessment_changes"] == changes
    assert result["used"]["tool_calls"] == 2
    assert {a["name"] for a in resumed.actions() if a["kind"] == "tool"} == {
        "search_events",
        "get_process_context",
    }
