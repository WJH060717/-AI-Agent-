"""Large S1 context, honest protocol stub usage; not a formal or real-LLM result."""

import json
from pathlib import Path

from packages.contracts.context import DatasetContext
from packages.contracts.models import AgentBudget
from packages.storage.analysis import AnalysisService
from packages.storage.context import ContextService
from tests.integration.d6_helpers import ModelStub


def create_s1(context):
    settings, _, service, workspace, _ = context
    actor = service.system_actor(workspace)
    source = Path(__file__).resolve().parents[2] / "data/fixtures/d9/S1"
    dataset = service.create_dataset(
        actor, {"name": "context-s1", "provenance_type": "synthetic"}, "context-s1"
    )
    ContextService(service).configure(
        actor,
        dataset["dataset_id"],
        DatasetContext.model_validate_json((source / "context.json").read_bytes()),
        "context-s1-context",
    )
    for filename, kind, sensor in [
        ("network", "zeek", "net-a"),
        ("auth_a", "linux_auth", "auth-a"),
        ("audit", "linux_audit", "audit-a"),
        ("auth_b", "linux_auth", "auth-b"),
        ("alerts", "suricata", "alert-a"),
    ]:
        service.stage_bytes(
            actor,
            dataset["dataset_id"],
            kind,
            sensor,
            "UTC",
            (source / (filename + ".jsonl")).read_bytes(),
            filename,
        )
        service.process_one()
    analysis = AnalysisService(service)
    items = analysis.incident_page(actor, dataset["dataset_id"], dataset["default_session_id"])[
        "items"
    ]
    incident = next(i for i in items if len(analysis.get_incident(actor, i["id"])["findings"]) > 1)
    return actor, analysis, incident


def test_s1_larger_usage_completes_two_tools_and_live_stub_report_with_same_limits(context):
    settings, _, service, _, _ = context
    with ModelStub("context_load") as stub:
        stub.configure(settings)
        actor, analysis, incident = create_s1(context)
        run = analysis.create_run(actor, incident["id"], "context-load-run", "live", AgentBudget())
        service.process_one()
    status = analysis.get_run(actor, run["run_id"])
    assert status["state"] == "completed", json.dumps(
        {
            "status": status,
            "requests": [
                {
                    "phase": r["phase"],
                    "facts": len(r["untrusted_context"]["facts"]),
                    "context_bytes": len(json.dumps(r["untrusted_context"]).encode()),
                }
                for r in stub.requests
            ],
        }
    )
    assert status["budget_used"]["model_calls"] == 3
    assert status["budget_used"]["tool_calls"] == 2
    assert status["budget_used"]["input_tokens"] > 4000
    assert status["budget_used"]["input_tokens"] <= 12000
    assert [x["phase"] for x in stub.requests] == ["plan", "plan", "draft"]
    assert all(
        x["untrusted_context"]["scope"]["snapshot_id"] == run["snapshot_id"] for x in stub.requests
    )
    report = analysis.get_report(actor, status["report_id"])
    assert report["mode"] == "live"
    assert report["provenance"]["model_execution"] == "protocol_test_stub"
    assert report["validation"] == "passed"
    facts = stub.requests[-1]["untrusted_context"]["facts"]
    assert facts
    known = set(report["investigation_analysis"]["after"]["known_evidence_ids"])
    assert {e["event_id"] for e in facts} <= known
    if any(e.get("auth") for e in facts):
        assert any(
            (c.get("fact_predicate") or {}).get("name") == "auth_outcome"
            and c["kind"] == "observed"
            and c["evidence_refs"]
            for c in report["claims"]
        )
    else:
        model_claims = [c for c in report["claims"] if c["claim_id"].startswith("agent-")]
        assert model_claims and all(c["kind"] == "unknown" for c in model_claims)


def test_s1_too_small_budget_still_prevents_external_requests(context):
    settings, _, service, _, _ = context
    with ModelStub("context_load") as stub:
        stub.configure(settings)
        actor, analysis, incident = create_s1(context)
        run = analysis.create_run(
            actor, incident["id"], "context-tiny-run", "live", AgentBudget(max_input_tokens=100)
        )
        service.process_one()
    status = analysis.get_run(actor, run["run_id"])
    assert status["state"] == "partial"
    assert status["budget_used"]["model_calls"] == 0
    assert stub.requests == []
