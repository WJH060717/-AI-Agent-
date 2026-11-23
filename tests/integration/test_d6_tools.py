import json
from uuid import uuid4

import pytest

from packages.agent.executor import ToolExecutor
from packages.storage.analysis import AnalysisService
from packages.storage.service import DomainError
from tests.integration.d4_helpers import audit_record, raw_lines
from tests.integration.test_d5_analysis import investigated


def test_tools_use_real_snapshot_and_two_different_queries_find_new_evidence(context):
    _, _, service, _, _ = context
    actor, _, run = investigated(context)
    tools = ToolExecutor(service, actor, run["run_id"])
    result = tools.call("search_events", {"types": ["host.process"], "limit": 1})
    assert result.status == "ok" and len(result.evidence_ids) == 1 and result.next_cursor
    assert len(result.model_dump_json().encode()) <= 16384
    second = tools.call(
        "search_events", {"types": ["host.process"], "limit": 1, "cursor": result.next_cursor}
    )
    assert len(second.evidence_ids) == 1 and second.evidence_ids != result.evidence_ids
    proof = tools.call("get_event_evidence", {"event_ids": result.evidence_ids})
    assert proof.status == "ok" and "sha256" in json.dumps(proof.data)
    assert "alice" not in proof.model_dump_json() and "identity_salt" not in proof.model_dump_json()
    process = result.data["items"][0]["process"]["entity_id"]
    assert tools.call(
        "get_process_context", {"process_entity_id": process, "depth": 2}
    ).evidence_ids
    asset = result.data["items"][0]["asset_id"]
    assert tools.call("get_asset_timeline", {"asset_id": asset, "limit": 2}).evidence_ids
    assert tools.call("get_candidate_paths", {"incident_id": tools.incident_id, "top_k": 1}).data[
        "items"
    ]
    assert tools.call("get_technique_context", {"technique_ids": ["T1110"]}).status == "ok"


@pytest.mark.parametrize(
    "tool,args",
    [
        ("shell", {"command": "echo token"}),
        ("search_events", {"workspace_id": "other"}),
        ("search_events", {"limit": 101}),
        ("search_events", {"limit": True}),
        ("search_events", {"field_filter": [{"field": "raw_password", "op": "eq", "value": "x"}]}),
        ("search_events", {"start": "2020-01-01T00:00:00Z"}),
        ("get_event_evidence", {"event_ids": ["f" * 64]}),
        ("get_process_context", {"process_entity_id": "42", "depth": 3}),
        ("get_asset_timeline", {"asset_id": str(uuid4())}),
        ("get_candidate_paths", {"incident_id": str(uuid4())}),
        ("get_technique_context", {"technique_ids": ["https://evil.test"]}),
    ],
)
def test_tool_policy_rejects_unknown_scope_filters_and_limits(context, tool, args):
    _, _, service, _, _ = context
    actor, _, run = investigated(context)
    with pytest.raises(DomainError):
        ToolExecutor(service, actor, run["run_id"]).call(tool, args)


def test_tool_scope_is_loaded_by_server_not_caller_and_cursor_is_bound(context):
    _, _, service, _, _ = context
    actor, _, run = investigated(context)
    tools = ToolExecutor(service, actor, run["run_id"])
    result = tools.call("search_events", {"limit": 1})
    with pytest.raises(DomainError, match="CURSOR"):
        tools.call("search_events", {"types": ["host.process"], "cursor": result.next_cursor})
    other, _ = service.init_workspace("other")
    with pytest.raises(DomainError, match="NOT_FOUND"):
        ToolExecutor(service, service.system_actor(other), run["run_id"])


def test_evidence_tool_cursor_covers_all_fragments_without_silent_truncation(context):
    _, _, service, _, _ = context
    actor, dataset, _ = investigated(context)
    records = [audit_record("SYSCALL", "partial")] + [audit_record("PATH", "partial")] * 21
    service.stage_bytes(
        actor,
        dataset["dataset_id"],
        "linux_audit",
        "audit-a",
        "UTC",
        raw_lines(records),
        "large-evidence",
    )
    service.process_one()
    analysis = AnalysisService(service)
    incident = analysis.list_incidents(actor, dataset["dataset_id"], dataset["default_session_id"])[
        0
    ]
    run = analysis.create_run(actor, incident["id"], "large-evidence-run")
    service.process_one()
    tools = ToolExecutor(service, actor, run["run_id"])
    event = next(e for e in tools.events if len(e.source_locators) == 22)
    page = tools.call("get_event_evidence", {"event_ids": [event.event_id]})
    assert page.truncated and page.next_cursor
    lines = []
    while True:
        assert len(page.model_dump_json().encode()) <= 16384
        lines += [
            line["line"]
            for item in page.data["items"]
            for part in item["fragments"]
            for line in part["lines"]
        ]
        if not page.next_cursor:
            break
        page = tools.call(
            "get_event_evidence", {"event_ids": [event.event_id], "cursor": page.next_cursor}
        )
    assert lines == list(range(1, 23))
