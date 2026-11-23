from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from packages.agent.tools import ReadOnlyTools
from packages.contracts.models import InvestigationScope
from packages.graph.service import connection_graph
from packages.storage.service import DomainError


def test_graph_edges_have_exact_evidence_and_tools_do_not_escape_scope(context):
    _, _, service, workspace, _ = context
    actor = service.system_actor(workspace)
    dataset = service.create_dataset(actor, {"name": "graph", "provenance_type": "synthetic"}, "g")
    service.stage_bytes(
        actor,
        dataset["dataset_id"],
        "zeek",
        "s",
        "UTC",
        Path("data/fixtures/d1/zeek.jsonl").read_bytes(),
        "u",
    )
    service.process_one()
    all_events = service.list_events(
        actor, dataset["dataset_id"], dataset["default_session_id"], 100
    )["items"]
    start = datetime(2026, 11, 14, 1, tzinfo=UTC)
    scope = InvestigationScope(
        workspace_id=UUID(workspace),
        dataset_id=dataset["dataset_id"],
        session_id=dataset["default_session_id"],
        snapshot_id=uuid4(),
        start=start,
        end=start + timedelta(minutes=1),
    )
    tools = ReadOnlyTools(service, actor, scope, frozenset([all_events[0]["event_id"]]))
    events = tools.search_events()
    assert len(events) == 1
    with pytest.raises(DomainError):
        tools.get_event_evidence(all_events[1]["event_id"])
    graph = connection_graph(events, scope)
    assert len(graph["edges"]) == 1
    edge = graph["edges"][0]
    assert edge.kind == "observed"
    assert edge.relation == "communicated_with"
    assert edge.evidence_refs[0].event_id == all_events[0]["event_id"]
    assert edge.evidence_refs[0].fragments[0].record_start == 1
