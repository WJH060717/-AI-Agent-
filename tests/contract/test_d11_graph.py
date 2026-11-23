from uuid import uuid4

import pytest

from packages.graph.service import evidence_graph
from tests.contract.test_d5_paths import chain


def test_node_boundary_clips_deterministically_without_dangling_edges():
    current, scope = chain()
    events = []
    for i in range(251):
        event = current[0].model_copy(deep=True)
        event.event_id = f"{i:064x}"
        event.src.port, event.dst.port = 10000 + i, 20000 + i
        events.append(event)
    exact = evidence_graph(events[:250], scope)
    assert len(exact["nodes"]) == 500 and exact["truncated"] is False
    clipped = evidence_graph(events, scope)
    assert len(clipped["nodes"]) == 500 and clipped["truncated"] is True
    nodes = {n["entity_id"] for n in clipped["nodes"]}
    assert all(e.source in nodes and e.target in nodes for e in clipped["edges"])
    assert clipped == evidence_graph(list(reversed(events)), scope)


def test_many_legal_parent_observations_clip_edges_at_1000_not_hide_pairs():
    current, scope = chain()
    parents, children = [], []
    for i in range(32):
        parent, child = current[2].model_copy(deep=True), current[3].model_copy(deep=True)
        parent.event_id, child.event_id = f"{i:064x}", f"{i + 100:064x}"
        parents.append(parent)
        children.append(child)
    graph = evidence_graph(parents + children, scope)
    assert graph["truncated"] is True and len(graph["edges"]) == 1000
    assert len({e.edge_id for e in graph["edges"]}) == 1000
    assert all(len(e.evidence_refs) == 2 for e in graph["edges"])
    assert graph == evidence_graph(list(reversed(parents + children)), scope)


def test_clipped_tail_is_still_validated_for_scope():
    current, scope = chain()
    events = []
    for i in range(501):
        event = current[0].model_copy(deep=True)
        event.event_id = f"{i:064x}"
        events.append(event)
    events[-1].workspace_id = uuid4()
    with pytest.raises(ValueError, match="scope"):
        evidence_graph(events, scope)
