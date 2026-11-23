import json
from dataclasses import replace
from datetime import timedelta
from uuid import uuid4

import pytest

from packages.contracts.models import InvestigationScope
from packages.graph.paths import analyze_paths
from packages.ingest.parsers import parse_record
from tests.contract.test_d4_identity_graph import process
from tests.integration.d4_helpers import auth_record, context_payload, parse_context


def chain():
    metadata = context_payload()
    metadata["sensors"].append(
        metadata["sensors"][0] | {"sensor_id": "net-a", "source_type": "zeek", "asset_id": None}
    )
    ctx = parse_context("linux_audit", b"synthetic", metadata)
    auth = auth_record(22, "success") | {"dest_ip": "10.10.0.20", "dest_port": 22}
    login = parse_record(
        json.dumps(auth).encode(), 100, replace(ctx, source_type="linux_auth", sensor_id="auth-a")
    )
    network = {
        "ts": login.event_time.timestamp() - 1,
        "uid": "net",
        "id.orig_h": "192.0.2.10",
        "id.orig_p": 42022,
        "id.resp_h": "10.10.0.20",
        "id.resp_p": 22,
        "proto": "tcp",
    }
    net = parse_record(
        json.dumps(network).encode(), 101, replace(ctx, source_type="zeek", sensor_id="net-a")
    )
    parent = process(ctx, 10, 50, "2026-11-14T01:00:30Z")
    child = process(ctx, 42, 100, "2026-11-14T01:00:40Z", (10, 50))
    scope = InvestigationScope(
        workspace_id=ctx.workspace_id,
        dataset_id=ctx.dataset_id,
        session_id=uuid4(),
        snapshot_id=uuid4(),
        start="2026-11-14T00:59:00Z",
        end="2026-11-14T01:05:00Z",
    )
    return [net, login, parent, child], scope


def test_supported_path_has_event_edges_origins_and_exact_evidence():
    current, scope = chain()
    result = analyze_paths(current, scope, {current[1].event_id})
    assert result.paths[0].event_ids == [e.event_id for e in current]
    assert result.paths[0].observed_steps == 2 and result.paths[0].inferred_steps == 1
    assert result.paths[0].coverage == 1 and result.paths[0].missing_steps == 0
    assert result.origins[0].left_censored is True
    assert result.paths[0].score < 1
    links = {link.edge_id: link for link in result.links}
    for edge_id in result.paths[0].edge_ids:
        link = links[edge_id]
        assert link.entity_edge_ids and len(link.evidence_refs) == 2
        assert {ref.event_id for ref in link.evidence_refs} == {
            link.from_event_id,
            link.to_event_id,
        }
    assert (
        analyze_paths(list(reversed(current)), scope, {current[1].event_id}).model_dump()
        == result.model_dump()
    )


@pytest.mark.parametrize(
    "case", ["no_session", "weak_process", "boot", "uncertain", "reverse", "failed_auth"]
)
def test_missing_or_uncertain_jumps_are_not_fabricated(case):
    current, scope = chain()
    if case == "no_session":
        for event in current[1:]:
            event.user.session_id = None
    elif case == "weak_process":
        current[2].process.entity_id = None
        current[2].process.identity_basis = "pid_only"
    elif case == "boot":
        current[2].host.boot_id = "other-boot"
    elif case == "uncertain":
        current[2].time_quality.uncertainty_ms = 10000
    elif case == "reverse":
        current[2].event_time -= timedelta(seconds=15)
    else:
        current[1].auth.outcome = "failure"
    result = analyze_paths(current, scope, {current[1].event_id})
    assert not any(
        link.relation == "associated_process" and link.to_event_id == current[2].event_id
        for link in result.links
    )
    assert result.breakpoints
    if case == "failed_auth":
        assert not result.paths


def test_pure_scan_and_unrelated_context_do_not_force_a_path():
    current, scope = chain()
    scan = current[0].model_copy(deep=True)
    scan.event_id = "f" * 64
    scan.src.ip = "192.0.2.99"
    result = analyze_paths([scan] + current, scope, {scan.event_id})
    assert result.paths == [] and result.status == "insufficient_evidence"
    assert result.origins and result.breakpoints
    with pytest.raises(ValueError, match="scope"):
        analyze_paths(
            current, scope.model_copy(update={"dataset_id": uuid4()}), {current[1].event_id}
        )
    with pytest.raises(ValueError, match="seed"):
        analyze_paths(current, scope, {"a" * 64})


def test_top3_six_hop_beam_and_scores_are_deterministic():
    current, scope = chain()
    children = []
    for i in range(25):
        child = current[-1].model_copy(deep=True)
        child.event_id = f"{200 + i:064x}"
        child.process.entity_id += str(i)
        children.append(child)
    result = analyze_paths(current[:3] + children, scope, {current[1].event_id})
    assert len(result.paths) == 3 and result.truncated
    assert all(len(path.edge_ids) <= 6 for path in result.paths)
    assert result.alternatives
    assert result == analyze_paths(
        list(reversed(current[:3] + children)), scope, {current[1].event_id}
    )


def test_isolated_rule_seeds_do_not_consume_the_search_beam():
    current, scope = chain()
    isolated = []
    for i in range(30):
        event = current[0].model_copy(deep=True)
        event.event_id = f"{i:064x}"
        event.src.port = 50000 + i
        isolated.append(event)
    result = analyze_paths(isolated + current, scope, {e.event_id for e in isolated + [current[1]]})
    assert any(path.event_ids == [e.event_id for e in current] for path in result.paths)


def test_additional_observations_cannot_hide_exact_session_or_parent_evidence():
    current, scope = chain()
    prior_auth = current[1].model_copy(deep=True)
    prior_auth.event_id = "a" * 64
    prior_auth.event_time -= timedelta(seconds=3)
    prior_parent = current[2].model_copy(deep=True)
    prior_parent.event_id = "b" * 64
    prior_parent.event_time -= timedelta(seconds=1)
    result = analyze_paths([prior_auth, prior_parent] + current, scope, {current[1].event_id})
    assert any(path.event_ids == [e.event_id for e in current] for path in result.paths)
    pairs = {(link.from_event_id, link.to_event_id, link.relation) for link in result.links}
    assert (current[1].event_id, current[2].event_id, "associated_process") in pairs
    assert (current[2].event_id, current[3].event_id, "spawned") in pairs


def test_origin_is_earliest_observation_per_target_not_every_isolated_scan():
    current, scope = chain()
    scans = []
    for i in range(5):
        event = current[0].model_copy(deep=True)
        event.event_id = f"{i:064x}"
        event.event_time -= timedelta(seconds=10 - i)
        event.dst.port = 100 + i
        scans.append(event)
    result = analyze_paths(scans + current, scope, {e.event_id for e in scans + [current[1]]})
    assert len(result.origins) == 1
    assert result.origins[0].event_id == scans[0].event_id
    assert result.paths


def test_external_and_internal_entry_are_network_candidates_only():
    from ipaddress import ip_address

    current, scope = chain()
    for event in current[:2]:
        event.src.ip = ip_address("8.8.8.8")
    result = analyze_paths(current, scope, {current[1].event_id})
    assert result.origins[0].classification == "external_entry_candidate"
    for event in current[:2]:
        event.src.asset_id = scope.dataset_id
    result = analyze_paths(current, scope, {current[1].event_id})
    assert result.origins[0].classification == "internal_start_candidate"


def test_six_hop_limit_stops_a_real_long_lifecycle_chain():
    current, scope = chain()
    ctx = parse_context("linux_audit", b"long-chain")
    ctx = replace(ctx, workspace_id=str(scope.workspace_id), dataset_id=str(scope.dataset_id))
    previous_pid, previous_birth = 42, 100
    for i in range(8):
        event = process(
            ctx, 100 + i, 200 + i, f"2026-11-14T01:00:{45 + i}Z", (previous_pid, previous_birth)
        )
        event.user.session_id = None
        current.append(event)
        previous_pid, previous_birth = 100 + i, 200 + i
    result = analyze_paths(current, scope, {current[1].event_id})
    assert result.truncated and max(len(path.edge_ids) for path in result.paths) == 6
    assert all(len(set(path.event_ids)) == len(path.event_ids) for path in result.paths)
