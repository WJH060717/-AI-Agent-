from copy import deepcopy
from datetime import UTC
from uuid import UUID

import pytest
from pydantic import ValidationError

from packages.contracts.models import (
    AgentBudget,
    Claim,
    GraphEdge,
    NormalizedEvent,
    ToolDecision,
    stable_event_id,
)


@pytest.fixture
def event() -> dict:
    return {
        "schema_version": "1.0",
        "event_id": "a" * 64,
        "workspace_id": "11111111-1111-4111-8111-111111111111",
        "dataset_id": "77777777-7777-4777-8777-777777777777",
        "event_type": "auth.login",
        "event_time": "2026-11-14T09:00:00+08:00",
        "ingested_at": "2026-11-14T01:00:02Z",
        "time_quality": {
            "original": "2026-11-14T09:00:00+08:00",
            "timezone": "Asia/Shanghai",
            "offset_ms": 0,
            "uncertainty_ms": 1000,
            "basis": "synthetic",
        },
        "sensor": {
            "sensor_id": "host-a",
            "type": "linux_auth",
            "instance_id": "boot-a",
            "observation_domain": "lab-a",
        },
        "source_locators": [
            {
                "object_id": "22222222-2222-4222-8222-222222222222",
                "record_start": 1,
                "record_end": 1,
                "raw_sha256": "b" * 64,
            }
        ],
        "parser_version": "synthetic@1.0.0",
        "dst": {"ip": "10.10.0.20", "port": 22},
        "auth": {"outcome": "success", "method": "password", "service": "ssh"},
        "quality_flags": [],
    }


def test_event_normalizes_aware_time_to_utc(event):
    result = NormalizedEvent.model_validate(event)
    assert result.event_time.hour == 1
    assert result.event_time.tzinfo == UTC


@pytest.mark.parametrize(
    "change",
    [
        {"event_time": "2026-11-14T01:00:00"},
        {"source_locators": []},
        {"schema_version": "2.0"},
        {"ground_truth": "attack"},
        {"dst": {"ip": "not-an-ip", "port": 22}},
        {"dst": {"ip": "10.0.0.1", "port": -1}},
        {"dst": {"ip": "10.0.0.1", "port": "22"}},
        {"auth": {"outcome": "success", "service": "ssh", "method": "password", "secret": "x"}},
    ],
)
def test_rejects_invalid_event_boundary(event, change):
    event.update(change)
    with pytest.raises(ValidationError):
        NormalizedEvent.model_validate(event)


@pytest.mark.parametrize("kind", ["network.connection", "host.process", "security.alert"])
def test_event_type_requires_its_payload(event, kind):
    event["event_type"] = kind
    with pytest.raises(ValidationError):
        NormalizedEvent.model_validate(event)


def test_weak_pid_cannot_claim_strong_process_identity(event):
    event.update(
        event_type="host.process",
        process={"pid": 42, "action": "exec", "entity_id": "proc:42", "identity_basis": "pid_only"},
    )
    with pytest.raises(ValidationError):
        NormalizedEvent.model_validate(event)


def test_linux_cannot_borrow_sysmon_identity_without_birth_marker(event):
    event.update(
        event_type="host.process",
        asset_id="33333333-3333-4333-8333-333333333333",
        process={
            "pid": 42,
            "action": "exec",
            "entity_id": "proc:42",
            "identity_basis": "process_guid",
        },
    )
    with pytest.raises(ValidationError):
        NormalizedEvent.model_validate(event)


def test_noncontiguous_evidence_is_preserved(event):
    second = deepcopy(event["source_locators"][0])
    second.update(record_start=5, record_end=5)
    event["source_locators"].append(second)
    assert len(NormalizedEvent.model_validate(event).source_locators) == 2


def test_event_id_is_order_independent_but_scope_sensitive(event):
    e = NormalizedEvent.model_validate(event)
    a = e.source_locators[0]
    b = a.model_copy(update={"record_start": 5, "record_end": 5})
    args = (e.workspace_id, e.dataset_id, e.sensor.sensor_id)
    assert stable_event_id(*args, [a, b]) == stable_event_id(*args, [b, a])
    assert stable_event_id(*args, [a]) != stable_event_id(*args, [b])
    assert stable_event_id(*args, [a]) != stable_event_id(
        e.workspace_id, UUID("88888888-8888-4888-8888-888888888888"), "host-a", [a]
    )


def test_observed_graph_edge_requires_evidence():
    with pytest.raises(ValidationError):
        GraphEdge(
            edge_id="edge-1",
            snapshot_id=UUID(int=1),
            source="a",
            target="b",
            relation="spawned",
            kind="observed",
            evidence_refs=[],
            method="audit",
            method_version="1.0.0",
            score=1,
        )


def test_observed_claim_cannot_be_uncited():
    with pytest.raises(ValidationError):
        Claim(
            claim_id="c1",
            kind="observed",
            statement="登录成功",
            evidence_refs=[],
            fact_predicate={"name": "auth_outcome", "values": {"outcome": "success"}},
        )


def test_agent_cannot_request_shell_or_increase_budget():
    with pytest.raises(ValidationError):
        ToolDecision(
            action="call_tool",
            tool="shell",
            arguments={"cmd": "whoami"},
            reason_summary="test",
            expected_evidence="test",
        )
    with pytest.raises(ValidationError):
        AgentBudget(max_tool_calls=7)
