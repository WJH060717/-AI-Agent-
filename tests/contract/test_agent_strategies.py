from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest

from packages.agent.strategies import evaluate, strategy_for, validate
from packages.contracts.models import NormalizedEvent


def event(event_id, rule_event_type="network.packet", packet=None, src=None, asset_id=None):
    return NormalizedEvent.model_construct(
        event_id=event_id,
        workspace_id=uuid4(),
        dataset_id=uuid4(),
        event_type=rule_event_type,
        event_time=datetime(2026, 11, 14, 1, 0, 0, tzinfo=UTC),
        time_quality=SimpleNamespace(uncertainty_ms=0),
        sensor=SimpleNamespace(type="pcap", observation_domain="lab-a"),
        source_locators=[],
        parser_version="test",
        packet=packet,
        src=src,
        asset_id=asset_id or uuid4(),
        process=None,
        host=None,
        quality_flags=[],
        extensions={},
    )


def test_registry_covers_scan_dns_arp_and_states_missing_fields():
    for rule in ("R01", "R24", "R25", "R26", "R27", "R30"):
        assert strategy_for({"rule_id": rule}).strategy_id == "scan_activity@1.0.0"
    assert strategy_for({"rule_id": "R29"}).tools == ("search_events", "get_event_evidence")
    assert strategy_for({"rule_id": "R28"}).missing_fields
    assert strategy_for({"rule_id": "R99"}) is None


def test_scan_is_open_without_authorization_and_queries_are_bounded():
    seed = event("a" * 64)
    finding = {"id": "f" * 64, "rule_id": "R24", "evidence_ids": [seed.event_id]}
    result = evaluate(finding, [seed], {seed.event_id})
    assert result is not None and result.status == "open"
    assert [gap["code"] for gap in result.gaps] == ["scan_authorization"]
    assert result.queries and result.queries[0]["tool"] == "get_asset_timeline"
    validate(result, {seed.event_id})


def test_dns_conflict_supports_only_with_two_distinct_answers():
    first = event(
        "b" * 64,
        packet=SimpleNamespace(
            dns_message=SimpleNamespace(
                message_type="response", question_sha256="q" * 64, answer_set_sha256="1" * 64
            )
        ),
    )
    second = first.model_copy(deep=True)
    second.event_id = "c" * 64
    second.packet = SimpleNamespace(
        dns_message=SimpleNamespace(
            message_type="response", question_sha256="q" * 64, answer_set_sha256="2" * 64
        )
    )
    finding = {"id": "d" * 64, "rule_id": "R29", "evidence_ids": [first.event_id]}
    supported = evaluate(finding, [first, second], {first.event_id, second.event_id})
    assert supported is not None and supported.status == "supported"
    assert set(supported.supporting) == {first.event_id, second.event_id}

    only_one = evaluate(finding, [first], {first.event_id})
    assert only_one is not None and only_one.status == "open"
    assert only_one.gaps[0]["code"] == "dns_resolver_context"


def test_arp_conflict_requires_two_macs_and_rejects_unknown_evidence():
    first = event("e" * 64, packet=SimpleNamespace(sender_mac="aabbccddeeff"), src=SimpleNamespace(ip="10.0.0.5"))
    second = event("f" * 64, packet=SimpleNamespace(sender_mac="001122334455"), src=SimpleNamespace(ip="10.0.0.5"))
    finding = {"id": "1" * 64, "rule_id": "R28", "evidence_ids": [first.event_id]}
    result = evaluate(finding, [first, second], {first.event_id, second.event_id})
    assert result is not None and result.status == "supported"
    with pytest.raises(ValueError, match="OUTSIDE_KNOWN"):
        validate(result, {first.event_id})