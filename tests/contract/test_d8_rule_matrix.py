"""Development invariance checks, not independent statistical evaluation."""

from ipaddress import ip_address

import pytest

from packages.detection.registry import detect_all, reproduce
from tests.contract.test_d4_r02 import events as authentication
from tests.contract.test_d6_rules import lateral
from tests.contract.test_d7_rules import baseline, connections


@pytest.mark.parametrize("rule", [f"R{i:02}" for i in range(1, 7)])
@pytest.mark.parametrize("remap", [False, True])
def test_six_rule_positive_negative_matrix_is_not_bound_to_demo_addresses(rule, remap):
    references = []
    if rule == "R01":
        events, session = connections(range(20))
        for index, event in enumerate(events):
            event.dst.port = index + 1
        negatives = [e.model_copy(deep=True) for e in events]
        for event in negatives:
            event.dst.port = 443
    elif rule == "R02":
        events, session = authentication(), "session"
        negatives = [e.model_copy(deep=True) for e in events[:-1]]
    elif rule in {"R03", "R04"}:
        events, session = lateral()
        negatives = [e.model_copy(deep=True) for e in events]
        if rule == "R03":
            negatives[3].process.executable = "/usr/sbin/nginx"
        else:
            negatives = negatives[:-2]
    else:
        events, session = connections(amount=3_000_000 if rule == "R06" else 100)
        references = [baseline(events[0])] if rule == "R06" else []
        negatives = [e.model_copy(deep=True) for e in events]
        if rule == "R05":
            negatives = negatives[:7]
        else:
            for event in negatives:
                event.network.bytes_out = 10
    if remap:
        # One-to-one endpoint rewrite, preserving private/external class and port relations.
        mapping = {}
        for collection in (events, negatives):
            for event in collection:
                for endpoint in (event.src, event.dst):
                    if endpoint and endpoint.ip:
                        source = str(endpoint.ip)
                        if source not in mapping:
                            prefix = "10.77.0" if source.startswith("10.") else "203.0.113"
                            mapping[source] = ip_address(f"{prefix}.{len(mapping) + 1}")
                        endpoint.ip = mapping[source]
    results = [f for f in detect_all(events, session, references) if f["rule_id"] == rule]
    assert results, rule
    assert not [f for f in detect_all(negatives, session, references) if f["rule_id"] == rule]
    for finding in results:
        subset = [e for e in events if e.event_id in finding["evidence_ids"]]
        assert any(f["id"] == finding["id"] for f in reproduce(subset, session, finding))
