from copy import deepcopy
from datetime import timedelta

import pytest

from packages.detection.aggregation import aggregate_findings
from tests.contract.test_d4_r02 import events


def finding(identifier, evidence, start=None, end=None):
    event = evidence[0]
    return {
        "id": identifier,
        "rule_id": "R02",
        "evidence_ids": [e.event_id for e in evidence],
        "group_key": [str(event.workspace_id), str(event.dataset_id), "session"],
        "start_time": (start or evidence[0].event_time).isoformat(),
        "end_time": (end or evidence[-1].event_time).isoformat(),
    }


def test_shared_strong_identity_and_overlap_groups_deterministically():
    current = events()
    a, b = finding("a", current[:3]), finding("b", current[2:])
    groups = aggregate_findings([b, a, a], list(reversed(current)))
    assert len(groups) == 1
    assert groups[0]["finding_ids"] == ["a", "b"]
    assert groups[0]["evidence_ids"] == sorted(e.event_id for e in current)
    assert groups[0]["reasons"][0]["shared_entities"]
    assert aggregate_findings([a, b], current) == groups


@pytest.mark.parametrize("change", ["asset_account", "domain", "time", "scope"])
def test_common_source_ip_is_not_enough(change):
    first = events()
    second = deepcopy(first)
    for i, event in enumerate(second):
        event.event_id = f"{i + 200:064x}"
        if change == "asset_account":
            event.asset_id = event.host.asset_id = "44444444-4444-4444-8444-444444444444"
            event.user.entity_id += "other"
        elif change == "domain":
            event.sensor.observation_domain = "other"
        elif change == "time":
            event.event_time += timedelta(minutes=1)
        else:
            event.dataset_id = "55555555-5555-4555-8555-555555555555"
    groups = aggregate_findings([finding("a", first), finding("b", second)], first + second)
    assert len(groups) == 2


def test_transitive_group_does_not_exceed_30_minutes_or_accept_missing_evidence():
    current = events()
    start = current[0].event_time
    findings = [
        finding(
            str(i),
            current,
            start + timedelta(minutes=i * 14),
            start + timedelta(minutes=(i + 1) * 14),
        )
        for i in range(3)
    ]
    groups = aggregate_findings(findings, current)
    assert len(groups) == 2
    with pytest.raises(ValueError, match="evidence"):
        aggregate_findings(findings, [])
