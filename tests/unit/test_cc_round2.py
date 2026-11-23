"""C&C triage: observable structure is neither identity nor malicious intent."""

from dataclasses import replace

import pytest

from packages.agent.executor import summary
from packages.contracts.models import NormalizedEvent
from packages.detection.limits import DetectionBudget, DetectionLimit
from packages.detection.registry import detect_all, reproduce
from tests.unit.test_http_dns import context, parse, record

TOKEN = "0123456789abcdef" * 2


def callbacks(count=3, gap=60):
    ctx = context()
    result = []
    for i in range(count):
        base = dict(ts=1000 + gap * i, uid=f"C{i}", **{"id.orig_p": 41000 + i})
        result.append(
            parse(
                record(**base, proto="tcp", duration=5),
                replace(ctx, source_type="zeek", sha256="b" * 64),
                i + 1,
            )
        )
        result.append(
            parse(
                record(
                    **base,
                    user_agent="TelemetryClient/1.0",
                    uri=f"/callback?device={TOKEN}&secret=DO-NOT-EXPOSE",
                    response_body_len=128,
                ),
                ctx,
                i + 1,
            )
        )
    return result


def r08(events):
    return [f for f in detect_all(events, "session") if f["rule_id"] == "R08"]


def test_shape_is_bounded_safe_and_legacy_optional():
    event = callbacks()[1]
    assert event.schema_version == "1.4"
    shape = event.http.client_shape
    assert shape.version == "http-client-shape@1"
    assert shape.user_agent_class == "other"
    assert shape.query_status == "parsed" and shape.opaque_hex_count == 1
    assert shape.query_field_count == 2
    text = str(summary(event))
    assert TOKEN not in text and "DO-NOT-EXPOSE" not in text and "TelemetryClient" not in text
    legacy = event.model_dump(mode="json")
    legacy["schema_version"] = "1.2"
    legacy["http"].pop("client_shape")
    assert NormalizedEvent.model_validate(legacy).http.client_shape is None


@pytest.mark.parametrize("uri", ["/x?x=%FF", "/x?" + "&".join(f"k{i}=1" for i in range(65))])
def test_unavailable_query_does_not_lose_existing_http_event(uri):
    event = parse(record(uri=uri, user_agent="Client/1"))
    assert event.event_type == "network.http"
    assert event.http.client_shape.query_status == "unavailable"
    assert event.http.client_shape.opaque_hex_count is None


def test_positive_callback_candidate_reproduces_from_evidence_only():
    events = callbacks()
    found = r08(events)
    assert len(found) == 1
    assert found[0]["statistics"]["connections"] == 3
    assert set(found[0]["evidence_ids"]) == {e.event_id for e in events}
    assert reproduce(events, "session", found[0]) == found
    assert "unknown" in found[0]["maliciousness"]


@pytest.mark.parametrize(
    "mutation",
    [
        "browser",
        "unknown_client",
        "no_shape",
        "no_token",
        "responses_failed",
        "body_unknown",
        "short",
        "different_host",
        "cross_collector",
        "cross_workspace",
        "no_conn",
        "ambiguous_conn",
        "outside_conn",
        "same_uid",
    ],
)
def test_negative_boundary(mutation):
    events = callbacks()
    for event in events[1::2]:
        if mutation == "browser":
            event.http.client_shape.user_agent_class = "browser_compatible"
        if mutation == "unknown_client":
            event.http.client_shape.user_agent_class = "unknown"
        if mutation == "no_shape":
            event.http.client_shape = None
        if mutation == "no_token":
            event.http.client_shape.opaque_hex_count = 0
        if mutation == "responses_failed":
            event.http.status_code = 404
        if mutation == "body_unknown":
            event.http.response_body_len = None
    if mutation == "short":
        events = callbacks(gap=5)
    if mutation == "different_host":
        events[-1].http.host = "other.example"
    if mutation == "cross_collector":
        events[-2].sensor.instance_id = "other"
    if mutation == "cross_workspace":
        events[-2].workspace_id = context().workspace_id
    if mutation == "no_conn":
        events.pop(-2)
    if mutation == "ambiguous_conn":
        events.append(events[0].model_copy(deep=True, update={"event_id": "f" * 64}))
    if mutation == "outside_conn":
        events[-2].network.duration_ms = 0
        from datetime import timedelta

        events[-2].event_time -= timedelta(seconds=10)
    if mutation == "same_uid":
        for event in events:
            event.network.uid = "same"
    assert r08(events) == []


def test_repeated_events_not_connections_and_updater_not_declared_malicious():
    events = callbacks()
    assert r08(events + events) == r08(events)
    # A legitimate updater can share this observable shape. Do not hide that ambiguity.
    found = r08(events)
    assert len(found) == 1
    assert "更新" in " ".join(found[0]["limitations"])


def test_overlapping_windows_merge_and_resource_limit_is_explicit():
    events = callbacks(count=8)
    found = r08(events)
    assert len(found) == 1 and found[0]["statistics"]["connections"] == 8
    assert reproduce(events, "session", found[0]) == found
    with pytest.raises(DetectionLimit), DetectionBudget(work_limit=10):
        r08(events)


def test_long_activity_windows_remain_bounded_and_reproduce_individually():
    events = callbacks(count=20)
    found = r08(events)
    assert len(found) > 1
    for item in found:
        assert item["statistics"]["span_upper_seconds"] <= 600
        subset = [event for event in events if event.event_id in item["evidence_ids"]]
        assert [f for f in reproduce(subset, "session", item) if f["id"] == item["id"]] == [item]


def test_shape_never_assumes_header_or_query_validity():
    for agent in (None, "", True, "Client\nInjected", "X" * 2049):
        event = parse(record(uri="/x?token=" + TOKEN, user_agent=agent))
        assert event.http.client_shape.user_agent_class == "unknown"
    for query in ("?x=%xx", "?x=%A", "?x=%"):
        event = parse(record(uri="/x" + query))
        assert event.http.client_shape.query_status == "unavailable"


def test_cc_freeze_rejects_drift_and_old_config_reproduces(tmp_path):
    import json
    from pathlib import Path

    from packages.detection.freeze import FrozenRulesError
    from packages.detection.freeze_cc import load_cc_rule

    events = callbacks()
    original = r08(events)
    for name in ("R08.json", "cc-round2-freeze.json"):
        (tmp_path / name).write_bytes((Path("rules") / name).read_bytes())
    config = json.loads((tmp_path / "R08.json").read_bytes())
    config["min_requests"] = 10
    (tmp_path / "R08.json").write_text(json.dumps(config))
    with pytest.raises(FrozenRulesError):
        load_cc_rule(tmp_path)
    assert reproduce(events, "session", original[0]) == original


def test_multi_host_endpoint_is_separate_rule_not_same_service_claim():
    events = callbacks()
    events[1].http.host = "config.example"
    events[3].http.host = events[5].http.host = "ping.example"
    events[3].http.status_code = events[5].http.status_code = 404
    found = [f for f in detect_all(events, "session") if f["rule_id"] == "R09"]
    assert r08(events) == []
    assert len(found) == 1
    assert found[0]["statistics"]["positive_responses"] == 1
    assert found[0]["http_hosts"] == ["config.example", "ping.example"]
    assert "共享" in " ".join(found[0]["limitations"])
    assert reproduce(events, "session", found[0]) == found


@pytest.mark.parametrize("mutation", ["one_host", "different_endpoint", "no_response"])
def test_multi_host_rule_boundaries(mutation):
    events = callbacks()
    if mutation != "one_host":
        events[1].http.host = "other.example"
    if mutation == "different_endpoint":
        from ipaddress import ip_address

        events[0].dst.ip = events[1].dst.ip = ip_address("198.51.100.3")
    if mutation == "no_response":
        for event in events[1::2]:
            event.http.status_code = 404
    assert not [f for f in detect_all(events, "session") if f["rule_id"] == "R09"]


@pytest.mark.parametrize("gap,expected", [(16, 1), (15.999, 0), (299, 1), (299.001, 0)])
def test_window_boundaries_include_time_uncertainty(gap, expected):
    # Both endpoints have 1 s uncertainty: observed span must be [32, 598] s.
    assert len(r08(callbacks(gap=gap))) == expected


def test_endpoint_freeze_rejects_drift(tmp_path):
    import json
    from pathlib import Path

    from packages.detection.freeze import FrozenRulesError
    from packages.detection.freeze_endpoint import load_endpoint_rule

    for name in ("R09.json", "cc-endpoint-freeze.json"):
        (tmp_path / name).write_bytes((Path("rules") / name).read_bytes())
    assert load_endpoint_rule(tmp_path).minimum_hosts == 2
    config = json.loads((tmp_path / "R09.json").read_bytes())
    config["min_requests"] = 4
    (tmp_path / "R09.json").write_text(json.dumps(config))
    with pytest.raises(FrozenRulesError):
        load_endpoint_rule(tmp_path)
