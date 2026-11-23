import base64
from dataclasses import replace

import pytest

from packages.agent.executor import summary
from packages.detection.limits import DetectionBudget, DetectionLimit
from packages.detection.registry import detect_all, reproduce
from tests.unit.test_http_dns import context, parse, record


def nontext_pairs(count=2, gap=10, query=None):
    ctx = context()
    query = query if query is not None else b"X" * 40 + bytes([255]) + b"%Q"
    events = []
    for index in range(count):
        base = dict(ts=1000 + gap * index, uid=f"B{index}", **{"id.orig_p": 45000 + index})
        events.append(
            parse(
                record(**base, proto="tcp", duration=5),
                replace(ctx, source_type="zeek", sha256="b" * 64),
                index + 1,
            )
        )
        raw = record(**base, status_code=404, response_body_len=0, user_agent=None)
        raw.pop("uri", None)
        raw["uri_b64"] = base64.b64encode(b"/q?" + query).decode()
        events.append(parse(raw, ctx, index + 1))
    return events


def r10(events):
    return [f for f in detect_all(events, "session") if f["rule_id"] == "R10"]


def test_binary_input_preserves_safe_observation_and_unknown_decode():
    event = nontext_pairs()[1]
    assert event.schema_version == "1.4"
    shape = event.http.query_shape
    assert shape.status == "observed" and shape.raw_bytes == 43
    assert shape.raw_non_utf8 is True and shape.percent_encoding == "invalid"
    assert shape.decoded_non_utf8 is shape.decoded_control_count is None
    assert event.http.client_shape.query_status == "unavailable"
    assert "uri_b64" not in str(summary(event)) and "XXXX" not in str(summary(event))


def test_utf8_byte_input_matches_text_and_legacy_shape_is_optional():
    raw = record(uri="/file.exe?x=hello", user_agent="Mozilla/5.0")
    text = parse(raw)
    for key in ("uri", "user_agent"):
        raw[key + "_b64"] = base64.b64encode(raw.pop(key).encode()).decode()
    binary = parse(raw)
    assert text.http == binary.http
    assert binary.http.uri_suffix == ".exe"
    assert parse(record(uri=None)).http.query_shape.status == "unavailable"
    legacy = text.model_dump(mode="json")
    legacy["schema_version"] = "1.3"
    legacy["http"].pop("query_shape")
    from packages.contracts.models import NormalizedEvent

    assert NormalizedEvent.model_validate(legacy).http.query_shape is None


@pytest.mark.parametrize(
    "bad", ["%%%", "YQ===", 123, None, base64.b64encode(b"a" * 16385).decode()]
)
def test_byte_wrapper_rejects_invalid_noncanonical_and_oversize(bad):
    raw = record()
    raw.pop("uri", None)
    raw["uri_b64"] = bad
    with pytest.raises(ValueError):
        parse(raw)


def test_wrapper_conflict_and_invalid_user_agent_are_explicit():
    with pytest.raises(ValueError):
        parse(record(uri="/a", uri_b64="L2E="))
    raw = record(uri="/q", user_agent_b64=base64.b64encode(bytes([255])).decode())
    assert parse(raw).http.client_shape.user_agent_class == "unknown"
    with pytest.raises(ValueError):
        parse(record(user_agent_b64=base64.b64encode(b"x" * 2049).decode()))


def test_nontext_candidate_has_failed_response_limit_and_exact_replay():
    events = nontext_pairs()
    found = r10(events)
    assert len(found) == 1 and found[0]["maliciousness"] == "unknown"
    assert found[0]["statistics"]["status_counts"] == {"404": 2}
    assert "失败" in " ".join(found[0]["limitations"])
    assert reproduce(events, "session", found[0]) == found
    assert r10(events + events) == found


@pytest.mark.parametrize(
    "query",
    [
        b"x" * 40,
        ("中文" * 20).encode(),
        b"word=" + bytes([255]) * 40,
        b"x" * 40 + b"%Q",
        b"x" * 40 + bytes([255]),
        b"bad%FF%00",
    ],
)
def test_normal_text_structured_legacy_and_short_query_do_not_trigger(query):
    assert r10(nontext_pairs(query=query)) == []


def test_canonical_binary_query_can_match_but_is_not_proven_malicious():
    events = nontext_pairs(query=b"%FF%00" * 10)
    shape = events[1].http.query_shape
    assert shape.raw_non_utf8 is False and shape.decoded_non_utf8 is True
    found = r10(events)
    assert len(found) == 1 and "正常" in " ".join(found[0]["limitations"])


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_conn",
        "ambiguous",
        "cross_dataset",
        "cross_sensor",
        "different_host",
        "same_uid",
        "duration_unknown",
        "late",
    ],
)
def test_nontext_association_boundaries(mutation):
    events = nontext_pairs()
    if mutation == "missing_conn":
        events.pop(0)
    if mutation == "ambiguous":
        events.append(events[0].model_copy(deep=True, update={"event_id": "f" * 64}))
    if mutation == "cross_dataset":
        events[0].dataset_id = context().dataset_id
    if mutation == "cross_sensor":
        events[0].sensor.instance_id = "other"
    if mutation == "different_host":
        events[1].http.host = "other.example"
    if mutation == "same_uid":
        for event in events:
            event.network.uid = "same"
    if mutation == "duration_unknown":
        events[0].network.duration_ms = None
    if mutation == "late":
        from datetime import timedelta

        events[0].event_time -= timedelta(seconds=20)
    assert r10(events) == []


@pytest.mark.parametrize("gap,expected", [(598, 1), (598.001, 0)])
def test_nontext_window_uncertainty_boundary(gap, expected):
    assert len(r10(nontext_pairs(gap=gap))) == expected


def test_nontext_windows_resource_and_individual_reproduction():
    events = nontext_pairs(count=20, gap=100)
    found = r10(events)
    assert len(found) > 1
    for item in found:
        selected = [e for e in events if e.event_id in item["evidence_ids"]]
        assert item["statistics"]["span_upper_seconds"] <= 600
        assert [f for f in reproduce(selected, "session", item) if f["id"] == item["id"]] == [item]
    with pytest.raises(DetectionLimit), DetectionBudget(work_limit=10):
        r10(events)


def test_nontext_freeze_rejects_drift_and_historical_config_replays(tmp_path):
    import json
    from pathlib import Path

    from packages.detection.freeze import FrozenRulesError
    from packages.detection.freeze_nontext import load_nontext_rule

    events = nontext_pairs()
    found = r10(events)
    for name in ("R10.json", "cc-nontext-freeze.json"):
        (tmp_path / name).write_bytes((Path("rules") / name).read_bytes())
    assert load_nontext_rule(tmp_path).min_query_bytes == 32
    config = json.loads((tmp_path / "R10.json").read_bytes())
    config["min_query_bytes"] = 64
    (tmp_path / "R10.json").write_text(json.dumps(config))
    with pytest.raises(FrozenRulesError):
        load_nontext_rule(tmp_path)
    assert reproduce(events, "session", found[0]) == found


def test_shape_rejects_unknown_as_zero_or_inconsistent_counts():
    from packages.contracts.protocols import HTTPQueryShape

    with pytest.raises(ValueError):
        HTTPQueryShape(status="unavailable", raw_bytes=0)
    shape = nontext_pairs()[1].http.query_shape.model_dump()
    for changes in (
        {"raw_bytes": False},
        {"raw_control_count": 100},
        {"decoded_non_utf8": True},
        {"status": "observed", "raw_bytes": None},
    ):
        with pytest.raises(ValueError):
            HTTPQueryShape.model_validate(shape | changes)


@pytest.mark.parametrize("wrapper", [False, True])
def test_fragment_question_mark_is_never_a_query(wrapper):
    ctx = context()
    events = nontext_pairs()
    uri = "/path#fragment?" + "%FF%00" * 10
    for i in range(2):
        raw = record(ts=1000 + i * 10, uid=f"B{i}", uri=uri, **{"id.orig_p": 45000 + i})
        if wrapper:
            raw["uri_b64"] = base64.b64encode(raw.pop("uri").encode()).decode()
        events[2 * i + 1] = parse(raw, ctx, i + 1)
    assert events[1].http.query_shape.raw_bytes == 0
    assert r10(events) == []


def test_all_request_uncertainty_bounds_window_and_does_not_skip_internal_point():
    from datetime import timedelta

    events = nontext_pairs(count=3, gap=100)
    for e in events[-2:]:
        e.event_time += timedelta(seconds=300)
    events[3].time_quality.uncertainty_ms = 400000
    # The interior request alone spans 800 s. Never claim a <=600 s group or join across it.
    assert r10(events) == []


def test_middle_uncertainty_is_in_statistics_merge_and_evidence_replay():
    from datetime import timedelta

    events = nontext_pairs(count=3, gap=100)
    for e in events[-2:]:
        e.event_time += timedelta(seconds=300)
    events[3].time_quality.uncertainty_ms = 200000
    found = r10(events)
    assert len(found) == 1
    assert found[0]["statistics"]["requests"] == 2
    assert found[0]["statistics"]["span_upper_seconds"] == 400
    subset = [e for e in events if e.event_id in found[0]["evidence_ids"]]
    assert reproduce(subset, "session", found[0]) == found


def test_archived_rule_keeps_original_reproduction():
    from datetime import timedelta

    from packages.detection.r10 import R10Config, detect_nontext_queries

    events = nontext_pairs(count=3, gap=100)
    for e in events[-2:]:
        e.event_time += timedelta(seconds=300)
    events[3].time_quality.uncertainty_ms = 400000
    old = detect_nontext_queries(events, "session", R10Config(version="1.0.0"))
    assert len(old) == 1  # Archived flawed candidate, explicitly not the current detector.
    assert reproduce(events, "session", old[0]) == old
    assert r10(events) == []


def test_varied_uncertainty_all_evidence_stays_bounded_and_reproducible():
    import random
    from datetime import timedelta

    rng = random.Random(71)
    for _ in range(40):
        events = nontext_pairs(count=10, gap=100)
        for event in events[1::2]:
            event.time_quality.uncertainty_ms = rng.choice([1000, 10000, 200000, 400000])
        for found in r10(events):
            selected = [e for e in events if e.event_id in found["evidence_ids"]]
            http = [e for e in selected if e.http]
            lower = min(
                e.event_time - timedelta(milliseconds=e.time_quality.uncertainty_ms) for e in http
            )
            upper = max(
                e.event_time + timedelta(milliseconds=e.time_quality.uncertainty_ms) for e in http
            )
            assert (upper - lower).total_seconds() <= 600
            assert found["statistics"]["span_upper_seconds"] == (upper - lower).total_seconds()
            assert [f for f in reproduce(selected, "session", found) if f["id"] == found["id"]] == [
                found
            ]
