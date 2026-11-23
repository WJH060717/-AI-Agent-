"""Behavioral request candidates must remain reproducible and narrowly scoped."""

from dataclasses import replace

import pytest

from packages.detection.limits import DetectionBudget, DetectionLimit
from packages.detection.registry import detect_all, reproduce
from tests.unit.test_http_dns import context, parse, record


def sample():
    ctx = context()
    conn = parse(
        record(ts=990, proto="tcp", duration=20), replace(ctx, source_type="zeek", sha256="b" * 64)
    )
    http = parse(record(), ctx)
    dns = parse(
        record(
            ts=980,
            proto="udp",
            query="example.com",
            qtype=1,
            rcode=0,
            rejected=False,
            answers=["198.51.100.2"],
        ),
        replace(ctx, source_type="zeek_dns", sha256="c" * 64),
    )
    return conn, http, dns


def r07(events):
    return [f for f in detect_all(events, "session") if f["rule_id"] == "R07"]


def test_request_candidate_contains_sources_and_reproduces_exactly():
    events = sample()
    found = r07(events)
    assert len(found) == 1
    assert set(found[0]["evidence_ids"]) == {e.event_id for e in events}
    assert found[0]["stage"] == "request_only"
    assert found[0]["dns_context_status"] == "included"
    assert reproduce(events, "session", found[0]) == found


@pytest.mark.parametrize(
    "field,value",
    [
        ("method", "POST"),
        ("status_code", 404),
        ("status_code", None),
        ("uri_suffix", None),
    ],
)
def test_nonmatching_request_is_not_candidate(field, value):
    conn, http, dns = sample()
    setattr(http.http, field, value)
    assert r07([conn, http, dns]) == []


@pytest.mark.parametrize(
    "target,field,value",
    [
        ("sensor", "sensor_id", "other"),
        ("sensor", "instance_id", "other"),
        ("sensor", "observation_domain", "other"),
        ("src", "port", 40001),
        ("network", "uid", "other"),
        ("network", "duration_ms", None),
    ],
)
def test_uid_alone_never_correlates(target, field, value):
    conn, http, dns = sample()
    setattr(getattr(conn, target), field, value)
    assert r07([conn, http, dns]) == []


def test_ambiguous_conn_and_outside_time_are_rejected():
    conn, http, dns = sample()
    duplicate = conn.model_copy(deep=True, update={"event_id": "f" * 64})
    assert r07([conn, duplicate, http, dns]) == []
    conn.network.duration_ms = 1000
    assert r07([conn, http, dns]) == []


def test_repeated_requests_with_one_uid_remain_distinct():
    conn, http, dns = sample()
    other = http.model_copy(deep=True, update={"event_id": "f" * 64})
    other.http.transaction_depth = 2
    found = r07([conn, http, other, dns])
    assert len(found) == 2
    assert found[0]["id"] != found[1]["id"]


@pytest.mark.parametrize("change", ["query", "answer", "clock", "collector", "overflow"])
def test_dns_context_cannot_invent_support(change):
    conn, http, dns = sample()
    records = [dns]
    if change == "query":
        dns.dns.query = "other.example"
    elif change == "answer":
        dns.dns.answers = []
    elif change == "clock":
        dns.event_time = http.event_time
    elif change == "collector":
        dns.sensor.instance_id = "other"
    else:
        records = [dns.model_copy(deep=True, update={"event_id": f"{i:064x}"}) for i in range(33)]
    events = [conn, http, *records]
    found = r07(events)
    assert len(found) == 1
    assert set(found[0]["evidence_ids"]) == {conn.event_id, http.event_id}
    assert found[0]["dns_context_status"] == "not_included"
    assert reproduce([conn, http], "session", found[0]) == found


def test_resource_guard_does_not_publish_partial_candidates():
    with pytest.raises(DetectionLimit), DetectionBudget(work_limit=1):
        r07(sample())


def test_mime_can_match_without_filename_and_body_is_separate():
    conn, http, dns = sample()
    http.http.uri_suffix = None
    http.http.response_mime_types = ["application/x-dosexec"]
    http.http.response_body_len = 100
    found = r07([conn, http, dns])
    assert len(found) == 1
    assert found[0]["stage"] == "body_observed"


def test_extension_freeze_rejects_drift_and_history_ignores_current_config(tmp_path):
    import json
    from pathlib import Path

    from packages.detection.freeze import FrozenRulesError
    from packages.detection.freeze_http import load_http_rule

    events = sample()
    found = r07(events)
    for name in ("R07.json", "http-round1-freeze.json"):
        (tmp_path / name).write_bytes((Path("rules") / name).read_bytes())
    config = json.loads((tmp_path / "R07.json").read_bytes())
    config["statuses"] = [404]
    (tmp_path / "R07.json").write_text(json.dumps(config))
    with pytest.raises(FrozenRulesError):
        load_http_rule(tmp_path)
    assert reproduce(events, "session", found[0]) == found


def test_txt_ip_shape_is_not_dns_address_support():
    conn, http, dns = sample()
    dns.dns.qtype = 16
    found = r07([conn, http, dns])
    assert len(found) == 1
    assert dns.event_id not in found[0]["evidence_ids"]
