"""HTTP/DNS contracts: safe fields, strict input, unchanged collector scope."""

import json
from dataclasses import replace
from uuid import uuid4

import pytest

from packages.contracts.models import NormalizedEvent
from packages.ingest.parsers import ParseContext, parse_record


def context(source="zeek_http"):
    return ParseContext(str(uuid4()), str(uuid4()), str(uuid4()), "a" * 64, "sensor", source, "UTC")


def record(**changes):
    return {
        "ts": 1000.0,
        "uid": "C-test",
        "id.orig_h": "192.0.2.1",
        "id.orig_p": 40000,
        "id.resp_h": "198.51.100.2",
        "id.resp_p": 80,
        "trans_depth": 1,
        "method": "GET",
        "host": "Example.COM:80",
        "uri": "/secret-installer.EXE?token=SECRET",
        "status_code": 200,
        "response_body_len": 0,
        "username": "SECRET",
        "password": "SECRET",
        **changes,
    }


def parse(value, ctx=None, line=1):
    return parse_record(json.dumps(value).encode(), line, ctx or context())


def test_http_fields_and_no_raw_secrets():
    event = parse(record())
    assert event.schema_version == "1.4"
    assert event.event_type == "network.http"
    assert event.http.host == "example.com"
    assert event.http.uri_suffix == ".exe"
    assert event.http.response_body_len == 0
    assert event.sensor.type == "zeek"
    assert "SECRET" not in event.model_dump_json()
    assert "secret-installer" not in event.model_dump_json()


def test_dns_preserves_only_ip_answers_and_records_omission():
    value = record(
        query="Example.COM.",
        qtype=1,
        rcode=0,
        rejected=False,
        answers=["198.51.100.2", "alias.example.com", "SECRET txt"],
        proto="udp",
    )
    event = parse(value, context("zeek_dns"))
    assert event.dns.query == "example.com"
    assert [str(ip) for ip in event.dns.answers] == ["198.51.100.2"]
    assert event.dns.non_ip_answers == 2
    assert "SECRET" not in event.model_dump_json()


@pytest.mark.parametrize(
    "changes",
    [
        {"status_code": True},
        {"status_code": "200"},
        {"response_body_len": -1},
        {"trans_depth": False},
        {"host": "x@SECRET"},
        {"uri": 1},
        {"resp_mime_types": "application/x-dosexec"},
        {"id.orig_p": True},
        {"ts": float("nan")},
        {"ts": float("inf")},
        {"uid": ""},
    ],
)
def test_bad_http_is_rejected(changes):
    with pytest.raises((ValueError, OverflowError)):
        parse(record(**changes))


def test_new_payload_required_and_legacy_shape_accepted():
    event = parse(record()).model_dump(mode="json")
    event.pop("http")
    with pytest.raises(ValueError):
        NormalizedEvent.model_validate(event)
    event.update(event_type="network.dns", schema_version="1.0")
    NormalizedEvent.model_validate(event)


def test_missing_http_observations_stay_unknown():
    value = record()
    for field in ("host", "uri", "status_code", "response_body_len"):
        value.pop(field)
    event = parse(value)
    assert event.http.host is event.http.uri_suffix is event.http.status_code is None
    assert event.http.response_body_len is None


def test_protocols_share_configured_zeek_profile():
    ctx = context()
    ctx = replace(
        ctx,
        metadata={
            "sensors": [
                {
                    "sensor_id": "sensor",
                    "source_type": "zeek",
                    "instance_id": "collector-1",
                    "observation_domain": "lab",
                    "offset_ms": 0,
                    "uncertainty_ms": 0,
                    "clock_basis": "fixture",
                }
            ],
            "assets": [],
        },
    )
    event = parse(record(), ctx)
    assert event.sensor.instance_id == "collector-1"


@pytest.mark.parametrize("qtype,answer", [(16, "198.51.100.2"), (28, "198.51.100.2"),
                                        (1, "2001:db8::1"), (None, "198.51.100.2")])
def test_dns_only_address_rr_answers_are_projected(qtype, answer):
    event = parse(record(proto="udp", query="example.com", qtype=qtype,
                         answers=[answer]), context("zeek_dns"))
    assert event.dns.answers == []
    assert event.dns.omitted_answers == 1


@pytest.mark.parametrize("changes", [{"answers": "192.0.2.1"}, {"answers": [True]},
    {"answers": ["192.0.2.1"] * 65}, {"qtype": True}, {"rcode": "0"}, {"rejected": 0}])
def test_bad_dns_is_rejected(changes):
    with pytest.raises(ValueError):
        parse(record(proto="udp", query="example.com", **changes), context("zeek_dns"))
