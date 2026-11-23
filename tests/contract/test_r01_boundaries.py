import hashlib
import json
from uuid import uuid4

import pytest

from packages.detection.r01 import detect_scans
from packages.ingest.parsers import ParseContext, parse_record


@pytest.mark.parametrize(
    "case,expected",
    [
        ("internal_hosts", True),
        ("external_hosts", False),
        ("different_sources", False),
        ("slow_ports", False),
        ("same_port", False),
    ],
)
def test_r01_does_not_merge_unrelated_observations(case, expected):
    records = []
    for i in range(20):
        record = {
            "ts": 1794618000 + i,
            "uid": f"x{i}",
            "id.orig_h": "192.0.2.10",
            "id.orig_p": 42000 + i,
            "id.resp_h": "10.10.0.20",
            "id.resp_p": i + 1,
            "proto": "tcp",
        }
        if case in ("internal_hosts", "external_hosts"):
            record["id.resp_h"] = (
                f"10.10.1.{i + 1}" if case == "internal_hosts" else f"198.51.100.{i + 1}"
            )
            record["id.resp_p"] = 22
        elif case == "different_sources":
            record["id.orig_h"] = "192.0.2.10" if i < 10 else "192.0.2.11"
        elif case == "slow_ports":
            record["ts"] = 1794618000 + i * 10
        else:
            record["id.resp_p"] = 22
        records.append(json.dumps(record).encode())
    ctx = ParseContext(
        str(uuid4()),
        str(uuid4()),
        str(uuid4()),
        hashlib.sha256(b"\n".join(records)).hexdigest(),
        "sensor",
        "zeek",
        "UTC",
    )
    events = [parse_record(raw, i + 1, ctx) for i, raw in enumerate(records)]
    findings = detect_scans(events, str(uuid4()))
    assert bool(findings) is expected
    if expected:
        assert {finding["kind"] for finding in findings} == {"hosts"}
