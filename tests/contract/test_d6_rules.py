import json
from dataclasses import replace
from datetime import timedelta

import pytest

from packages.detection.r03 import detect_process_anomalies
from packages.detection.r04 import detect_remote_access
from packages.detection.registry import detect_all, reproduce
from packages.ingest.parsers import ParseContext, parse_record
from tests.contract.test_d5_paths import chain
from tests.integration.d4_helpers import OTHER, auth_record, context_payload


def lateral():
    current, scope = chain()
    current[2].process.executable = "/usr/sbin/nginx"
    current[3].process.executable = "/bin/sh"
    metadata = context_payload()
    metadata["assets"].append(
        {
            "asset_id": OTHER,
            "hostnames": ["host-b"],
            "addresses": [
                {
                    "ip": "10.10.0.30",
                    "observation_domain": "lab-a",
                    "valid_from": "2026-11-14T00:00:00Z",
                    "valid_to": "2026-11-15T00:00:00Z",
                }
            ],
        }
    )
    metadata["sensors"] += [
        metadata["sensors"][0] | {"sensor_id": "auth-b", "asset_id": OTHER},
        metadata["sensors"][0] | {"sensor_id": "net-a", "source_type": "zeek", "asset_id": None},
    ]
    ref = current[0].source_locators[0]
    ctx = ParseContext(
        str(scope.workspace_id),
        str(scope.dataset_id),
        str(ref.object_id),
        ref.raw_sha256,
        "net-a",
        "zeek",
        "UTC",
        metadata,
        "a" * 64,
    )
    network = {
        "ts": current[0].event_time.timestamp() + 29,
        "id.orig_h": "10.10.0.20",
        "id.orig_p": 43000,
        "id.resp_h": "10.10.0.30",
        "id.resp_p": 22,
        "proto": "tcp",
    }
    net = parse_record(json.dumps(network).encode(), 300, ctx)
    auth = auth_record(51, "success") | {
        "host": "host-b",
        "boot_id": "boot-b",
        "src_ip": "10.10.0.20",
        "src_port": 43000,
        "dest_ip": "10.10.0.30",
        "dest_port": 22,
        "session_id": "b-session",
    }
    login = parse_record(
        json.dumps(auth).encode(), 301, replace(ctx, sensor_id="auth-b", source_type="linux_auth")
    )
    return current + [net, login], str(scope.session_id)


def test_r03_r04_positive_and_original_config_reproduce():
    current, session = lateral()
    findings = detect_all(current, session)
    r03 = next(f for f in findings if f["rule_id"] == "R03")
    r04 = next(f for f in findings if f["rule_id"] == "R04")
    assert r03["evidence_ids"] == [current[2].event_id, current[3].event_id]
    assert r04["kind"] == "remote_access_candidate"
    assert "process_socket_binding" in r04["missing_steps"]
    selected = [e for e in current if e.event_id in r04["evidence_ids"]]
    assert any(f["id"] == r04["id"] for f in reproduce(selected, session, r04))
    assert detect_all(list(reversed(current)), session) == findings


@pytest.mark.parametrize(
    "case", ["allowed_child", "unknown_parent", "weak", "boot", "reverse", "scope"]
)
def test_r03_normal_or_weak_identity_does_not_trigger(case):
    current, session = lateral()
    parent, child = current[2:4]
    if case == "allowed_child":
        child.process.executable = "/usr/sbin/nginx"
    elif case == "unknown_parent":
        parent.process.executable = "/lab/unconfigured-service"
    elif case == "weak":
        child.process.entity_id = None
    elif case == "boot":
        child.host.boot_id = "different"
    elif case == "reverse":
        child.event_time = parent.event_time
    else:
        child.sensor.observation_domain = "other"
    assert detect_process_anomalies(current, session) == []


@pytest.mark.parametrize(
    "case",
    [
        "no_auth",
        "failed_auth",
        "tuple",
        "nat",
        "domain",
        "expired",
        "no_seed",
        "weak_target",
        "uncertain",
        "same_host",
    ],
)
def test_r04_missing_or_unrelated_context_does_not_claim_success(case):
    current, session = lateral()
    network, login = current[-2:]
    if case == "no_auth":
        current.pop()
    elif case == "failed_auth":
        login.auth.outcome = "failure"
    elif case == "tuple":
        login.src.port += 1
    elif case == "nat":
        login.src.ip = "192.0.2.99"
    elif case == "domain":
        login.sensor.observation_domain = "other"
    elif case == "expired":
        network.event_time += timedelta(minutes=11)
        login.event_time += timedelta(minutes=11)
    elif case == "no_seed":
        current[3].process.executable = "/usr/sbin/nginx"
    elif case == "weak_target":
        login.user.session_id = None
    elif case == "uncertain":
        login.time_quality.uncertainty_ms = 5000
    else:
        network.dst.asset_id = network.src.asset_id
    sources = detect_process_anomalies(current, session)
    result = detect_remote_access(current, session, sources)
    assert not any(f["kind"] == "remote_access_candidate" for f in result)
