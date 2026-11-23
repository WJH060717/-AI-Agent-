import pytest

from packages.detection.r02 import detect_auth_sequence
from packages.ingest.parsers import parse_record
from tests.integration.d4_helpers import auth_record, context_payload, parse_context, raw_lines


def events(changes=None, uncertainty=0, offset=0):
    records = [auth_record(i) for i in range(5)] + [auth_record(10, "success")]
    if changes:
        changes(records)
    raw = raw_lines(records)
    metadata = context_payload()
    metadata["sensors"][0].update(uncertainty_ms=uncertainty, offset_ms=offset)
    ctx = parse_context("linux_auth", raw, metadata)
    return [parse_record(row, i + 1, ctx) for i, row in enumerate(raw.splitlines())]


def test_r02_positive_is_order_independent_and_tracks_success_failure_evidence():
    candidates = detect_auth_sequence(list(reversed(events())), "session")
    assert len(candidates) == 1
    assert len(candidates[0]["failure_ids"]) == 5 and candidates[0]["success_id"]
    assert len(candidates[0]["evidence_ids"]) == 6
    assert "alice" not in str(candidates)


def test_r02_independent_sensors_do_not_multiply_one_failure():
    current = events()
    failure = current[0]
    observations = []
    for i in range(5):
        observation = failure.model_copy(deep=True)
        observation.event_id = f"{i:064x}"
        observation.sensor.sensor_id = f"sensor-{i}"
        observation.sensor.instance_id = f"collector-{i}"
        observations.append(observation)
    current[-1].sensor = observations[0].sensor.model_copy()
    assert detect_auth_sequence(observations + [current[-1]], "session") == []


@pytest.mark.parametrize(
    "case",
    [
        "account",
        "source",
        "service",
        "target",
        "boot",
        "realm",
        "too_late",
        "before",
        "weak_account",
        "four",
        "uncertain",
    ],
)
def test_r02_does_not_join_unrelated_or_unordered_auth(case):
    current = events(uncertainty=6000 if case == "uncertain" else 0)
    success = current[-1]
    if case == "account":
        success.user.entity_id += "other"
    elif case == "source":
        success.src.ip = "192.0.2.11"
    elif case == "service":
        success.auth.service = "console"
    elif case == "target":
        success.asset_id = "44444444-4444-4444-8444-444444444444"
    elif case == "boot":
        success.host.boot_id = "boot-b"
    elif case == "realm":
        success.user.realm = "other"
    elif case == "weak_account":
        success.user.entity_id = None
    elif case == "too_late":
        from datetime import timedelta

        success.event_time += timedelta(seconds=121)
    elif case == "before":
        success.event_time = current[0].event_time
    elif case == "four":
        current.pop(0)
    assert detect_auth_sequence(current, "session") == []
