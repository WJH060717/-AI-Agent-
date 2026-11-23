import hashlib
from datetime import timedelta
from uuid import UUID

import pytest

from packages.contracts.context import EgressBaseline
from packages.detection.r05 import detect_periodic
from packages.detection.r06 import detect_egress
from packages.detection.registry import reproduce
from tests.contract.test_d5_paths import chain


def connections(offsets=None, amount=100):
    current, scope = chain()
    template = current[0]
    events = []
    for i, second in enumerate(offsets if offsets is not None else range(10, 431, 60)):
        event = template.model_copy(deep=True)
        event.event_id = hashlib.sha256(f"d7-{i}".encode()).hexdigest()
        event.event_time = template.event_time.replace(minute=0, second=0) + timedelta(
            seconds=second
        )
        event.src, event.dst = event.dst, event.src
        event.src.port, event.dst.port = 40000 + i, 443
        event.network.bytes_out, event.network.bytes_in = amount, 50
        event.time_quality.uncertainty_ms = 0
        events.append(event)
    return events, str(scope.session_id)


def baseline(event, count=30, amount=1_000_000):
    end = event.event_time.replace(minute=0, second=0) - timedelta(hours=1)
    return EgressBaseline.model_validate(
        {
            "id": "normal-dev-v1",
            "version": "1.0.0",
            "asset_id": str(event.src.asset_id),
            "sensor_id": event.sensor.sensor_id,
            "instance_id": event.sensor.instance_id,
            "observation_domain": event.sensor.observation_domain,
            "provenance_type": "synthetic",
            "source_sha256": "a" * 64,
            "samples": [
                {
                    "start": (end - timedelta(seconds=300 * (i + 1))).isoformat(),
                    "end": (end - timedelta(seconds=300 * i)).isoformat(),
                    "bytes_out": amount,
                }
                for i in range(count)
            ],
        }
    )


def test_r05_periodic_duplicate_order_and_frozen_reproduction():
    events, session = connections()
    result = detect_periodic(events, session)
    assert len(result) == 1
    item = result[0]
    assert item["kind"] == "periodic_connection" and item["statistics"]["count"] == 8
    assert item["statistics"]["cv_upper"] == 0 and item["statistics"]["span_seconds"] == 420
    assert "心跳" in item["interpretation"] and "C2" in item["interpretation"]
    assert detect_periodic(list(reversed(events)) + events, session) == result
    assert any(f["id"] == item["id"] for f in reproduce(events, session, item))


@pytest.mark.parametrize(
    "case",
    ["few", "short", "jitter", "uncertain", "channel", "domain", "asset", "target", "ambiguous"],
)
def test_r05_below_threshold_or_scope_split_is_not_periodic(case):
    events, session = connections()
    if case == "few":
        events.pop()
    elif case == "short":
        events, session = connections(range(10, 81, 10))
    elif case == "jitter":
        events, session = connections([10, 15, 30, 90, 95, 270, 350, 430])
    elif case == "uncertain":
        for event in events:
            event.time_quality.uncertainty_ms = 6000
    elif case == "channel":
        events[-1].sensor.instance_id = "another-channel"
    elif case == "domain":
        events[-1].sensor.observation_domain = "another-domain"
    elif case == "asset":
        events[-1].src.asset_id = UUID("44444444-4444-4444-8444-444444444444")
    elif case == "target":
        events[-1].dst.port = 8443
    else:
        events[-1].src.asset_id = None
        events[-1].src.resolution_quality = "ambiguous"
    assert detect_periodic(events, session) == []


def test_r05_sliding_window_can_cross_wallclock_bucket_and_clock_error_is_visible():
    events, session = connections(range(800, 1221, 60))
    for event in events:
        event.time_quality.uncertainty_ms = 1000
    result = detect_periodic(events, session)
    assert result and 0 < result[0]["statistics"]["cv_upper"] < 0.15


def test_r06_known_baseline_anomaly_and_missing_baseline_signal_reproduce():
    events, session = connections([10, 20], amount=6_000_000)
    normal = baseline(events[0])
    item = detect_egress(events, session, baselines=[normal])[0]
    assert item["kind"] == "outbound_volume_anomaly"
    assert item["statistics"]["bytes_out"] == 12_000_000
    assert item["statistics"]["p95_bytes"] == 1_000_000
    assert item["baseline"]["source_sha256"] == "a" * 64
    assert any(f["id"] == item["id"] for f in reproduce(events, session, item))
    fixed = detect_egress(events, session)[0]
    assert (
        fixed["kind"] == "fixed_threshold_signal" and fixed["statistics"]["baseline_windows"] == 0
    )
    assert "基线不足" in fixed["interpretation"]
    assert (
        detect_egress(events, session, baselines=[baseline(events[0], 29)])[0]["kind"]
        == "fixed_threshold_signal"
    )
    assert detect_egress(events, session, baselines=[baseline(events[0], amount=8_000_000)]) == []


@pytest.mark.parametrize(
    "case",
    [
        "below",
        "ratio_equal",
        "response",
        "unknown",
        "ambiguous",
        "channel",
        "bucket",
        "future_baseline",
        "wrong_baseline",
    ],
)
def test_r06_boundary_direction_and_baseline_scope(case):
    events, session = connections([10, 20], amount=6_000_000)
    normal = baseline(events[0])
    if case == "below":
        events[0].network.bytes_out = 3_000_000
    elif case == "ratio_equal":
        normal = baseline(events[0], amount=4_000_000)
    elif case == "response":
        for e in events:
            e.network.bytes_out, e.network.bytes_in = 10, 50_000_000
    elif case in {"unknown", "ambiguous"}:
        for e in events:
            e.src.asset_id = None
            e.src.resolution_quality = case
    elif case == "channel":
        events[-1].sensor.instance_id = "independent"
    elif case == "bucket":
        events[-1].event_time += timedelta(seconds=300)
    elif case == "future_baseline":
        for s in normal.samples:
            s.start += timedelta(days=1)
            s.end += timedelta(days=1)
    else:
        normal.asset_id = UUID("44444444-4444-4444-8444-444444444444")
    result = detect_egress(events, session, baselines=[normal])
    if case in {"future_baseline", "wrong_baseline"}:
        assert result[0]["kind"] == "fixed_threshold_signal"
    else:
        assert result == []


def test_r06_nearest_rank_p95_not_average_and_threshold_is_inclusive():
    events, session = connections([10], amount=10_000_000)
    normal = baseline(events[0])
    normal.samples[0].bytes_out = 100_000_000
    item = detect_egress(events, session, baselines=[normal])[0]
    assert item["statistics"]["p95_bytes"] == 1_000_000
    assert item["statistics"]["bytes_out"] == 10_000_000


def test_r06_finding_identity_binds_frozen_baseline_not_only_rule_and_event_ids():
    events, session = connections([10, 20], amount=6_000_000)
    low = detect_egress(events, session, baselines=[baseline(events[0])])[0]
    changed = detect_egress(events, session, baselines=[baseline(events[0], amount=2_000_000)])[0]
    assert low["id"] != changed["id"]
    assert low["baseline_hash"] != changed["baseline_hash"]


def test_r06_three_times_baseline_uses_exact_integer_boundary():
    p95 = 9_007_199_254_740_993
    events, session = connections([10], amount=3 * p95)
    reference = baseline(events[0], amount=p95)
    assert detect_egress(events, session, baselines=[reference]) == []
    events[0].network.bytes_out += 1
    assert (
        detect_egress(events, session, baselines=[reference])[0]["kind"]
        == "outbound_volume_anomaly"
    )


@pytest.mark.parametrize("prefix", [[0], [100]])
def test_r05_earlier_noise_or_tie_does_not_hide_later_valid_contiguous_segment(prefix):
    events, session = connections(prefix + list(range(100, 521, 60)))
    result = detect_periodic(events, session)
    assert result and result[0]["statistics"]["cv_upper"] == 0
    assert result[0]["statistics"]["count"] == 8


def test_r05_must_not_remove_internal_irregular_events_to_manufacture_periodicity():
    events, session = connections([100, 160, 190, 220, 280, 340, 400, 460, 520])
    assert detect_periodic(events, session) == []


def test_r05_continuous_overlapping_windows_merge_with_auditable_bounded_witnesses():
    events, session = connections(range(10, 1791, 20))
    findings = detect_periodic(events, session)
    assert len(findings) == 1
    item = findings[0]
    assert len(item["evidence_ids"]) == 90 and item["statistics"]["span_seconds"] == 1780
    assert item["statistics"]["cv_semantics"] == "merged_episode_summary"
    assert all(
        w["span_seconds"] <= 1200 and w["cv_upper"] <= 0.15 for w in item["qualifying_windows"]
    )
    assert len(item["qualifying_windows"]) == 2
    assert any(f["id"] == item["id"] for f in reproduce(events, session, item))
    from packages.agent.assessment import assess, policy

    _, scope = chain()
    scope.workspace_id, scope.dataset_id = events[0].workspace_id, events[0].dataset_id
    scope.session_id = UUID(session)
    scope.start = events[0].event_time - timedelta(seconds=10)
    scope.end = events[-1].event_time + timedelta(seconds=10)
    assessment = assess(events, scope, findings, {e.event_id for e in events}, policy())
    assert len(assessment.hypotheses) == 1 and not assessment.truncated


def test_r05_merged_episode_cv_is_not_misrepresented_as_a_single_qualifying_window():
    events, session = connections(
        [10 + 60 * i for i in range(8)] + [430 + 90 * i for i in range(1, 9)]
    )
    item = detect_periodic(events, session)[0]
    assert len(detect_periodic(events, session)) == 1
    assert item["statistics"]["cv"] > 0.15
    assert all(w["cv_upper"] <= 0.15 for w in item["qualifying_windows"])
