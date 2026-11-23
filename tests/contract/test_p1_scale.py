import hashlib
import random
from datetime import timedelta

import pytest

from packages.config import Settings
from packages.detection.r05 import _qualifying_windows, config, detect_periodic
from tests.contract.p1_scale_reference import legacy_windows
from tests.contract.test_d7_rules import connections


def mixed_events(count=10025):
    """Synthetic engineering fixture. Never imported by the runtime detector."""
    from tests.contract.test_d6_rules import lateral

    signal, session = lateral()
    periodic, _ = connections(amount=6_000_000)
    for e in periodic:
        e.workspace_id, e.dataset_id = signal[0].workspace_id, signal[0].dataset_id
    signal += periodic
    for i in range(24):
        e = signal[0].model_copy(deep=True)
        e.event_id = hashlib.sha256(f"scale-scan-{i}".encode()).hexdigest()
        e.dst.port = 1000 + i
        signal.append(e)
    for i in range(5):
        e = signal[1].model_copy(deep=True)
        e.event_id = hashlib.sha256(f"scale-auth-{i}".encode()).hexdigest()
        e.event_time -= timedelta(seconds=20 - i * 2)
        e.auth.outcome = "failure"
        signal.append(e)
    filler = []
    for i in range(count - len(signal)):
        e = signal[2].model_copy(deep=True)
        e.event_id = hashlib.sha256(f"scale-benign-{i}".encode()).hexdigest()
        e.event_time -= timedelta(days=1, seconds=i)
        e.process.executable = "/usr/bin/true"
        e.process.entity_id = f"process:{i}"
        filler.append(e)
    return filler + signal, session, signal


def test_all_six_rules_include_tail_evidence_over_10000():
    from packages.detection.limits import DetectionBudget
    from packages.detection.registry import detect_all, reproduce

    events, session, signal = mixed_events(10100)
    with DetectionBudget():
        result = detect_all(events, session)
    expected = detect_all(signal, session)
    assert {f["rule_id"] for f in result} == {f"R0{i}" for i in range(1, 7)}
    assert result == expected
    assert all(set(f["evidence_ids"]).issubset({e.event_id for e in signal}) for f in result)
    for f in result:
        assert f["id"] in {r["id"] for r in reproduce(events, session, f)}


def test_full_scope_default_and_maximum():
    assert Settings(_env_file=None).detection_event_limit == 100000
    assert Settings(_env_file=None, detection_event_limit=100000).detection_event_limit == 100000


def test_dense_periodic_12001_uses_bounded_work():
    from packages.detection.limits import DetectionBudget

    events, session = connections([i / 10 for i in range(12001)])
    with DetectionBudget(work_limit=100000):
        result = detect_periodic(events, session)
    assert result and len(result[0]["evidence_ids"]) == 12001
    assert events[-1].event_id in result[0]["evidence_ids"]


@pytest.mark.parametrize("seed", range(12))
def test_periodic_prefix_matches_legacy_contiguous_windows(seed):
    rng = random.Random(seed)
    times = [0.0]
    for _ in range(110):
        times.append(times[-1] + rng.choice([0, 3, 10, 38, 40, 42, 60, 220]))
    events, _ = connections(times)
    for e in events:
        e.time_quality.uncertainty_ms = rng.choice([0, 1, 20, 1000])
    actual, expected = _qualifying_windows(events, config()), legacy_windows(events, config())
    assert [(a, b) for a, b, _ in actual] == [(a, b) for a, b, _ in expected]
    for (_, _, a), (_, _, b) in zip(actual, expected, strict=True):
        assert a == pytest.approx(b, abs=1e-10)


def test_work_budget_stops_adversarial_irregular_windows():
    from packages.detection.limits import DetectionBudget, DetectionLimit

    events, session = connections([i * 0.1 + (i // 2) * 2 for i in range(2000)])
    with pytest.raises(DetectionLimit), DetectionBudget(work_limit=1000):
        detect_periodic(events, session)
