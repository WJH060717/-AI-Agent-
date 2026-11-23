"""Offline synthetic scale check; imports test fixtures, never used by app/worker."""

import argparse
import hashlib
import json
import time
from datetime import UTC, datetime
from pathlib import Path

from packages.detection.limits import DetectionBudget
from packages.detection.registry import detect_all
from scripts.benchmark_d11 import runtime_files
from tests.contract.test_d7_rules import connections
from tests.contract.test_p1_scale import mixed_events


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    assert not args.output.exists()
    sources = runtime_files()
    events, session, tail = mixed_events(100000)
    start = time.perf_counter()
    with DetectionBudget() as budget:
        found = detect_all(events, session)
    elapsed = time.perf_counter() - start
    expected = detect_all(tail, session)
    assert found == expected
    assert {f["rule_id"] for f in found} == {f"R0{i}" for i in range(1, 7)}
    del events
    dense, session = connections([i / 50 for i in range(100000)])
    start = time.perf_counter()
    with DetectionBudget() as dense_budget:
        dense_findings = detect_all(dense, session)
    dense_elapsed = time.perf_counter() - start
    periodic = [f for f in dense_findings if f["rule_id"] == "R05"]
    assert {eid for f in periodic for eid in f["evidence_ids"]} == {e.event_id for e in dense}
    result = {
        "created_at": datetime.now(UTC).isoformat(),
        "events": 100000,
        "synthetic_engineering_only": True,
        "formal_evaluation": False,
        "mixed_seconds": elapsed,
        "mixed_work": budget.work,
        "mixed_rules": sorted({f["rule_id"] for f in found}),
        "tail_reference_findings_equal": True,
        "dense_seconds": dense_elapsed,
        "dense_work": dense_budget.work,
        "dense_periodic_findings": len(periodic),
        "dense_all_members_covered": True,
        "runtime_files": sources,
        "runtime_unchanged": runtime_files() == sources,
        "fixture_sha256": hashlib.sha256(
            Path("tests/contract/test_p1_scale.py").read_bytes()
        ).hexdigest(),
    }
    assert result["runtime_unchanged"]
    args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps({k: v for k, v in result.items() if k != "runtime_files"}, indent=2))


if __name__ == "__main__":
    main()
