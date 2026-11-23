import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest


def test_d11_gate_keeps_formal_gaps_and_requires_actual_experiments():
    from scripts.d10_gate import required_checks, validate_acceptance

    root = Path(__file__).resolve().parents[2]
    cases, defects = validate_acceptance(root, stage="d11")
    assert {c.id for c in cases if c.scope != "implemented"} == {
        "TC-021",
        "TC-036",
        "TC-037",
        "TC-038",
        "TC-039",
        "TC-040",
    }
    assert sum(d.state == "open" for d in defects) == 7
    assert {"evaluation", "evaluation_verify", "benchmark", "browser_d11"} <= required_checks("d11")
    assert "benchmark" not in required_checks("d10")


def test_benchmark_verification_rejects_smoke_and_changed_samples(tmp_path):
    from scripts.d11_evidence import verify_benchmark

    (tmp_path / "protocol.json").write_text(json.dumps({"profile": "smoke"}))
    (tmp_path / "summary.json").write_text("{}")
    (tmp_path / "samples.jsonl").write_text("")
    with pytest.raises(ValueError, match="FULL_PROTOCOL_REQUIRED"):
        verify_benchmark(tmp_path)


def test_evaluation_verification_rejects_missing_or_changed_outputs(tmp_path):
    from scripts.d11_evidence import verify_evaluation

    with pytest.raises(OSError):
        verify_evaluation(tmp_path)


def test_success_label_without_bound_experiment_files_is_rejected(tmp_path):
    from scripts.d10_gate import GateError, check_experiments, check_record, record_check

    log = tmp_path / "check.log"
    log.write_text("success")
    record = record_check(
        "benchmark", ["python", "benchmark"], 0, log, "a" * 64, "2026-11-15T00:00:00+00:00"
    )
    with pytest.raises(GateError, match="EXPERIMENT_OUTPUT_UNBOUND"):
        check_experiments([check_record(record, "a" * 64)])


@pytest.fixture
def benchmark_result(tmp_path, monkeypatch):
    from scripts import d11_evidence
    from scripts.benchmark_d11 import BENCHMARK_CONFIG, records, summarize
    from scripts.release_manifest import encoded

    protocol = {
        "profile": "full",
        "batch_records": 500,
        "batch_interval_seconds": 10.0,
        "scheduled_batches": 180,
        "duration_seconds": 1800.0,
        "query_target_events": 100000,
        "query_requests": 100,
        "runtime_files": {"unit": "test-only"},
        "effective_settings": BENCHMARK_CONFIG,
    }
    monkeypatch.setattr(d11_evidence, "runtime_files", lambda: {"unit": "test-only"})
    rows = []
    start = datetime(2026, 11, 15, tzinfo=UTC)
    for index in range(200):
        phase = "ingest" if index < 180 else "query_preload"
        if index < 180:
            rows += [
                {
                    "kind": "schedule",
                    "index": index,
                    "recorded_at": (start + timedelta(seconds=index * 10)).isoformat(),
                },
                {"kind": "resources", "status": "measured", "processes": [{"WorkingSet64": 10}]},
            ]
        rows += [
            {
                "kind": "upload",
                "phase": phase,
                "index": index,
                "offset": index * 500,
                "expected": 500,
                "sha256": hashlib.sha256(records(index * 500, 500)).hexdigest(),
                "status": 202,
            },
            {
                "kind": "batch",
                "phase": phase,
                "index": index,
                "expected": 500,
                "status": "partial",
                "accepted": 500,
                "raw_records": 500,
                "duplicate": 0,
                "quarantined": 0,
                "error_code": "RULE_SCOPE_TOO_LARGE",
            },
        ]
    rows += [{"kind": "query", "status": 200, "elapsed_ms": 1} for _ in range(100)]
    raw = b"\n".join(json.dumps(row).encode() for row in rows)
    summary = summarize(
        rows, profile="full", final_count=100000, drain_seconds=1, duration_seconds=1800
    )
    summary.update(
        errors=[], runtime_unchanged=True, samples_sha256=hashlib.sha256(raw).hexdigest()
    )
    (tmp_path / "protocol.json").write_bytes(encoded(protocol))
    (tmp_path / "summary.json").write_bytes(encoded(summary))
    (tmp_path / "samples.jsonl").write_bytes(raw)
    return tmp_path


@pytest.mark.parametrize(
    "change",
    ["none", "sample_bytes", "runtime", "resource_gap", "duplicate_fragment", "query_failure"],
)
def test_benchmark_bound_records_and_negative_cases(benchmark_result, change, monkeypatch):
    from scripts import d11_evidence
    from scripts.release_manifest import encoded

    folder = benchmark_result
    if change == "none":
        assert d11_evidence.verify_benchmark(folder)["resource_samples"] == 180
        return
    if change == "runtime":
        monkeypatch.setattr(d11_evidence, "runtime_files", lambda: {"different": "source"})
    else:
        samples = folder / "samples.jsonl"
        rows = [json.loads(line) for line in samples.read_bytes().splitlines()]
        if change == "resource_gap":
            rows = [r for r in rows if r["kind"] != "resources"]
        elif change == "duplicate_fragment":
            next(r for r in rows if r["kind"] == "upload")["sha256"] = "0" * 64
        elif change == "query_failure":
            next(r for r in rows if r["kind"] == "query")["status"] = 429
        raw = b"\n".join(json.dumps(row).encode() for row in rows) + b"\n"
        samples.write_bytes(raw)
        if change != "sample_bytes":
            summary = json.loads((folder / "summary.json").read_bytes())
            summary["samples_sha256"] = hashlib.sha256(raw).hexdigest()
            (folder / "summary.json").write_bytes(encoded(summary))
    with pytest.raises(ValueError):
        d11_evidence.verify_benchmark(folder)
