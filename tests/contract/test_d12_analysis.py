import json

import pytest

from eval.analysis_d12 import execution_summary, load_inputs, resource_series


def row(status="completed", elapsed=10, **kwargs):
    return dict(
        run_id="r",
        group="B3",
        repeat=0,
        status=status,
        elapsed_ms=elapsed,
        mode="protocol_test_stub",
        **kwargs,
    )


def test_failures_unknown_cost_and_zero_denominators_are_preserved():
    records = [row(), row("failed", 90, error="TIMEOUT"), row("partial", 30), row("blocked", 0)]
    result = execution_summary(records)
    assert result["attempts"] == 4
    assert result["noncompletion"] == {"n": 3, "N": 4, "rate": 0.75}
    assert result["elapsed_ms"]["p95"] == 90
    assert result["timeout"] == {"n": 1, "N": 4, "rate": 0.25}
    assert result["provider_billed_usd"] is None
    assert result["usage"]["input_tokens"] is None
    empty = execution_summary([])
    assert empty["noncompletion"]["rate"] is None
    assert empty["elapsed_ms"]["p95"] is None


def test_budget_estimates_do_not_become_provider_bills():
    result = execution_summary(
        [
            row(
                usage={
                    "input_tokens": 100,
                    "output_tokens": 5,
                    "cost_microusd": 99,
                    "actual_cost_microusd": 8,
                }
            )
        ]
    )
    assert result["usage"]["cost_microusd"] == 99
    assert result["usage"]["actual_cost_microusd"] == 8
    assert result["provider_billed_usd"] is None


def test_legacy_unmeasured_import_failure_is_not_zero_latency():
    result = execution_summary([row(), row("failed", 0, error="IDEMPOTENCY_CONFLICT")])
    assert result["attempts"] == 2 and result["noncompletion"]["n"] == 1
    assert result["elapsed_ms"]["unmeasured_attempts"] == 1
    assert result["elapsed_ms"]["values"] == [10]
    assert result["elapsed_ms"]["all_attempts_p95"] is None


def test_resources_use_process_cpu_deltas_and_mark_restarts_unknown():
    samples = [
        dict(
            kind="resources",
            recorded_at=f"2026-11-15T00:00:{sec:02d}+00:00",
            status="measured",
            processes=[dict(Id=pid, CPU=cpu, WorkingSet64=1000, PrivateMemorySize64=2000)],
        )
        for sec, pid, cpu in [(0, 1, 2), (10, 1, 7), (20, 2, 1)]
    ]
    series = resource_series(samples)
    assert series[0]["cpu_cores"] is None
    assert series[1]["cpu_cores"] == 0.5
    assert series[2]["cpu_cores"] is None
    assert series[1]["working_set_bytes"] == 1000


def test_unknown_resources_remain_null_and_are_not_drawn_as_zero():
    from eval.analysis_d12 import chart

    points = resource_series(
        [
            dict(
                kind="resources",
                recorded_at="2026-11-15T00:00:00+00:00",
                status="unsupported_platform",
                processes=[],
            )
        ]
    )
    drawing = chart({"benchmarks": [{"id": "unmeasured", "resource_series": points}]}).decode()
    assert "unavailable" in drawing and "peak 1.00" not in drawing


def test_resource_chart_does_not_bridge_unknown_points():
    from eval.analysis_d12 import chart

    points = [
        dict(working_set_bytes=m, cpu_cores=c) for m, c in [(1000, 0.1), (None, None), (2000, 0.2)]
    ]
    drawing = chart({"benchmarks": [{"id": "gaps", "resource_series": points}]}).decode()
    assert drawing.count("<polyline") == 4


def test_manifest_rejects_changed_missing_or_outside_inputs(tmp_path):
    file = tmp_path / "records.json"
    file.write_text("[]", encoding="utf-8")
    import hashlib

    config = {
        "version": "d12-analysis-inputs@1.0.0",
        "files": {"records.json": hashlib.sha256(file.read_bytes()).hexdigest()},
        "evaluations": [],
        "benchmarks": [],
        "screenshots": [],
    }
    path = tmp_path / "inputs.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    assert load_inputs(tmp_path, path)["files"]
    file.write_text("[1]", encoding="utf-8")
    with pytest.raises(ValueError, match="INPUT_INTEGRITY"):
        load_inputs(tmp_path, path)
    config["files"] = {"../outside": "0" * 64}
    path.write_text(json.dumps(config), encoding="utf-8")
    with pytest.raises(ValueError, match="PATH"):
        load_inputs(tmp_path, path)
