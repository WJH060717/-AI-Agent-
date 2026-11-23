import json

from tests.contract.test_d11_evaluation import engineering_config


def test_four_engineering_groups_execute_actual_pipeline_and_recompute(tmp_path):
    from eval.metrics import recompute
    from eval.run import run

    config = engineering_config() | {"model_mode": "protocol_stub"}
    output = tmp_path / "experiment"
    metrics = run(config, output)
    rows = [
        json.loads(line)
        for line in (output / "predictions.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert len(rows) == 4 and all(r["status"] == "completed" for r in rows), [
        (r["group"], r["status"], r["error"]) for r in rows
    ]
    by_group = {r["group"]: r for r in rows}
    assert by_group["B0"]["usage"] == {} and by_group["B0"]["reports"] == []
    assert by_group["B1"]["usage"]["model_calls"] == 0
    assert by_group["B2"]["usage"]["model_calls"] == len(by_group["B2"]["reports"]) > 0
    assert by_group["B2"]["usage"]["tool_calls"] == 0
    assert by_group["B3"]["usage"]["tool_calls"] >= 2
    assert by_group["B2"]["mode"] == by_group["B3"]["mode"] == "protocol_test_stub"
    assert all(r["references_valid"] == r["references_total"] for r in rows)
    assert by_group["B1"]["references_total"] > 0
    assert metrics == recompute(output)
    assert metrics["formal_metrics_available"] is False
    assert all(g["detection_f1_macro"] is None for g in metrics["groups"].values())
    # D12: single-investigation timing includes create, queue wait and completion;
    # usage is recorded even when no report is returned.
    for group in ("B1", "B2", "B3"):
        assert by_group[group]["investigations"]
        assert all(
            i["elapsed_ms"] > 0 and i["status"] == "completed"
            for i in by_group[group]["investigations"]
        )


def test_separate_evaluation_runs_do_not_reuse_workspace_import_idempotency_keys(tmp_path):
    from copy import deepcopy

    from eval.run import run

    config = engineering_config()
    second = deepcopy(config["runs"][0])
    second["run_id"] = "engineering-second"
    config["runs"].append(second)
    result = run(config, tmp_path / "two-runs")
    assert result["statuses"] == {"completed": 4, "blocked": 4}
