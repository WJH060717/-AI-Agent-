"""Synthetic unit metadata and a stub executor test freeze integrity, not formal performance."""

import hashlib
import json
import shutil
from pathlib import Path

import pytest

from scripts.release_manifest import encoded


@pytest.fixture
def formal_inputs(tmp_path):
    from eval.freeze import build_freeze

    root = tmp_path / "unit-root"
    for folder in ("eval/ground_truth", "data/unit", "infra"):
        (root / folder).mkdir(parents=True)
    shutil.copytree(Path(__file__).resolve().parents[2] / "rules", root / "rules")
    runs, dossiers, selected = [], [], []
    for split, count in (("dev", 12), ("val", 6), ("test", 12), ("demo", 3)):
        for i in range(count):
            key = f"unit-{split}-{i}"
            raw = encoded({"unit_fixture": key})
            obj = {"path": f"data/unit/{key}.json", "sha256": hashlib.sha256(raw).hexdigest()}
            (root / obj["path"]).write_bytes(raw)
            scenario = f"S{i % 3 + 1}"
            runs.append(
                {
                    "run_id": key,
                    "split": split,
                    "scenario_id": scenario,
                    "seed": i,
                    "activity_group": key,
                    "status": "prepared",
                    "provenance_type": "synthetic",
                    "authorized_scope": "Unit test metadata only; not actual collected evidence",
                    "objects": [obj],
                }
            )
            truth = encoded(
                {
                    "run_id": key,
                    "ground_truth_steps": [],
                    "ground_truth_edges": [],
                    "activities": [],
                    "observable_origins": [],
                    "left_censored": False,
                }
            )
            ref = {
                "path": f"eval/ground_truth/{key}.json",
                "sha256": hashlib.sha256(truth).hexdigest(),
            }
            (root / ref["path"]).write_bytes(truth)
            dossiers.append(
                {
                    "run_id": key,
                    "truth": ref,
                    "reviewers": [
                        {"actor": f"unit-fixture-{person}", "truth_hash": ref["sha256"]}
                        for person in ("a", "b")
                    ],
                }
            )
            if split == "test":
                selected.append(
                    {
                        "run_id": key,
                        "scenario_id": scenario,
                        "provenance_type": "synthetic",
                        "sources": [{"source_type": "zeek", "sensor_id": "unit", "object": obj}],
                    }
                )
    (root / "eval/runs.json").write_bytes(encoded({"version": "1.0.0", "runs": runs}))
    (root / "eval/dossiers.json").write_bytes(encoded({"version": "1.0.0", "runs": dossiers}))
    (root / "infra/release-inputs.json").write_text('{"files":{}}')
    (root / "eval/freeze-d9.json").write_bytes(encoded(build_freeze(root)))
    return root, {
        "version": "d11-evaluation@1.0.0",
        "profile": "formal",
        "model_mode": "configured",
        "repeats": 3,
        "runs": selected,
    }


@pytest.mark.parametrize("change", ["none", "new_reviewed_freeze", "truth_bytes"])
def test_formal_predictions_cannot_switch_to_new_labels_midrun(
    formal_inputs, tmp_path, monkeypatch, change
):
    import eval.run as module
    from eval.freeze import build_freeze

    root, config = formal_inputs
    monkeypatch.setattr(module, "versions", lambda _: {"unit_executor": "not-real-model"})

    def execute(value, root, emit):
        for run in value.runs:
            for group in value.groups:
                for repeat in range(value.repeats):
                    emit(
                        {
                            "run_id": run.run_id,
                            "group": group,
                            "repeat": repeat,
                            "status": "completed",
                            "elapsed_ms": 0,
                        }
                    )
        if change != "none":
            path = root / "eval/ground_truth/unit-test-0.json"
            truth = json.loads(path.read_bytes()) | {"left_censored": True}
            path.write_bytes(encoded(truth))
            if change == "new_reviewed_freeze":
                dossiers = json.loads((root / "eval/dossiers.json").read_bytes())
                item = next(d for d in dossiers["runs"] if d["run_id"] == "unit-test-0")
                item["truth"]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
                for reviewer in item["reviewers"]:
                    reviewer["truth_hash"] = item["truth"]["sha256"]
                (root / "eval/dossiers.json").write_bytes(encoded(dossiers))
                (root / "eval/freeze-d9.json").write_bytes(encoded(build_freeze(root)))

    monkeypatch.setattr(module, "execute", execute)
    output = tmp_path / "result"
    if change == "none":
        result = module.run(config, output, root)
        assert result["executions"] == 144 and result["formal_metrics_available"]
    else:
        with pytest.raises(ValueError, match="EVALUATION_INPUT_DRIFT"):
            module.run(config, output, root)
        assert len((output / "predictions.jsonl").read_text().splitlines()) == 144
        assert not (output / "metrics.json").exists()
        assert (
            json.loads((output / "failure.json").read_bytes())["code"] == "EVALUATION_INPUT_DRIFT"
        )


@pytest.mark.parametrize("change", ["missing_run", "shared_group", "wrong_scenario"])
def test_formal_test_set_requires_twelve_independent_balanced_runs(formal_inputs, change):
    from eval.freeze import build_freeze
    from eval.validate_manifest import validate

    root, config = formal_inputs
    inventory = json.loads((root / "eval/runs.json").read_bytes())
    dossiers = json.loads((root / "eval/dossiers.json").read_bytes())
    if change == "missing_run":
        inventory["runs"] = [r for r in inventory["runs"] if r["run_id"] != "unit-test-0"]
        dossiers["runs"] = [r for r in dossiers["runs"] if r["run_id"] != "unit-test-0"]
        config["runs"] = [r for r in config["runs"] if r["run_id"] != "unit-test-0"]
    elif change == "shared_group":
        next(r for r in inventory["runs"] if r["run_id"] == "unit-test-1")["activity_group"] = (
            "unit-test-0"
        )
    else:
        config["runs"][0]["scenario_id"] = "S2"
    (root / "eval/runs.json").write_bytes(encoded(inventory))
    (root / "eval/dossiers.json").write_bytes(encoded(dossiers))
    (root / "eval/freeze-d9.json").write_bytes(encoded(build_freeze(root)))
    with pytest.raises(ValueError, match="FORMAL_TEST"):
        validate(config, root)
