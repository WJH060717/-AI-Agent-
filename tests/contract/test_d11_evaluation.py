import copy
import hashlib
import json
from pathlib import Path

import pytest


def engineering_config():
    root = Path(__file__).resolve().parents[2]

    def obj(name):
        return {"path": name, "sha256": hashlib.sha256((root / name).read_bytes()).hexdigest()}

    return {
        "version": "d11-evaluation@1.0.0",
        "profile": "engineering",
        "model_mode": "disabled",
        "runs": [
            {
                "run_id": "engineering-s2",
                "scenario_id": "S2",
                "context": obj("data/fixtures/d9/S2/context.json"),
                "sources": [
                    {
                        "source_type": "zeek",
                        "sensor_id": "net-a",
                        "object": obj("data/fixtures/d9/S2/network.jsonl"),
                    }
                ],
            }
        ],
    }


def test_preflight_binds_engineering_inputs_and_rejects_label_paths_or_drift():
    from eval.validate_manifest import validate

    root = Path(__file__).resolve().parents[2]
    config = engineering_config()
    assert validate(config, root)["formal_ready"] is False
    bad = copy.deepcopy(config)
    bad["runs"][0]["sources"][0]["object"]["path"] = "eval/ground_truth/private.json"
    with pytest.raises(ValueError):
        validate(bad, root)
    bad = copy.deepcopy(config)
    bad["runs"][0]["sources"][0]["object"]["sha256"] = "0" * 64
    with pytest.raises(ValueError):
        validate(bad, root)


def test_formal_execution_refuses_planned_unreviewed_runs_before_creating_output(tmp_path):
    from eval.run import run

    config = engineering_config() | {"profile": "formal", "model_mode": "configured", "repeats": 3}
    output = tmp_path / "must-not-exist"
    with pytest.raises(ValueError, match="DATA_AND_LABELS_NOT_READY"):
        run(config, output)
    assert not output.exists()


def test_metrics_recompute_rejects_prediction_tampering_and_missing_groups(tmp_path):
    from eval.metrics import recompute

    rows = [{"run_id": "r", "group": "B0", "repeat": 0, "status": "completed", "elapsed_ms": 1}]
    raw = (json.dumps(rows[0]) + "\n").encode()
    (tmp_path / "predictions.jsonl").write_bytes(raw)
    manifest = {
        "profile": "engineering",
        "run_ids": ["r"],
        "groups": ["B0", "B1"],
        "repeats": 1,
        "predictions_sha256": hashlib.sha256(raw).hexdigest(),
    }
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="MISSING_EXECUTION"):
        recompute(tmp_path)
    (tmp_path / "predictions.jsonl").write_bytes(raw + b" ")
    with pytest.raises(ValueError, match="HASH_MISMATCH"):
        recompute(tmp_path)
