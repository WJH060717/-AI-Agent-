import copy
import json
from pathlib import Path

import pytest


def test_freeze_is_reproducible_and_does_not_promote_plans_to_reviewed_runs():
    from eval.freeze import build_freeze, verify_freeze

    root = Path(__file__).resolve().parents[2]
    frozen = build_freeze(root)
    assert frozen["readiness"]["planned"] == 33
    assert frozen["readiness"]["reviewed_runs"] == 0
    assert frozen["readiness"]["data_collection_complete"] is False
    assert len(frozen["readiness"]["pending_run_ids"]) == 36
    assert verify_freeze(root, frozen) == frozen["readiness"]
    changed = copy.deepcopy(frozen)
    changed["manifest_hash"] = "0" * 64
    with pytest.raises(ValueError, match="INVENTORY_FREEZE_DRIFT"):
        verify_freeze(root, changed)


def test_dossier_cannot_claim_review_without_two_distinct_reviewers_and_inputs(tmp_path):
    from eval.freeze import validate_dossiers

    manifest = {"runs": [{"run_id": "planned", "status": "planned", "objects": []}]}
    bad = {
        "version": "1.0.0",
        "runs": [
            {
                "run_id": "planned",
                "truth": None,
                "reviewers": [
                    {"actor": "same", "truth_hash": "a" * 64},
                    {"actor": "same", "truth_hash": "a" * 64},
                ],
            }
        ],
    }
    with pytest.raises(ValueError):
        validate_dossiers(tmp_path, manifest, bad)
    assert not list(tmp_path.iterdir())


def test_frozen_inventory_artifact_exists_and_matches_current_inputs():
    from eval.freeze import verify_freeze

    root = Path(__file__).resolve().parents[2]
    result = verify_freeze(root, json.loads((root / "eval/freeze-d9.json").read_bytes()))
    assert not result["formal_test_executed"]
