import hashlib
import json
from pathlib import Path

import pytest


def record(run_id="a", split="dev", parent=None, group="g"):
    return {
        "run_id": run_id,
        "split": split,
        "scenario_id": "S1",
        "seed": 1,
        "activity_group": group,
        "parent_run_id": parent,
        "status": "planned",
        "provenance_type": "synthetic",
        "authorized_scope": "local synthetic only",
        "objects": [],
    }


def test_split_audit_accepts_plans_but_never_counts_them_as_completed(tmp_path):
    from eval.inventory import audit_inventory

    result = audit_inventory(
        {"version": "1.0.0", "runs": [record(), record("b", parent="a")]}, tmp_path
    )
    assert result["planned"] == 2 and result["prepared"] == 0
    assert result["independent_groups"] == 1
    assert result["formal_test_executed"] is False


@pytest.mark.parametrize(
    "case",
    [
        "parent_split",
        "group_split",
        "missing_parent",
        "cycle",
        "duplicate_id",
        "hash_leak",
        "escape",
        "tampered",
        "empty_prepared",
    ],
)
def test_inventory_rejects_leaks_and_invalid_provenance(tmp_path, case):
    from eval.inventory import InventoryError, audit_inventory

    runs = [record(), record("b", parent="a")]
    if case == "parent_split":
        runs[1].update(split="test", activity_group="other")
    elif case == "group_split":
        runs[1].update(split="val", parent_run_id=None)
    elif case == "missing_parent":
        runs[1]["parent_run_id"] = "absent"
    elif case == "cycle":
        runs[0]["parent_run_id"] = "b"
    elif case == "duplicate_id":
        runs[1]["run_id"] = "a"
    else:
        raw = tmp_path / "sample.jsonl"
        raw.write_bytes(b"synthetic\n")
        obj = {"path": "sample.jsonl", "sha256": hashlib.sha256(raw.read_bytes()).hexdigest()}
        runs[0].update(status="prepared", objects=[obj])
        if case == "hash_leak":
            runs[1].update(
                status="prepared",
                parent_run_id=None,
                activity_group="other",
                split="test",
                objects=[obj],
            )
        elif case == "escape":
            obj["path"] = "../outside.jsonl"
        elif case == "tampered":
            raw.write_bytes(b"modified")
        elif case == "empty_prepared":
            runs[0]["objects"] = []
    with pytest.raises(InventoryError):
        audit_inventory({"version": "1.0.0", "runs": runs}, tmp_path)


def test_rule_freeze_detects_semantic_drift_and_accepts_format_only_changes(tmp_path):
    from packages.detection.freeze import FrozenRulesError, load_frozen_rules

    source = Path(__file__).resolve().parents[2] / "rules"
    for file in source.glob("*.json"):
        (tmp_path / file.name).write_bytes(file.read_bytes())
    configs = load_frozen_rules(tmp_path)
    assert set(configs) == {f"R{i:02}" for i in range(1, 7)}
    target = tmp_path / "R01.json"
    value = json.loads(target.read_bytes())
    target.write_text(json.dumps(value, indent=4), encoding="utf-8")
    assert load_frozen_rules(tmp_path) == configs
    value["port_threshold"] += 1
    target.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(FrozenRulesError, match="RULE_CONFIGURATION_DRIFT"):
        load_frozen_rules(tmp_path)


def test_committed_inventory_is_auditable_without_running_formal_test():
    from eval.inventory import audit_inventory

    root = Path(__file__).resolve().parents[2]
    result = audit_inventory(json.loads((root / "eval/runs.json").read_bytes()), root)
    assert result["planned_by_split"] == {"dev": 12, "val": 6, "test": 12, "demo": 3}
    assert result["prepared"] >= 3
    assert result["formal_test_executed"] is False
