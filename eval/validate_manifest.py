"""Validate offline evaluation inputs. Formal mode fails closed on uncollected/unreviewed runs."""

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

from eval.contracts import EvaluationConfig
from eval.freeze import read_scoped, verify_freeze
from packages.detection.freeze import config_digest, load_frozen_rules


def validate(payload: dict, root: Path) -> dict:
    config = EvaluationConfig.model_validate(payload)
    inventory = json.loads((root / "eval/runs.json").read_bytes())
    frozen_inventory = (
        read_scoped(root, config.inventory_freeze)
        if config.inventory_freeze
        else (root / "eval/freeze-d9.json").read_bytes()
    )
    frozen = json.loads(frozen_inventory)
    dossiers = json.loads((root / "eval/dossiers.json").read_bytes())
    if (
        config_digest(inventory) != frozen["manifest_hash"]
        or config_digest(dossiers) != frozen["dossiers_hash"]
    ):
        raise ValueError("INVENTORY_FREEZE_DRIFT")
    readiness = verify_freeze(root, frozen)
    if config.profile == "formal" and not (
        readiness["data_collection_complete"] and readiness["labels_review_complete"]
    ):
        raise ValueError("DATA_AND_LABELS_NOT_READY")
    approved = json.loads((root / "infra/release-inputs.json").read_bytes())["files"]
    formal_runs = {r["run_id"]: r for r in inventory["runs"] if r["split"] == "test"}
    if config.profile == "formal" and (
        len(formal_runs) != 12
        or len({r["activity_group"] for r in formal_runs.values()}) != 12
        or Counter(r["scenario_id"] for r in formal_runs.values()) != {"S1": 4, "S2": 4, "S3": 4}
    ):
        raise ValueError("FORMAL_TEST_SET_INCOMPLETE_OR_DEPENDENT")
    if config.profile == "formal" and set(formal_runs) != {r.run_id for r in config.runs}:
        raise ValueError("FORMAL_TEST_RUN_SET_MISMATCH")
    hashes = {}
    for run in config.runs:
        objects = ([run.context] if run.context else []) + [s.object for s in run.sources]
        if len({(s.source_type, s.sensor_id, s.object.path) for s in run.sources}) != len(
            run.sources
        ):
            raise ValueError("DUPLICATE_SOURCE_BINDING")
        known = (
            {o["path"]: o["sha256"] for o in formal_runs[run.run_id]["objects"]}
            if config.profile == "formal"
            else approved
        )
        for obj in objects:
            if not obj.path.startswith("data/") or "ground_truth" in Path(obj.path).parts:
                raise ValueError("RUNTIME_INPUT_PATH_NOT_ALLOWED")
            if known.get(obj.path) != obj.sha256:
                raise ValueError("INPUT_NOT_IN_FROZEN_INVENTORY")
            hashes[obj.path] = hashlib.sha256(read_scoped(root, obj)).hexdigest()
        if config.profile == "formal":
            if run.scenario_id != formal_runs[run.run_id]["scenario_id"]:
                raise ValueError("FORMAL_TEST_SCENARIO_MISMATCH")
            if {obj.path for obj in objects} != set(known):
                raise ValueError("FORMAL_INPUT_BINDINGS_INCOMPLETE")
            if run.provenance_type != formal_runs[run.run_id]["provenance_type"]:
                raise ValueError("PROVENANCE_MISMATCH")
    rules = load_frozen_rules(root / "rules")
    return {
        "profile": config.profile,
        "formal_ready": config.profile == "formal",
        "config_hash": config_digest(config.model_dump(mode="json")),
        "input_hashes": hashes,
        "rule_hash": config_digest({k: v.model_dump(mode="json") for k, v in rules.items()}),
        "readiness": readiness,
        "inventory_freeze": frozen,
        "truth_refs": {
            dossier["run_id"]: dossier["truth"]
            for dossier in dossiers["runs"]
            if config.profile == "formal" and dossier["run_id"] in formal_runs
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = validate(json.loads(args.config.read_bytes()), Path(__file__).resolve().parents[1])
        print(json.dumps(result, ensure_ascii=False, indent=2))
    except (OSError, ValueError, KeyError) as exc:
        code = (
            "DATA_AND_LABELS_NOT_READY"
            if str(exc) == "DATA_AND_LABELS_NOT_READY"
            else type(exc).__name__
        )
        parser.exit(
            2 if code == "DATA_AND_LABELS_NOT_READY" else 1, f"EVALUATION_PREFLIGHT_FAILED:{code}\n"
        )


if __name__ == "__main__":
    main()
