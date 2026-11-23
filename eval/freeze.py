"""Offline D9 inventory freeze and label-review readiness; does not execute experiments."""

import argparse
import hashlib
import json
from pathlib import Path, PureWindowsPath

from pydantic import Field

from eval.inventory import InputObject, audit_inventory
from packages.contracts.models import Contract, Digest
from packages.detection.freeze import config_digest, load_frozen_rules


class LabelReview(Contract):
    actor: str = Field(min_length=1, max_length=100)
    truth_hash: Digest


class RunDossier(Contract):
    run_id: str
    truth: InputObject | None = None
    reviewers: list[LabelReview] = Field(default_factory=list, max_length=2)
    unresolved_disagreements: list[str] = Field(default_factory=list, max_length=30)


class Dossiers(Contract):
    version: str
    runs: list[RunDossier]


def read_scoped(root: Path, obj: InputObject) -> bytes:
    root = root.resolve()
    path = (root / obj.path).resolve()
    if "\\" in obj.path or PureWindowsPath(obj.path).drive or not path.is_relative_to(root):
        raise ValueError("LABEL_PATH_OUT_OF_SCOPE")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != obj.sha256:
        raise ValueError("LABEL_HASH_MISMATCH")
    return raw


def validate_dossiers(root: Path, manifest: dict, payload: dict) -> dict:
    dossiers = Dossiers.model_validate(payload)
    runs = {r["run_id"]: r for r in manifest["runs"]}
    if (
        dossiers.version != "1.0.0"
        or len({d.run_id for d in dossiers.runs}) != len(dossiers.runs)
        or {d.run_id for d in dossiers.runs} != set(runs)
    ):
        raise ValueError("DOSSIER_RUN_MISMATCH")
    reviewed = []
    for dossier in dossiers.runs:
        if dossier.truth:
            if runs[dossier.run_id]["status"] != "prepared":
                raise ValueError("LABELS_WITHOUT_INPUTS")
            truth = json.loads(read_scoped(root, dossier.truth))
            if truth.get("run_id") != dossier.run_id or not isinstance(
                truth.get("ground_truth_steps"), list
            ):
                raise ValueError("LABEL_RUN_MISMATCH")
        if dossier.reviewers:
            if not dossier.truth or any(
                r.truth_hash != dossier.truth.sha256 for r in dossier.reviewers
            ):
                raise ValueError("REVIEW_HASH_MISMATCH")
            if len({r.actor.strip().casefold() for r in dossier.reviewers}) != len(
                dossier.reviewers
            ):
                raise ValueError("REVIEWERS_NOT_DISTINCT")
        if len(dossier.reviewers) == 2 and not dossier.unresolved_disagreements:
            reviewed.append(dossier.run_id)
    return {
        "reviewed_runs": len(reviewed),
        "pending_run_ids": sorted(set(runs) - set(reviewed)),
        "data_collection_complete": all(r["status"] == "prepared" for r in runs.values()),
        "labels_review_complete": len(reviewed) == len(runs),
    }


def build_freeze(root: Path) -> dict:
    manifest = json.loads((root / "eval/runs.json").read_bytes())
    dossiers = json.loads((root / "eval/dossiers.json").read_bytes())
    readiness = audit_inventory(manifest, root) | validate_dossiers(root, manifest, dossiers)
    rules = {k: v.model_dump(mode="json") for k, v in load_frozen_rules(root / "rules").items()}
    return {
        "version": "d9-inventory@1.0.0",
        "manifest_hash": config_digest(manifest),
        "dossiers_hash": config_digest(dossiers),
        "rules_hash": config_digest(rules),
        "readiness": readiness,
    }


def verify_freeze(root: Path, frozen: dict) -> dict:
    if frozen != build_freeze(root):
        raise ValueError("INVENTORY_FREEZE_DRIFT")
    return frozen["readiness"]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--freeze", type=Path, default=Path("eval/freeze-d9.json"))
    parser.add_argument(
        "--create", action="store_true", help="Create a NEW freeze file; never overwrite"
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require-ready", action="store_true")
    args = parser.parse_args()
    try:
        if args.create:
            frozen = build_freeze(args.root)
            with args.freeze.open("x", encoding="utf-8") as stream:
                stream.write(json.dumps(frozen, ensure_ascii=False, indent=2) + "\n")
        result = verify_freeze(args.root, json.loads(args.freeze.read_bytes()))
        text = json.dumps(result, ensure_ascii=False, indent=2)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(text + "\n", encoding="utf-8")
        print(text)
        if args.require_ready and not (
            result["data_collection_complete"] and result["labels_review_complete"]
        ):
            parser.exit(2, "D9_DATA_AND_LABEL_REVIEW_INCOMPLETE\n")
    except (OSError, ValueError) as exc:
        parser.exit(1, f"D9 freeze check failed: {type(exc).__name__}\n")


if __name__ == "__main__":
    main()
