"""Offline preflight only: no detection, truth ingestion, or formal-test execution."""

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Literal

from pydantic import Field, ValidationError, model_validator

from packages.contracts.models import Contract, Digest
from packages.detection.freeze import config_digest, load_frozen_rules


class InventoryError(ValueError):
    pass


class InputObject(Contract):
    path: str = Field(min_length=1, max_length=300)
    sha256: Digest


class EvaluationRun(Contract):
    run_id: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,80}$")
    split: Literal["dev", "val", "test", "demo"]
    scenario_id: Literal["S1", "S2", "S3"]
    seed: int = Field(ge=0)
    activity_group: str = Field(min_length=1, max_length=100)
    parent_run_id: str | None = None
    status: Literal["planned", "prepared"]
    provenance_type: Literal["synthetic", "real_capture", "replayed", "derived"]
    authorized_scope: str = Field(min_length=1, max_length=500)
    objects: list[InputObject] = Field(max_length=20)

    @model_validator(mode="after")
    def availability(self):
        if (self.status == "prepared") != bool(self.objects):
            raise ValueError("prepared needs objects; planned cannot claim existing objects")
        if self.provenance_type in {"derived", "replayed"} and not self.parent_run_id:
            raise ValueError("derived/replayed needs parent lineage")
        return self


class Inventory(Contract):
    version: Literal["1.0.0"]
    runs: list[EvaluationRun] = Field(min_length=1, max_length=1000)


def audit_inventory(payload: dict, root: Path) -> dict:
    try:
        manifest = Inventory.model_validate(payload)
    except ValidationError:
        raise InventoryError("INVALID_INVENTORY") from None
    by_id = {run.run_id: run for run in manifest.runs}
    if len(by_id) != len(manifest.runs):
        raise InventoryError("DUPLICATE_RUN_ID")
    groups, hashes = {}, {}
    root = root.resolve()
    for run in manifest.runs:
        if groups.setdefault(run.activity_group, run.split) != run.split:
            raise InventoryError("ACTIVITY_GROUP_SPLIT_LEAK")
        visited, current = {run.run_id}, run
        while current.parent_run_id:
            parent = by_id.get(current.parent_run_id)
            if parent is None:
                raise InventoryError("MISSING_PARENT_RUN")
            if parent.run_id in visited:
                raise InventoryError("CYCLIC_LINEAGE")
            if parent.split != run.split or parent.activity_group != run.activity_group:
                raise InventoryError("LINEAGE_SPLIT_OR_GROUP_MISMATCH")
            visited.add(parent.run_id)
            current = parent
        for obj in run.objects:
            relative = PurePosixPath(obj.path)
            if (
                relative.is_absolute()
                or PureWindowsPath(obj.path).drive
                or "\\" in obj.path
                or ".." in relative.parts
            ):
                raise InventoryError("OBJECT_PATH_OUT_OF_SCOPE")
            path = (root / obj.path).resolve()
            if not path.is_relative_to(root):
                raise InventoryError("OBJECT_PATH_OUT_OF_SCOPE")
            try:
                with path.open("rb") as stream:
                    actual = hashlib.file_digest(stream, "sha256").hexdigest()
            except OSError:
                raise InventoryError("OBJECT_UNAVAILABLE") from None
            if actual != obj.sha256:
                raise InventoryError("OBJECT_HASH_MISMATCH")
            if hashes.setdefault(actual, run.split) != run.split:
                raise InventoryError("RAW_HASH_SPLIT_LEAK")
    planned = Counter(run.split for run in manifest.runs if run.status == "planned")
    return {
        "version": manifest.version,
        "planned": sum(planned.values()),
        "planned_by_split": dict(planned),
        "prepared": sum(run.status == "prepared" for run in manifest.runs),
        "independent_groups": len(groups),
        "prepared_groups": len(
            {run.activity_group for run in manifest.runs if run.status == "prepared"}
        ),
        "formal_test_executed": False,
        "limitations": [
            "prepared means hashed inputs available, "
            "not a completed or independently reviewed experiment",
            "planned groups/seeds are reservations, not independent samples",
            "semantic near-duplicates still require human lineage review",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=Path("eval/runs.json"))
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        result = audit_inventory(json.loads(args.manifest.read_bytes()), args.root)
        configs = load_frozen_rules()
        result["rules_config_hash"] = config_digest(
            {key: value.model_dump(mode="json") for key, value in configs.items()}
        )
    except (OSError, ValueError) as exc:
        parser.exit(1, f"Inventory preflight failed: {type(exc).__name__}\n")
    text = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n", encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
