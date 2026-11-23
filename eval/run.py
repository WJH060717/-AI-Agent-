"""Version-bound offline evaluation. Engineering fixtures cannot become a formal test score."""

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from eval.contracts import EvaluationConfig, Execution
from eval.freeze import read_scoped
from eval.inventory import InputObject
from eval.metrics import recompute
from eval.runner import execute
from eval.validate_manifest import validate
from scripts.benchmark_d11 import runtime_files
from scripts.release_manifest import encoded, manifest_digest, write_new

ROOT = Path(__file__).resolve().parents[1]


def versions(root: Path) -> dict:
    return runtime_files() | {
        p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted((root / "eval").glob("*.py"))
    }


def run(payload: dict, output: Path, root: Path = ROOT) -> dict:
    checked = validate(payload, root)
    config = EvaluationConfig.model_validate(payload)
    frozen_versions = versions(root)
    if output.exists():
        raise FileExistsError("EVALUATION_OUTPUT_EXISTS")
    if config.profile == "formal":
        # Consumes the held-out input once even if this execution later fails.
        key = manifest_digest(checked["input_hashes"])
        write_new(
            root / "artifacts/eval-formal-ledger" / f"{key}.json",
            encoded(
                {
                    "started_at": datetime.now(UTC).isoformat(),
                    "config_hash": checked["config_hash"],
                    "versions": frozen_versions,
                    "output": str(output.resolve()),
                }
            ),
        )
    output.mkdir(parents=True, exist_ok=False)
    write_new(output / "config.json", encoded(config.model_dump(mode="json")))
    write_new(output / "preflight.json", encoded(checked))
    records = []
    started_at = datetime.now(UTC).isoformat()
    with (output / "predictions.jsonl").open("x", encoding="utf-8") as stream:

        def emit(record: dict) -> None:
            value = Execution.model_validate(record).model_dump(mode="json")
            records.append(value)
            stream.write(json.dumps(value, ensure_ascii=False) + "\n")
            stream.flush()

        execute(config, root, emit)
    manifest = {
        "version": "d11-results@1.0.0",
        "profile": config.profile,
        "started_at": started_at,
        "ended_at": datetime.now(UTC).isoformat(),
        "config_hash": checked["config_hash"],
        "versions": frozen_versions,
        "runtime_unchanged": frozen_versions == versions(root),
        "run_ids": [r.run_id for r in config.runs],
        "groups": config.groups,
        "repeats": config.repeats,
        "predictions_sha256": hashlib.sha256(
            (output / "predictions.jsonl").read_bytes()
        ).hexdigest(),
        "truth_sha256": None,
        "input_unchanged": False,
    }
    try:
        if validate(payload, root) != checked:
            raise ValueError("EVALUATION_INPUT_DRIFT")
        if config.profile == "formal":
            labels = {}
            # Use only references pinned at preflight, never the current dossier pointers.
            for run_id, reference in checked["truth_refs"].items():
                raw = json.loads(read_scoped(root, InputObject.model_validate(reference)))
                labels[run_id] = {
                    "steps": raw["ground_truth_steps"],
                    "edges": raw["ground_truth_edges"],
                    "activities": raw["activities"],
                    "observable_origins": raw["observable_origins"],
                    "left_censored": raw["left_censored"],
                }
            if validate(payload, root) != checked:
                raise ValueError("EVALUATION_INPUT_DRIFT")
            write_new(output / "labels.json", encoded(labels))
            manifest["truth_sha256"] = hashlib.sha256(
                (output / "labels.json").read_bytes()
            ).hexdigest()
        manifest["input_unchanged"] = True
    except (OSError, ValueError, KeyError) as exc:
        write_new(output / "manifest.json", encoded(manifest))
        write_new(output / "failure.json", encoded({"code": "EVALUATION_INPUT_DRIFT"}))
        raise ValueError("EVALUATION_INPUT_DRIFT") from exc
    write_new(output / "manifest.json", encoded(manifest))
    result = recompute(output)
    result["runtime_unchanged"] = manifest["runtime_unchanged"]
    write_new(output / "metrics.json", encoded(result))
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = run(json.loads(args.config.read_bytes()), args.output.resolve())
        print(
            json.dumps(
                {
                    "executions": result["executions"],
                    "statuses": result["statuses"],
                    "formal_metrics_available": result["formal_metrics_available"],
                    "runtime_unchanged": result["runtime_unchanged"],
                }
            )
        )
        if not result["runtime_unchanged"] or result["statuses"].get("failed"):
            raise SystemExit(1)
        if (
            json.loads(args.config.read_bytes())["profile"] == "formal"
            and not result["formal_metrics_available"]
        ):
            raise SystemExit(2)
    except (OSError, ValueError, KeyError) as exc:
        code = (
            "DATA_AND_LABELS_NOT_READY"
            if str(exc) == "DATA_AND_LABELS_NOT_READY"
            else type(exc).__name__
        )
        parser.exit(2 if code == "DATA_AND_LABELS_NOT_READY" else 1, f"EVALUATION_FAILED:{code}\n")


if __name__ == "__main__":
    main()
