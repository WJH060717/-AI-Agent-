"""Recompute D11 local engineering evidence; never upgrade it to formal evaluation."""

import argparse
import hashlib
import json
import time
from datetime import datetime
from pathlib import Path

from eval.contracts import EvaluationConfig
from eval.metrics import recompute
from eval.run import versions
from eval.validate_manifest import validate
from scripts.benchmark_d11 import BENCHMARK_CONFIG, records, runtime_files, summarize
from scripts.release_manifest import encoded, write_new

ROOT = Path(__file__).resolve().parents[1]


def verify_benchmark(folder: Path) -> dict:
    protocol = json.loads((folder / "protocol.json").read_bytes())
    summary = json.loads((folder / "summary.json").read_bytes())
    expected = {
        "profile": "full",
        "batch_records": 500,
        "batch_interval_seconds": 10.0,
        "scheduled_batches": 180,
        "duration_seconds": 1800.0,
        "query_target_events": 100000,
        "query_requests": 100,
    }
    if any(protocol.get(key) != value for key, value in expected.items()):
        raise ValueError("FULL_PROTOCOL_REQUIRED")
    if protocol.get("effective_settings") != BENCHMARK_CONFIG:
        raise ValueError("BENCHMARK_CONFIGURATION_MISMATCH")
    raw = (folder / "samples.jsonl").read_bytes()
    if hashlib.sha256(raw).hexdigest() != summary.get("samples_sha256"):
        raise ValueError("BENCHMARK_SAMPLES_CHANGED")
    if protocol["runtime_files"] != runtime_files() or not summary.get("runtime_unchanged"):
        raise ValueError("BENCHMARK_RUNTIME_CHANGED")
    samples = [json.loads(line) for line in raw.splitlines()]
    uploads = [row for row in samples if row["kind"] == "upload"]
    batches = [row for row in samples if row["kind"] == "batch"]
    schedules = [row for row in samples if row["kind"] == "schedule"]
    if (
        [row["index"] for row in uploads] != list(range(200))
        or sorted(row["index"] for row in batches) != list(range(200))
        or [row["index"] for row in schedules] != list(range(180))
    ):
        raise ValueError("INCOMPLETE_BENCHMARK_RECORDS")
    for row in uploads:
        index = row["index"]
        if (
            row["status"] != 202
            or row["expected"] != 500
            or row["offset"] != index * 500
            or row["phase"] != ("ingest" if index < 180 else "query_preload")
            or row["sha256"] != hashlib.sha256(records(index * 500, 500)).hexdigest()
        ):
            raise ValueError("BENCHMARK_INPUT_MISMATCH")
    for row in batches:
        if (
            row["phase"] != ("ingest" if row["index"] < 180 else "query_preload")
            or row["status"] not in {"succeeded", "partial"}
            or row["accepted"] != row["raw_records"]
            or row["accepted"] != 500
            or row["duplicate"]
            or row["quarantined"]
        ):
            raise ValueError("BENCHMARK_RECORD_LOSS")
    times = [datetime.fromisoformat(row["recorded_at"]) for row in schedules]
    if any(abs((value - times[0]).total_seconds() - i * 10) > 1 for i, value in enumerate(times)):
        raise ValueError("BENCHMARK_SCHEDULE_DRIFT")
    resources = [row for row in samples if row["kind"] == "resources"]
    if len(resources) != 180 or any(
        row["status"] != "measured" or not row["processes"] for row in resources
    ):
        raise ValueError("RESOURCE_EVIDENCE_INCOMPLETE")
    counted = sum(row["accepted"] for row in batches)
    calculated = summarize(
        samples,
        profile="full",
        final_count=counted,
        drain_seconds=summary["drain_seconds"],
        duration_seconds=summary["duration_seconds"],
    )
    if summary.get("errors") or any(summary.get(key) != value for key, value in calculated.items()):
        raise ValueError("BENCHMARK_SUMMARY_MISMATCH")
    if not calculated["full_protocol_passed"]:
        raise ValueError("BENCHMARK_TARGET_NOT_MET")
    return {
        "verified": True,
        "profile": "engineering",
        "summary": calculated,
        "peak_process_tree_working_set_bytes": max(
            sum(p["WorkingSet64"] for p in row["processes"]) for row in resources
        ),
        "resource_samples": len(resources),
    }


def verify_evaluation(folder: Path) -> dict:
    recorded = json.loads((folder / "metrics.json").read_bytes())
    calculated = recompute(folder)
    manifest = json.loads((folder / "manifest.json").read_bytes())
    config = EvaluationConfig.model_validate_json((folder / "config.json").read_bytes())
    expected_config = EvaluationConfig.model_validate_json(
        (ROOT / "eval/configs/d11-engineering.json").read_bytes()
    )
    preflight = validate(config.model_dump(mode="json"), ROOT)
    if (
        config != expected_config
        or preflight != json.loads((folder / "preflight.json").read_bytes())
        or manifest["config_hash"] != preflight["config_hash"]
        or manifest["run_ids"] != [run.run_id for run in config.runs]
        or manifest["groups"] != config.groups
        or manifest["repeats"] != config.repeats
    ):
        raise ValueError("EVALUATION_CONFIG_MISMATCH")
    if manifest["versions"] != versions(ROOT):
        raise ValueError("EVALUATION_RUNTIME_CHANGED")
    if recorded != calculated:
        raise ValueError("METRICS_RECOMPUTATION_MISMATCH")
    if (
        not calculated["runtime_unchanged"]
        or not calculated["input_unchanged"]
        or calculated["statuses"] != {"completed": 12}
        or manifest["profile"] != "engineering"
        or calculated["formal_metrics_available"]
    ):
        raise ValueError("ENGINEERING_EXECUTIONS_INCOMPLETE")
    return {
        "verified": True,
        "executions": calculated["executions"],
        "formal_metrics_available": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=["benchmark", "evaluation"])
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--wait-seconds",
        type=float,
        default=0,
        help="At most 1900 seconds for an already-started benchmark to finish",
    )
    args = parser.parse_args()
    try:
        if not 0 <= args.wait_seconds <= 1900:
            raise ValueError("INVALID_BENCHMARK_WAIT")
        if args.kind == "benchmark" and args.wait_seconds:
            protocol = json.loads((args.input / "protocol.json").read_bytes())
            if protocol.get("profile") != "full":
                raise ValueError("FULL_PROTOCOL_REQUIRED")
            deadline = time.monotonic() + args.wait_seconds
            while not (args.input / "summary.json").exists() and time.monotonic() < deadline:
                time.sleep(0.5)
        result = (verify_benchmark if args.kind == "benchmark" else verify_evaluation)(args.input)
        write_new(args.output, encoded(result))
        print(json.dumps(result, ensure_ascii=False))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(1, f"D11_EVIDENCE_FAILED:{type(exc).__name__}:{exc}\n")


if __name__ == "__main__":
    main()
