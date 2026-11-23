"""Offline metrics from archived predictions; labels never flow back into investigation."""

import argparse
import hashlib
import json
import math
import random
from collections import Counter
from pathlib import Path

from eval.contracts import Activity, EdgePrediction, Execution, Step, TruthEdge
from scripts.release_manifest import encoded, write_new


def proportion(numerator: int, denominator: int) -> dict:
    if not 0 <= numerator <= denominator:
        raise ValueError("INVALID_PROPORTION")
    if denominator == 0:
        return {"numerator": 0, "denominator": 0, "value": None, "wilson95": None}
    p, z = numerator / denominator, 1.959963984540054
    scale = 1 + z * z / denominator
    center = (p + z * z / (2 * denominator)) / scale
    delta = z * math.sqrt((p * (1 - p) + z * z / (4 * denominator)) / denominator) / scale
    return {
        "numerator": numerator,
        "denominator": denominator,
        "value": p,
        "wilson95": [max(0.0, center - delta), min(1.0, center + delta)],
    }


def prf(tp: int, fp: int, fn: int) -> dict:
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None,
    }


def detection_score(predictions: list[dict], labels: list[dict]) -> dict:
    predicted = [Activity.model_validate(p) for p in predictions]
    all_truth = [Activity.model_validate(t) for t in labels]
    truth = [t for t in all_truth if t.observable]
    for items in (predicted, all_truth):
        if len({i.id for i in items}) != len(items):
            raise ValueError("DUPLICATE_ACTIVITY_ID")
    adjacency = [
        [
            j
            for j, target in enumerate(truth)
            if item.rule_id == target.rule_id
            and item.asset_id is not None
            and item.asset_id == target.asset_id
            and item.start <= target.end
            and target.start <= item.end
        ]
        for item in predicted
    ]
    matched: dict[int, int] = {}

    def augment(i: int, seen: set[int]) -> bool:
        for j in adjacency[i]:
            if j in seen:
                continue
            seen.add(j)
            if j not in matched or augment(matched[j], seen):
                matched[j] = i
                return True
        return False

    for i in range(len(predicted)):
        augment(i, set())
    tp = len(matched)
    return prf(tp, len(predicted) - tp, len(truth) - tp) | {
        "unobservable_truth": len(all_truth) - len(truth),
        "matches": [
            {"prediction": predicted[i].id, "truth": truth[j].id}
            for j, i in sorted(matched.items())
        ],
    }


def step_mapping(truth: dict) -> tuple[list[Step], dict[str, str]]:
    steps = [Step.model_validate(s) for s in truth["steps"]]
    if len({s.id for s in steps}) != len(steps):
        raise ValueError("DUPLICATE_STEP_ID")
    mapping = {}
    for step in steps:
        for event_id in step.event_ids:
            if event_id in mapping and mapping[event_id] != step.id:
                raise ValueError("AMBIGUOUS_EVENT_STEP_MAPPING")
            mapping[event_id] = step.id
    return steps, mapping


def graph_score(predictions: list[dict], truth: dict) -> dict:
    steps, mapping = step_mapping(truth)
    ids = {s.id for s in steps}
    visible = {s.id for s in steps if s.observable}
    edges = [TruthEdge.model_validate(e) for e in truth["edges"]]
    if any(e.from_step not in ids or e.to_step not in ids for e in edges):
        raise ValueError("UNKNOWN_TRUTH_STEP")
    expected = {
        (e.from_step, e.to_step, e.relation)
        for e in edges
        if e.observable and e.from_step in visible and e.to_step in visible
    }
    unknown = {(e.from_step, e.to_step, e.relation) for e in edges} - expected
    projected = set()
    duplicates = unscored = 0
    for raw in predictions:
        edge = EdgePrediction.model_validate(raw)
        source, target = mapping.get(edge.from_event_id), mapping.get(edge.to_event_id)
        key = (source, target, edge.relation)
        if source not in visible or target not in visible or key in unknown:
            unscored += 1
        elif key in projected:
            duplicates += 1
        else:
            projected.add(key)
    matched = projected & expected
    covered = {value for edge in matched for value in edge[:2]}
    return prf(len(matched), len(projected - expected), len(expected - projected)) | {
        "duplicate_projections": duplicates,
        "unknown_predictions": unscored,
        "observable_steps": len(visible),
        "unobservable_steps": len(steps) - len(visible),
        "step_coverage": {
            "numerator": len(covered),
            "denominator": len(visible),
            "value": len(covered) / len(visible) if visible else None,
        },
    }


def resolve_truth(truth: dict, events: list[dict]) -> dict:
    # Join labels AFTER predictions exist. Never assign labels from detector output.
    result = json.loads(json.dumps(truth))
    for step in result["steps"]:
        for location in step.get("locations", []):
            if set(location) != {"sha256", "record_start", "record_end"}:
                raise ValueError("INVALID_TRUTH_LOCATION")
            for event in events:
                if any(
                    ref["raw_sha256"] == location["sha256"]
                    and ref["record_start"] == location["record_start"]
                    and ref["record_end"] == location["record_end"]
                    for ref in event["source_locators"]
                ):
                    step.setdefault("event_ids", []).append(event["event_id"])
        step["event_ids"] = sorted(set(step.get("event_ids", [])))
    step_mapping(result)
    return result


def run_means(details: list[dict], metric: str) -> list[float]:
    grouped: dict[str, list[float]] = {}
    for row in details:
        if row[metric] and row[metric]["f1"] is not None:
            grouped.setdefault(row["run_id"], []).append(row[metric]["f1"])
    return [sum(values) / len(values) for _, values in sorted(grouped.items())]


def bootstrap(values: list[float]) -> list[float] | None:
    if len(values) < 12:
        return None
    generator = random.Random(20261115)
    draws = sorted(sum(generator.choices(values, k=len(values))) / len(values) for _ in range(1000))
    return [draws[24], draws[974]]


def summarize_results(records: list[dict], truths: dict[str, dict] | None = None) -> dict:
    executions = [Execution.model_validate(r) for r in records]
    identities = [(r.run_id, r.group, r.repeat) for r in executions]
    if len(set(identities)) != len(identities):
        raise ValueError("DUPLICATE_EXECUTION")
    truths = truths or {}
    details = []
    for row in executions:
        item = {
            "run_id": row.run_id,
            "group": row.group,
            "repeat": row.repeat,
            "status": row.status,
            "detection": None,
            "graph": None,
            "origin_top1": None,
            "origin_top3": None,
        }
        if row.run_id in truths and row.status in {"completed", "partial"}:
            truth = resolve_truth(truths[row.run_id], row.events)
            item["detection"] = detection_score(
                [p.model_dump(mode="json") for p in row.detections], truth["activities"]
            )
            item["graph"] = graph_score([p.model_dump() for p in row.graph_edges], truth)
            _, mapping = step_mapping(truth)
            expected = set(truth.get("observable_origins", []))
            if expected:
                item["origin_top1"] = bool(expected & {mapping.get(e) for e in row.origins[:1]})
                item["origin_top3"] = bool(expected & {mapping.get(e) for e in row.origins[:3]})
            item["left_censored"] = truth.get("left_censored", False)
        details.append(item)
    groups = {}
    for group in sorted({r.group for r in executions}):
        rows = [r for r in executions if r.group == group]
        scored = [d for d in details if d["group"] == group]
        f1 = run_means(scored, "detection")
        graph_f1 = run_means(scored, "graph")
        groups[group] = {
            "executions": len(rows),
            "statuses": dict(Counter(r.status for r in rows)),
            "failure_rate": proportion(sum(r.status != "completed" for r in rows), len(rows)),
            "elapsed_ms": [r.elapsed_ms for r in rows],
            "detection_f1_macro": sum(f1) / len(f1) if f1 else None,
            "graph_f1_macro": sum(graph_f1) / len(graph_f1) if graph_f1 else None,
            "scored_runs": len(f1),
            "f1_interval": bootstrap(f1),
            "f1_interval_reason": "Insufficient scored runs (<12)."
            if len(f1) < 12
            else "Exploratory run-group bootstrap; 1000 resamples, seed 20261115.",
            "reference_authorized": proportion(
                sum(r.references_valid for r in rows), sum(r.references_total for r in rows)
            ),
            "rejected_claims": sum(r.rejected_claims for r in rows),
            "natural_language_unsupported_rate": None,
            "human_review": "not_available",
            "origin_top1": proportion(
                sum(d["origin_top1"] is True for d in scored),
                sum(d["origin_top1"] is not None for d in scored),
            ),
            "origin_top3": proportion(
                sum(d["origin_top3"] is True for d in scored),
                sum(d["origin_top3"] is not None for d in scored),
            ),
        }
        groups[group]["origin_by_repeat"] = {
            str(repeat): {
                metric: proportion(
                    sum(d[metric] is True for d in scored if d["repeat"] == repeat),
                    sum(d[metric] is not None for d in scored if d["repeat"] == repeat),
                )
                for metric in ("origin_top1", "origin_top3")
            }
            for repeat in sorted({r.repeat for r in rows})
        }
        if len({r.run_id for r in rows}) != len(rows):
            for metric in ("failure_rate", "origin_top1", "origin_top3", "reference_authorized"):
                groups[group][metric]["wilson95"] = None
    return {
        "version": "d11-metrics@1.0.0",
        "executions": len(executions),
        "statuses": dict(Counter(r.status for r in executions)),
        "groups": groups,
        "cases": details,
        "formal_metrics_available": bool(executions)
        and all(r.run_id in truths for r in executions)
        and all(r.status == "completed" for r in executions),
        "limitations": [
            "No labels means no detection/path F1, not a perfect score.",
            "Repeated runs are correlated; intervals do not prove independence.",
        ],
    }


def recompute(folder: Path) -> dict:
    manifest = json.loads((folder / "manifest.json").read_bytes())
    raw = (folder / "predictions.jsonl").read_bytes()
    if hashlib.sha256(raw).hexdigest() != manifest["predictions_sha256"]:
        raise ValueError("PREDICTION_HASH_MISMATCH")
    records = [json.loads(line) for line in raw.splitlines()]
    expected = {
        (run_id, group, repeat)
        for run_id in manifest["run_ids"]
        for group in manifest["groups"]
        for repeat in range(manifest["repeats"])
    }
    if {(r["run_id"], r["group"], r["repeat"]) for r in records} != expected:
        raise ValueError("MISSING_EXECUTION_RESULTS")
    truths = {}
    if manifest.get("truth_sha256"):
        raw_truth = (folder / "labels.json").read_bytes()
        if hashlib.sha256(raw_truth).hexdigest() != manifest["truth_sha256"]:
            raise ValueError("TRUTH_HASH_MISMATCH")
        truths = json.loads(raw_truth)
    result = summarize_results(records, truths)
    result["runtime_unchanged"] = manifest["runtime_unchanged"]
    result["input_unchanged"] = manifest.get("input_unchanged", False)
    result["formal_metrics_available"] &= (
        manifest["profile"] == "formal"
        and manifest["runtime_unchanged"]
        and result["input_unchanged"]
    )
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = recompute(args.input)
        write_new(args.output, encoded(result))
        print(
            json.dumps(
                {
                    "executions": result["executions"],
                    "formal_metrics_available": result["formal_metrics_available"],
                }
            )
        )
    except (OSError, ValueError, KeyError) as exc:
        parser.exit(1, f"METRICS_FAILED:{type(exc).__name__}\n")


if __name__ == "__main__":
    main()
