"""Offline D12 statistics and evidence presentation; never used by the running Agent."""

import argparse
import csv
import hashlib
import html
import io
import json
import math
import statistics
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Literal

from pydantic import Field

from eval.metrics import recompute
from packages.contracts.models import Contract, Digest
from scripts.backup import encoded, safe_path
from scripts.benchmark_d11 import runtime_files, summarize

ROOT = Path(__file__).resolve().parents[1]
USAGE = (
    "model_calls",
    "tool_calls",
    "input_tokens",
    "output_tokens",
    "cost_microusd",
    "actual_cost_microusd",
)


class Source(Contract):
    id: str = Field(pattern=r"^[a-z0-9-]{1,80}$")
    folder: str
    note: str = Field(min_length=1)


class Inputs(Contract):
    version: Literal["d12-analysis-inputs@1.0.0"]
    files: dict[str, Digest]
    evaluations: list[Source]
    benchmarks: list[Source]
    screenshots: list[str]


def load_inputs(root: Path, path: Path) -> dict:
    config = Inputs.model_validate_json(path.read_bytes()).model_dump()
    for name, digest in config["files"].items():
        source = safe_path(root.absolute(), name)
        if not source.is_file() or hashlib.sha256(source.read_bytes()).hexdigest() != digest:
            raise ValueError("ANALYSIS_INPUT_INTEGRITY")
    for item in config["evaluations"]:
        for name in (
            "config.json",
            "manifest.json",
            "predictions.jsonl",
            "metrics.json",
            "preflight.json",
        ):
            if item["folder"] + "/" + name not in config["files"]:
                raise ValueError("ANALYSIS_UNBOUND_INPUT")
        if (root / item["folder"] / "labels.json").exists() and item[
            "folder"
        ] + "/labels.json" not in config["files"]:
            raise ValueError("ANALYSIS_UNBOUND_LABELS")
    for item in config["benchmarks"]:
        if any(
            item["folder"] + "/" + n not in config["files"]
            for n in ("protocol.json", "summary.json", "samples.jsonl")
        ):
            raise ValueError("ANALYSIS_UNBOUND_INPUT")
    if any(n not in config["files"] for n in config["screenshots"]):
        raise ValueError("ANALYSIS_UNBOUND_SCREENSHOT")
    ids = [s["id"] for s in config["evaluations"] + config["benchmarks"]]
    if len(ids) != len(set(ids)):
        raise ValueError("ANALYSIS_DUPLICATE_SOURCE")
    return config


def ratio(n: int, total: int) -> dict:
    return {"n": n, "N": total, "rate": n / total if total else None}


def distribution(values: list[float]) -> dict:
    ordered = sorted(values)
    if any(not math.isfinite(v) or v < 0 for v in values):
        raise ValueError("INVALID_MEASUREMENT")
    return {
        "values": values,
        "n": len(values),
        "mean": statistics.mean(values) if values else None,
        "stdev": statistics.stdev(values) if len(values) > 1 else None,
        "p50": statistics.median(values) if values else None,
        "p95": ordered[math.ceil(len(values) * 0.95) - 1] if values else None,
    }


def execution_summary(records: list[dict]) -> dict:
    usage = {
        key: sum(r["usage"][key] for r in records if key in r.get("usage", {}))
        if any(key in r.get("usage", {}) for r in records)
        else None
        for key in USAGE
    }

    def timed_out(row: dict) -> bool:
        return "TIMEOUT" in (row.get("error") or row.get("stop_reason") or "").upper()

    measured = [
        r["elapsed_ms"]
        for r in records
        if (r["elapsed_ms"] > 0 or r["status"] == "completed")
        and r.get("terminal_observed") is not False
    ]
    elapsed = distribution(measured)
    elapsed["unmeasured_attempts"] = len(records) - len(measured)
    elapsed["all_attempts_p95"] = elapsed["p95"] if len(measured) == len(records) else None
    return {
        "attempts": len(records),
        "statuses": dict(Counter(r["status"] for r in records)),
        "noncompletion": ratio(sum(r["status"] != "completed" for r in records), len(records)),
        "timeout": ratio(sum(timed_out(r) for r in records), len(records)),
        "elapsed_ms": elapsed,
        "usage": usage,
        "usage_recorded_attempts": {
            k: sum(k in r.get("usage", {}) for r in records) for k in USAGE
        },
        "provider_billed_usd": None,
        "billing_basis": "No invoice. Budget debits and configured-price estimates are not bills.",
    }


def resource_series(samples: list[dict]) -> list[dict]:
    result = []
    previous = None
    previous_time = None
    for row in samples:
        if row["kind"] != "resources":
            continue
        stamp = datetime.fromisoformat(row["recorded_at"])
        processes = row.get("processes", [])
        current = {p["Id"]: p.get("CPU") for p in processes}
        elapsed = (stamp - previous_time).total_seconds() if previous_time else None
        valid = (
            row.get("status") == "measured"
            and previous is not None
            and current
            and current.keys() == previous.keys()
            and elapsed
            and elapsed > 0
            and all(
                isinstance(v, (int, float))
                and isinstance(previous[k], (int, float))
                and v >= previous[k]
                for k, v in current.items()
            )
        )
        cpu = sum(v - previous[k] for k, v in current.items()) / elapsed if valid else None
        result.append(
            {
                "recorded_at": row["recorded_at"],
                "cpu_cores": cpu,
                "working_set_bytes": sum(p["WorkingSet64"] for p in processes)
                if processes
                else None,
                "private_memory_bytes": sum(p["PrivateMemorySize64"] for p in processes)
                if processes
                else None,
            }
        )
        previous, previous_time = current, stamp
    return result


def calculate(root: Path, config: dict) -> dict:
    result = {
        "version": "d12-analysis@1.0.0",
        "evaluations": [],
        "benchmarks": [],
        "failure_cases": [],
        "formal_detection_f1": None,
        "normal_run_false_positive_rate": None,
        "limitations": [
            "Same-lineage synthetic engineering fixtures; not independent test runs.",
            "No reviewed labels: false positives, F1 and human factual accuracy remain unknown.",
            "Protocol stub cost and speed cannot establish real-model performance.",
            "Historical benchmark results belong to their recorded code, never the current build.",
            "Elapsed group work differs from per-investigation acceptance-to-terminal time.",
            "p95: nearest rank. CPU: process-tree CPU-seconds / wall-seconds, in cores.",
        ],
    }
    for item in config["evaluations"]:
        folder = root / item["folder"]
        manifest = json.loads((folder / "manifest.json").read_bytes())
        calculated = recompute(folder)
        recorded = json.loads((folder / "metrics.json").read_bytes())
        comparable = dict(calculated)
        # The first two D11 runs predate this metadata flag. Absence is unknown,
        # not evidence that their input was unchanged; all metric values still match.
        if "input_unchanged" not in recorded:
            comparable.pop("input_unchanged", None)
        if comparable != recorded:
            raise ValueError("HISTORICAL_METRICS_MISMATCH")
        records = [
            json.loads(line) for line in (folder / "predictions.jsonl").read_bytes().splitlines()
        ]
        groups = {}
        for group in ("B0", "B1", "B2", "B3"):
            rows = [r for r in records if r["group"] == group]
            investigations = [i for r in rows for i in r.get("investigations", [])]
            groups[group] = execution_summary(rows)
            groups[group]["investigations"] = execution_summary(investigations)
            groups[group]["investigation_timing_available"] = bool(investigations)
            groups[group]["references"] = ratio(
                sum(r["references_valid"] for r in rows), sum(r["references_total"] for r in rows)
            )
            groups[group]["rejected_claims"] = sum(r["rejected_claims"] for r in rows)
        result["evaluations"].append(
            {
                **item,
                "profile": manifest["profile"],
                "groups": groups,
                "model_mode": json.loads((folder / "config.json").read_bytes())["model_mode"],
                "formal_metrics_available": calculated["formal_metrics_available"],
                "versions": manifest["versions"],
                "recorded_input_unchanged": recorded.get("input_unchanged"),
            }
        )
        for index, row in enumerate(records, 1):
            if row["status"] != "completed":
                result["failure_cases"].append(
                    {
                        "source": item["folder"] + "/predictions.jsonl",
                        "line": index,
                        "run_id": row["run_id"],
                        "group": row["group"],
                        "status": row["status"],
                        "reason": row.get("error"),
                        "interpretation": (
                            "Execution failure retained in its round; "
                            "not a labeled detection false positive."
                        ),
                    }
                )
    current_files = runtime_files()
    for item in config["benchmarks"]:
        folder = root / item["folder"]
        protocol = json.loads((folder / "protocol.json").read_bytes())
        original = json.loads((folder / "summary.json").read_bytes())
        raw = (folder / "samples.jsonl").read_bytes()
        if hashlib.sha256(raw).hexdigest() != original["samples_sha256"]:
            raise ValueError("HISTORICAL_BENCHMARK_INTEGRITY")
        rows = [json.loads(line) for line in raw.splitlines()]
        calculated = summarize(
            rows,
            profile=protocol["profile"],
            final_count=original["query_dataset_events"],
            drain_seconds=original["drain_seconds"],
            duration_seconds=original["duration_seconds"],
        )
        if any(original.get(k) != v for k, v in calculated.items()):
            raise ValueError("HISTORICAL_BENCHMARK_MISMATCH")
        series = resource_series(rows)
        result["benchmarks"].append(
            {
                **item,
                "summary": calculated,
                "resource_series": series,
                "runtime_matches_current": protocol["runtime_files"] == current_files,
                "recorded_runtime": protocol["runtime_files"],
                "peak_working_set_bytes": max(
                    (r["working_set_bytes"] for r in series if r["working_set_bytes"] is not None),
                    default=None,
                ),
            }
        )
        if not calculated["full_protocol_passed"]:
            result["failure_cases"].append(
                {
                    "source": item["folder"] + "/summary.json",
                    "status": "target_not_met",
                    "reason": "FULL_INGEST_QUERY_PROTOCOL_FAILED",
                    "query_p95_ms": calculated["query_p95_ms"],
                    "query_target_p95_ms": 2000,
                }
            )
    result["interpretations"] = [
        {
            "subject": "R05 periodic communication",
            "assessment": "normal alternative; not a measured false positive",
            "reason": "Monitoring can be periodic. Periodicity alone does not establish C2.",
            "source": "docs/03-detection-graph.md",
        },
        {
            "subject": "R06 outbound volume",
            "assessment": "normal alternative or unknown; not a measured false positive",
            "reason": (
                "Approved backup is context_only. Missing socket or baseline cannot establish "
                "exfiltration or absence of attack."
            ),
            "source": "docs/03-detection-graph.md",
        },
        {
            "subject": "100000-event benchmark",
            "assessment": "partial detection coverage",
            "reason": (
                "Durable ingestion and fast query do not imply complete detection "
                "above the 10000-event limit."
            ),
            "source": "docs/d11-limitations.md",
        },
    ]
    return result


def chart(result: dict) -> bytes:
    parts = [
        '<svg xmlns="http://www.w3.org/2000/svg" width="1000" height="760" viewBox="0 0 1000 760">',
        '<rect width="1000" height="760" fill="#f7f9fc"/>'
        '<g font-family="sans-serif" fill="#152238">',
        '<text x="38" y="34" font-size="22">Historical D11 resource curves</text>',
    ]
    for index, item in enumerate(result["benchmarks"]):
        top = 62 + index * 222
        points = item["resource_series"]
        mem = [
            r["working_set_bytes"] / 1048576 if r["working_set_bytes"] is not None else None
            for r in points
        ]
        cpu = [r["cpu_cores"] for r in points]
        parts.append(
            f'<text x="38" y="{top}" font-size="15">{html.escape(item["id"])}'
            " | historical code | memory MiB / CPU cores</text>"
        )
        for col, values, color, label in (
            (0, mem, "#1e6091", "Memory MiB"),
            (1, cpu, "#8b3b88", "CPU cores"),
        ):
            left = 55 + col * 480
            peak = max((v for v in values if v is not None), default=None)
            maximum = peak or 1
            peak_label = f"peak {peak:.2f}" if peak is not None else "unavailable"
            segments: list[list[str]] = [[]]
            for i, value in enumerate(values):
                if value is None:
                    if segments[-1]:
                        segments.append([])
                    continue
                segments[-1].append(
                    f"{left + i * 410 / max(1, len(values) - 1):.2f},"
                    f"{top + 155 - value * 120 / maximum:.2f}"
                )
            for segment in segments:
                if segment:
                    coords = " ".join(segment)
                    parts.append(
                        f'<polyline points="{coords}" fill="none" '
                        f'stroke="{color}" stroke-width="1.6"/>'
                    )
            parts += [
                f'<path d="M{left} {top + 25}V{top + 155}H{left + 410}" '
                'fill="none" stroke="#8796a8"/>',
                f'<text x="{left}" y="{top + 18}" font-size="12">{label}, {peak_label}</text>',
                f'<text x="{left}" y="{top + 177}" font-size="12">'
                f"sample 0 → {len(values) - 1} (10s spacing; gaps unknown)</text>",
            ]
    return ("".join(parts) + "</g></svg>").encode()


def outputs(root: Path, config: dict) -> dict[str, bytes]:
    result = calculate(root, config)
    stream = io.StringIO(newline="")
    writer = csv.writer(stream)
    writer.writerow(
        [
            "round",
            "group",
            "attempts",
            "noncompletion_n",
            "noncompletion_N",
            "elapsed_p50_ms",
            "elapsed_p95_ms",
            "input_tokens",
            "output_tokens",
            "reserved_cost_microusd",
            "reported_estimated_cost_microusd",
            "provider_billed_usd",
        ]
    )
    for run in result["evaluations"]:
        for group, data in run["groups"].items():
            writer.writerow(
                [
                    run["id"],
                    group,
                    data["attempts"],
                    data["noncompletion"]["n"],
                    data["noncompletion"]["N"],
                    data["elapsed_ms"]["p50"],
                    data["elapsed_ms"]["p95"],
                    *[
                        data["usage"][key]
                        for key in (
                            "input_tokens",
                            "output_tokens",
                            "cost_microusd",
                            "actual_cost_microusd",
                        )
                    ],
                    "",
                ]
            )
    page = """<!doctype html><html lang="zh-CN"><meta charset="utf-8">
<title>D12 实验分析</title><style>
body{font:16px/1.65 system-ui;max-width:1100px;margin:35px auto;padding:0 22px;
color:#172638;background:#f7f9fc}table{border-collapse:collapse;width:100%;background:white}
td,th{border:1px solid #ccd5df;padding:8px}img{max-width:100%;border:1px solid #ccd5df}
pre{white-space:pre-wrap;background:#fff;padding:16px}</style>
<h1>D12 可复算实验分析</h1><p>合成工程数据 · 本地协议桩 · 正式效果与真实费用未验收</p>
<p>保留历史失败；D11 性能属于其记录版本。耗时包含各轮失败与未完成项，
组执行耗时不能替代单次调查耗时。</p><h2>逐组统计</h2><table><tr><th>轮次 / 组</th>
<th>未完成 / 尝试</th><th>已测耗时 p50 / p95 (ms)</th><th>未测次数</th><th>模型账单</th></tr>"""
    for run in result["evaluations"]:
        for group, d in run["groups"].items():
            times = d["elapsed_ms"]
            timing = (
                f"{times['p50']:.3f} / {times['p95']:.3f}" if times["p50"] is not None else "未知"
            )
            page += (
                f"<tr><td>{html.escape(run['id'])} / {group}</td>"
                f"<td>{d['noncompletion']['n']} / {d['attempts']}</td>"
                f"<td>{timing}</td><td>{times['unmeasured_attempts']}</td>"
                "<td>未知（无供应商账单）</td></tr>"
            )
    page += (
        "</table><p>旧版导入失败的0ms是未测标记，不当作零延迟；仍计入失败分母。"
        "存在未测时全尝试p95未知。</p>"
    )
    page += "<h2>单次调查耗时与预算</h2><table><tr><th>轮次 / 组</th><th>已测次数</th>"
    page += "<th>p50 / p95 ms</th><th>输入 / 输出 token</th><th>预留 / usage估计（μUSD）</th></tr>"
    for run in result["evaluations"]:
        for group, data in run["groups"].items():
            stats = data["investigations"]
            if not stats["attempts"]:
                continue
            values, usage = stats["elapsed_ms"], stats["usage"]
            timing = (
                f"{values['p50']:.3f} / {values['p95']:.3f}"
                if values["p50"] is not None
                else "未知"
            )
            page += (
                f"<tr><td>{html.escape(run['id'])} / {group}</td><td>{values['n']}</td>"
                f"<td>{timing}</td>"
                f"<td>{usage['input_tokens']} / {usage['output_tokens']}</td>"
                f"<td>{usage['cost_microusd']} / {usage['actual_cost_microusd']}</td></tr>"
            )
    page += (
        '</table><h2>全部性能轮次</h2><img src="resources.svg" alt="内存及CPU曲线">'
        "<h2>失败与限制</h2><pre>"
        + html.escape(json.dumps(result["failure_cases"], ensure_ascii=False, indent=2))
        + "</pre><h2>正常替代解释</h2><pre>"
        + html.escape(json.dumps(result["interpretations"], ensure_ascii=False, indent=2))
        + "</pre><h2>历史证据截图</h2>"
    )
    files = {
        "summary.json": encoded(result),
        "metrics.csv": stream.getvalue().encode("utf-8-sig"),
        "resources.svg": chart(result),
        "inputs.json": encoded(config),
    }
    for index, name in enumerate(config["screenshots"]):
        filename = f"evidence-{index}.png"
        files[filename] = (root / name).read_bytes()
        page += (
            f"<p>{html.escape(name)}（历史运行，非实时 AI）</p>"
            f'<img src="{filename}" alt="历史工程验证截图">'
        )
    files["index.html"] = (
        page + "<p>详见 summary.json、metrics.csv 和 inputs.json 的逐项来源与分母。"
        "无正式标签，不报告误报率或 F1。</p></html>"
    ).encode()
    return files


def build_analysis(root: Path, manifest: Path, output: Path) -> dict:
    config = load_inputs(root, manifest)
    files = outputs(root, config)
    output.mkdir(parents=True, exist_ok=False)
    for name, data in files.items():
        (output / name).write_bytes(data)
    record = {
        "version": "d12-analysis-output@1.0.0",
        "files": {n: hashlib.sha256(b).hexdigest() for n, b in files.items()},
    }
    (output / "manifest.json").write_bytes(encoded(record))
    return record


def verify_analysis(root: Path, output: Path) -> dict:
    config = load_inputs(root, output / "inputs.json")
    expected = outputs(root, config)
    record = json.loads((output / "manifest.json").read_bytes())
    if record["files"] != {n: hashlib.sha256(b).hexdigest() for n, b in expected.items()}:
        raise ValueError("ANALYSIS_RECOMPUTATION_MISMATCH")
    for name, data in expected.items():
        if (output / name).read_bytes() != data:
            raise ValueError("ANALYSIS_OUTPUT_CHANGED")
    return {"verified": True, "files": len(expected), "formal_metrics_available": False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    if args.verify:
        print(json.dumps(verify_analysis(ROOT, args.output)))
    elif args.manifest:
        result = build_analysis(ROOT, args.manifest, args.output)
        print(json.dumps({"files": len(result["files"])}))
    else:
        parser.error("--manifest is required when creating an analysis")


if __name__ == "__main__":
    main()
