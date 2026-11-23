"""Offline label-based selection; labels never enter the application input file."""

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from eval.ctu13_label_compare import event_time_us, label_kind, official_time_us
from scripts.ctu13_sample import convert, sha

VERSION = "ctu13-official-malicious-sample@1"
ROOT = Path(__file__).resolve().parents[1]


def select_records(bro: bytes, labels: bytes) -> dict[str, Any]:
    if max(len(bro), len(labels)) > 32 * 1024 * 1024:
        raise ValueError("source_exceeds_32MiB_bound")
    lines = bro.splitlines(keepends=True)
    fields = next(line for line in lines if line.startswith(b"#fields\t"))
    names = fields.decode().rstrip("\r\n").split("\t")[1:]
    index: dict[tuple, list[dict]] = defaultdict(list)
    scanned = 0
    for number, line in enumerate(lines, 1):
        if line.startswith(b"#"):
            continue
        scanned += 1
        row = dict(zip(names, line.decode().rstrip("\r\n").split("\t"), strict=True))
        if row["proto"] not in {"tcp", "udp"}:
            continue
        if not row["id.orig_p"].isdigit() or not row["id.resp_p"].isdigit():
            continue
        key = (
            row["proto"],
            row["id.orig_h"],
            int(row["id.orig_p"]),
            row["id.resp_h"],
            int(row["id.resp_p"]),
            event_time_us(row["ts"]),
        )
        index[key].append(
            {"source_line": number, "uid": row["uid"], "source_line_sha256": sha(line)}
        )
    label_lines = labels.splitlines(keepends=True)
    header = next(csv.reader([label_lines[0].decode("utf-8-sig")]))
    matched = []
    unresolved = []
    count = 0
    for number, line in enumerate(label_lines[1:], 2):
        row = dict(zip(header, next(csv.reader([line.decode()])), strict=True))
        if label_kind(row["Label"]) != "botnet":
            continue
        count += 1
        metadata = {
            "official_line": number,
            "official_line_sha256": sha(line),
            "label": row["Label"],
        }
        if (
            row["Proto"] not in {"tcp", "udp"}
            or not row["Sport"].isdigit()
            or not row["Dport"].isdigit()
        ):
            unresolved.append({**metadata, "reason": "unkeyable_official_flow"})
            continue
        key = (
            row["Proto"],
            row["SrcAddr"],
            int(row["Sport"]),
            row["DstAddr"],
            int(row["Dport"]),
            official_time_us(row["StartTime"]),
        )
        reverse = (key[0], key[3], key[4], key[1], key[2], key[5])
        found = {
            item["source_line"]: {**item, "orientation": orientation}
            for candidate, orientation in [(key, "same"), (reverse, "reversed")]
            for item in index.get(candidate, [])
        }
        if len(found) != 1:
            unresolved.append(
                {
                    **metadata,
                    "reason": "unmatched" if not found else "ambiguous_bro_rows",
                    "candidate_source_lines": sorted(found),
                }
            )
        else:
            matched.append({**metadata, **next(iter(found.values())), "time_delta_us": 0})
    repeated = Counter(item["source_line"] for item in matched)
    unique = []
    for item in matched:
        if repeated[item["source_line"]] == 1:
            unique.append(item)
        else:
            unresolved.append({**item, "reason": "reused_bro_row"})
    return {
        "official_from_botnet": count,
        "scanned_bro_records": scanned,
        "matched": sorted(unique, key=lambda item: item["source_line"]),
        "unresolved": sorted(unresolved, key=lambda item: item["official_line"]),
    }


def save(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8") as target:
        json.dump(value, target, ensure_ascii=False, indent=2)
        target.write("\n")


def prepare(bro_path: Path, label_path: Path, output: Path) -> dict[str, Any]:
    if output.exists():
        raise FileExistsError(output)
    bro = bro_path.read_bytes()
    labels = label_path.read_bytes()
    selected = select_records(bro, labels)
    if not 1 <= len(selected["matched"]) <= 10000:
        raise ValueError("matched_sample_must_have_1_to_10000_records")
    output.mkdir(parents=True, exist_ok=False)
    save(
        output / "official-selection.json",
        {
            **selected,
            "version": VERSION,
            "tool_sha256": sha(Path(__file__).read_bytes()),
            "bro_file_sha256": sha(bro),
            "official_labels_sha256": sha(labels),
            "selection_is_label_based": True,
            "purpose": "targeted_functional_test_not_blind_test",
        },
    )
    lines = bro.splitlines(keepends=True)
    headers = [line for line in lines if line.startswith(b"#") and not line.startswith(b"#close\t")]
    selected_bytes = b"".join(
        headers + [lines[item["source_line"] - 1] for item in selected["matched"]]
    )
    selected_file = output / "selected-original.log"
    selected_file.write_bytes(selected_bytes)
    intermediate = output / "adapter-intermediate"
    manifest = convert(selected_file, intermediate)
    assert manifest["accepted_records"] == len(selected["matched"])
    assert manifest["rejected_records"] == 0
    converted = (intermediate / "conn.jsonl").read_bytes()
    records = [json.loads(line) for line in converted.splitlines()]
    intermediate_maps = [
        json.loads(line) for line in (intermediate / "line-map.jsonl").read_bytes().splitlines()
    ]
    mappings = []
    for number, (row, mapping, selected_row) in enumerate(
        zip(records, intermediate_maps, selected["matched"], strict=True), 1
    ):
        assert row["uid"] == mapping["uid"] == selected_row["uid"]
        assert mapping["source_line_sha256"] == selected_row["source_line_sha256"]
        assert not any("label" in key.lower() or "botnet" in key.lower() for key in row)
        mappings.append(
            {**mapping, "output_line": number, "source_line": selected_row["source_line"]}
        )
    final = output / "adapted"
    final.mkdir()
    (final / "source-sample.log").write_bytes(bro)
    (final / "conn.jsonl").write_bytes(converted)
    (final / "line-map.jsonl").write_text(
        "".join(json.dumps(item) + "\n" for item in mappings), encoding="utf-8"
    )
    (final / "rejected.jsonl").write_text("", encoding="utf-8")
    result = {
        **manifest,
        "selection_tool": VERSION,
        "selection_tool_sha256": sha(Path(__file__).read_bytes()),
        "selection": "all_unique_Bro_rows_exactly_matching_official_From-Botnet_flows",
        "source_sha256": sha(bro),
        "source_bytes": len(bro),
        "sample_sha256": sha(bro),
        "sample_bytes": len(bro),
        "scanned_records": selected["scanned_bro_records"],
        "skipped_nonselected_source_records": selected["scanned_bro_records"] - len(records),
        "official_from_botnet_flows": selected["official_from_botnet"],
        "official_flows_unresolved": len(selected["unresolved"]),
        "labels_read": True,
        "labels_used_only_for_offline_selection": True,
        "runtime_input_contains_labels": False,
        "source_is_complete_capture": False,
        "selection_truncated": True,
        "selection_purpose": "official_label_selected_functional_test_not_blind_evaluation",
        "limitations": manifest["limitations"][1:]
        + [
            "Unmatched official records excluded and retained in official-selection.json",
            "Label-selected subset does not preserve all background context",
            "Official malicious label does not guarantee coverage by current rules",
        ],
    }
    save(final / "manifest.json", result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--audit", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    frozen = json.loads((args.audit / "frozen-inputs.json").read_text(encoding="utf-8"))
    for path, expected in frozen.items():
        if sha((ROOT / path).read_bytes()) != expected:
            raise ValueError(f"Frozen input changed: {path}")
    result = prepare(
        ROOT / "artifacts/ctu13-source-02/download/conn.prefix.log",
        ROOT / "artifacts/ctu13-labels-01/source/capture20110816-2.binetflow",
        args.output,
    )
    print(
        json.dumps(
            {
                name: result[name]
                for name in [
                    "accepted_records",
                    "protocols",
                    "warnings",
                    "official_from_botnet_flows",
                    "official_flows_unresolved",
                    "event_time_min",
                    "event_time_max",
                    "jsonl_sha256",
                ]
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
