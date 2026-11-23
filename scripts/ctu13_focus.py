"""Extract a complete connection sequence from an already frozen parent sample."""

import argparse
import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from scripts.ctu13_sample import sha


def extract(parent: Path, output: Path, key: list) -> dict:
    if output.exists():
        raise FileExistsError(output)
    manifest = json.loads((parent / "manifest.json").read_text(encoding="utf-8"))
    raw = (parent / "conn.jsonl").read_bytes()
    sample = (parent / "source-sample.log").read_bytes()
    if sha(raw) != manifest["jsonl_sha256"] or sha(sample) != manifest["sample_sha256"]:
        raise ValueError("parent_integrity_mismatch")
    records = raw.splitlines(keepends=True)
    maps = [json.loads(line) for line in (parent / "line-map.jsonl").read_bytes().splitlines()]
    if len(records) != len(maps):
        raise ValueError("parent_mapping_integrity_mismatch")
    lines: list[bytes] = []
    mapping: list[dict] = []
    times: list[float] = []
    warnings: Counter[str] = Counter()
    for index, (line, location) in enumerate(zip(records, maps, strict=True), 1):
        record = json.loads(line)
        if location["output_line"] != index or location["uid"] != record["uid"]:
            raise ValueError("parent_mapping_integrity_mismatch")
        if [
            record["id.orig_h"],
            record["id.resp_h"],
            record.get("id.resp_p"),
            record["proto"],
        ] != key:
            continue
        lines.append(line)
        mapping.append({**location, "output_line": len(lines), "parent_output_line": index})
        times.append(record["ts"])
        if "duration" not in record:
            warnings["duration_unknown"] += 1
        if "orig_bytes" not in record or "resp_bytes" not in record:
            warnings["byte_count_unknown"] += 1
        if record.get("missed_bytes", 0) > 0:
            warnings["source_reports_missed_bytes"] += 1
    if not 1 <= len(lines) <= 250:
        raise ValueError("whole_connection_sequence_must_have_1_to_250_records")
    data = b"".join(lines)
    result = {
        **manifest,
        "selection_tool": "ctu13-whole-connection@1.1",
        "selection_tool_sha256": sha(Path(__file__).read_bytes()),
        "parent_jsonl_sha256": manifest["jsonl_sha256"],
        "jsonl_sha256": sha(data),
        "jsonl_bytes": len(data),
        "selected_records": len(lines),
        "accepted_records": len(lines),
        "rejected_records": 0,
        "scanned_records": len(records),
        "skipped_other_protocol": 0,
        "skipped_other_connections": len(records) - len(lines),
        "protocols": {str(key[3]): len(lines)},
        "connection_key": key,
        "selection": "complete_connection_sequence_within_frozen_parent_sample",
        "selection_purpose": "targeted_engineering_positive_not_blind_evaluation",
        "same_capture_as_parent": True,
        "independent_sample": False,
        "selection_truncated": True,
        "event_time_min": datetime.fromtimestamp(min(times), UTC).isoformat(),
        "event_time_max": datetime.fromtimestamp(max(times), UTC).isoformat(),
        "parent_warnings": manifest["warnings"],
        "warnings": dict(warnings),
    }
    output.mkdir(parents=True, exist_ok=False)
    (output / "source-sample.log").write_bytes(sample)
    (output / "conn.jsonl").write_bytes(data)
    (output / "line-map.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in mapping), encoding="utf-8"
    )
    (output / "rejected.jsonl").write_text("", encoding="utf-8")
    (output / "manifest.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--parent", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--candidates", type=Path, required=True)
    args = parser.parse_args()
    candidates = json.loads(args.candidates.read_text(encoding="utf-8"))
    print(
        json.dumps(extract(args.parent, args.output, candidates["candidates"][0]["key"]), indent=2)
    )


if __name__ == "__main__":
    main()
