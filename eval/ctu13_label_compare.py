"""Offline-only audit of frozen CTU-13 candidates; never imported by the application."""

import argparse
import csv
import hashlib
import json
import sqlite3
from collections import Counter
from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any

VERSION = "ctu13-offline-label-compare@1"
ROOT = Path(__file__).resolve().parents[1]
CEST = timezone(timedelta(hours=2))
EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
TIME_TOLERANCE_US = 1


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def official_time_us(value: str) -> int:
    # Scenario README explicitly records the Aug 16 capture in CEST.
    delta = datetime.strptime(value, "%Y/%m/%d %H:%M:%S.%f").replace(tzinfo=CEST) - EPOCH
    return (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds


def event_time_us(value: object) -> int:
    scaled = Decimal(str(value)) * 1_000_000
    if not scaled.is_finite() or scaled != scaled.to_integral_value():
        raise ValueError("Event timestamp must have finite microsecond precision")
    return int(scaled)


def label_kind(value: str) -> str:
    if not value.startswith("flow="):
        return "unknown_label"
    name = value.removeprefix("flow=")
    if name == "From-Botnet" or name.startswith("From-Botnet-"):
        return "botnet"
    if name == "From-Normal" or name.startswith("From-Normal-"):
        return "normal"
    if name.startswith(("To-Botnet-", "To-Normal-")) or name in {"To-Botnet", "To-Normal"}:
        return "unknown_direction"
    if name == "Background" or name.startswith(
        ("Background-", "From-Background-", "To-Background-")
    ):
        return "background"
    return "unknown_label"


def classify_candidate(evidence: list[dict[str, Any]]) -> str:
    if not evidence or any(item["match_status"] != "unique" for item in evidence):
        return "unknown_incomplete"
    kinds = {item["label_kind"] for item in evidence}
    if kinds == {"normal"}:
        return "known_normal"
    if kinds == {"botnet"}:
        return "botnet_supported"
    if "botnet" in kinds:
        return "mixed_labels"
    if kinds <= {"normal", "background"}:
        return "unknown_background"
    return "unknown_label"


def create_schema(db: sqlite3.Connection) -> None:
    db.executescript("""
        CREATE TABLE official_flows (
          line_no INTEGER PRIMARY KEY, start_us INTEGER NOT NULL,
          protocol TEXT NOT NULL, src_ip TEXT NOT NULL, src_port INTEGER,
          dst_ip TEXT NOT NULL, dst_port INTEGER, direction TEXT NOT NULL,
          label TEXT NOT NULL, original_time TEXT NOT NULL, line_sha256 TEXT NOT NULL
        );
        CREATE INDEX flow_lookup ON official_flows
          (protocol,src_ip,src_port,dst_ip,dst_port,start_us);
        CREATE TABLE evidence (event_id TEXT PRIMARY KEY, payload TEXT NOT NULL);
        CREATE TABLE candidates (incident_id TEXT PRIMARY KEY, payload TEXT NOT NULL);
    """)


def find_matches(db: sqlite3.Connection, record: dict[str, Any]) -> list[dict[str, Any]]:
    start = event_time_us(record["ts"])
    endpoints = (
        record["id.orig_h"],
        record.get("id.orig_p"),
        record["id.resp_h"],
        record.get("id.resp_p"),
    )
    if endpoints[1] is None or endpoints[3] is None:
        return []
    matches: dict[int, dict[str, Any]] = {}
    for orientation, key in [("same", endpoints), ("reversed", endpoints[2:] + endpoints[:2])]:
        rows = db.execute(
            """
            SELECT * FROM official_flows WHERE protocol=? AND src_ip=? AND src_port=?
              AND dst_ip=? AND dst_port=? AND start_us BETWEEN ? AND ? ORDER BY line_no
        """,
            (record["proto"], *key, start - TIME_TOLERANCE_US, start + TIME_TOLERANCE_US),
        )
        for row in rows:
            # Same-endpoint loops can satisfy both orientations: retain one physical row.
            if row["line_no"] not in matches:
                matches[row["line_no"]] = {
                    **dict(row),
                    "orientation": orientation,
                    "time_delta_us": row["start_us"] - start,
                }
    return sorted(matches.values(), key=lambda item: item["line_no"])


def write_json(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8") as target:
        json.dump(value, target, ensure_ascii=False, indent=2)
        target.write("\n")


def build_label_index(db: sqlite3.Connection, raw: bytes) -> dict[str, Any]:
    lines = raw.splitlines(keepends=True)
    header = next(csv.reader([lines[0].decode("utf-8-sig")]))
    expected = (
        "StartTime,Dur,Proto,SrcAddr,Sport,Dir,DstAddr,Dport,State,"
        "sTos,dTos,TotPkts,TotBytes,SrcBytes,Label"
    )
    if header != expected.split(","):
        raise ValueError("Unexpected official label schema")
    label_counts: Counter[str] = Counter()
    unkeyable_tcp = 0
    for line_no, line in enumerate(lines[1:], 2):
        cells = next(csv.reader([line.decode("utf-8")]))
        row = dict(zip(header, cells, strict=True))
        sport = int(row["Sport"]) if row["Sport"].isdigit() else None
        dport = int(row["Dport"]) if row["Dport"].isdigit() else None
        if any(port is not None and not 0 <= port <= 65535 for port in [sport, dport]):
            raise ValueError(f"Invalid port at official line {line_no}")
        unkeyable_tcp += row["Proto"] == "tcp" and (sport is None or dport is None)
        db.execute(
            "INSERT INTO official_flows VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                line_no,
                official_time_us(row["StartTime"]),
                row["Proto"],
                row["SrcAddr"],
                sport,
                row["DstAddr"],
                dport,
                row["Dir"],
                row["Label"],
                row["StartTime"],
                sha256(line),
            ),
        )
        label_counts[row["Label"]] += 1
    return {
        "records": len(lines) - 1,
        "tcp_with_unkeyable_ports": unkeyable_tcp,
        "label_counts": dict(label_counts),
    }


def compare(audit: Path, output: Path) -> dict[str, Any]:
    output.mkdir(parents=True, exist_ok=False)
    frozen = json.loads((audit / "frozen-inputs.json").read_text(encoding="utf-8"))
    for name, expected in frozen.items():
        if sha256((ROOT / name).read_bytes()) != expected:
            raise ValueError(f"Frozen input changed: {name}")
    source = ROOT / "artifacts/ctu13-source-02/adapted-fixed"
    incidents = json.loads(
        (ROOT / "artifacts/ctu13-check-05/incident-details.json").read_text(encoding="utf-8")
    )
    source_manifest = json.loads((source / "manifest.json").read_text(encoding="utf-8"))
    label_raw = (audit / "source/capture20110816-2.binetflow").read_bytes()
    download = json.loads((audit / "source/download.json").read_text(encoding="utf-8-sig"))
    if sha256(label_raw) != download["sha256"] or len(label_raw) != download["byte_count"]:
        raise ValueError("Official label download checksum mismatch")
    if len(label_raw) > 32 * 1024 * 1024:
        raise ValueError("Label input exceeds offline limit")
    raw = (source / "conn.jsonl").read_bytes()
    raw_sha = sha256(raw)
    original = (source / "source-sample.log").read_bytes()
    assert raw_sha == source_manifest["jsonl_sha256"]
    assert sha256(original) == source_manifest["sample_sha256"]
    original_lines = original.splitlines(keepends=True)
    mappings = [json.loads(line) for line in (source / "line-map.jsonl").read_bytes().splitlines()]
    records = raw.splitlines()
    assert len(records) == len(mappings) == source_manifest["accepted_records"]
    needed = {eid for incident in incidents for eid in incident["finding"]["evidence_ids"]}
    scopes = {(item["workspace_id"], item["dataset_id"]) for item in incidents}
    assert len(scopes) == 1 and len(incidents) == 18
    workspace, dataset = next(iter(scopes))
    assert {item["finding"]["group_key"][4] for item in incidents} == {"ctu13-s07-bro"}
    fields = next(line for line in original_lines if line.startswith(b"#fields\t"))
    field_names = fields.decode().rstrip("\r\n").split("\t")[1:]
    evidence: dict[str, dict[str, Any]] = {}
    source_records: dict[str, dict[str, Any]] = {}
    with sqlite3.connect(output / "offline-labels.sqlite") as db:
        db.row_factory = sqlite3.Row
        create_schema(db)
        official_stats = build_label_index(db, label_raw)
        for line_no, raw_line in enumerate(records, 1):
            # The installed stable_event_id contract uses content hash + physical record bounds.
            canonical = json.dumps(
                [
                    workspace,
                    dataset,
                    "ctu13-s07-bro",
                    [(raw_sha, line_no, line_no)],
                ],
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            eid = sha256(canonical.encode())
            if eid not in needed:
                continue
            record = json.loads(raw_line)
            mapping = mappings[line_no - 1]
            source_line = original_lines[mapping["source_line"] - 1]
            assert mapping["output_line"] == line_no and mapping["uid"] == record["uid"]
            assert sha256(source_line) == mapping["source_line_sha256"]
            upstream = dict(
                zip(field_names, source_line.decode().rstrip("\r\n").split("\t"), strict=True)
            )
            assert upstream["uid"] == record["uid"]
            assert event_time_us(upstream["ts"]) == event_time_us(record["ts"])
            for name in ["id.orig_h", "id.resp_h", "proto"]:
                assert upstream[name] == record[name]
            for name in ["id.orig_p", "id.resp_p"]:
                assert int(upstream[name]) == record[name]
            matches = find_matches(db, record)
            evidence[eid] = {
                "event_id": eid,
                "bro_uid": record["uid"],
                "jsonl_line": line_no,
                "source_line": mapping["source_line"],
                "source_line_sha256": mapping["source_line_sha256"],
                "event_start_us": event_time_us(record["ts"]),
                "connection": {
                    key: record[key]
                    for key in ["id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto"]
                },
                "match_status": "unique"
                if len(matches) == 1
                else "unmatched"
                if not matches
                else "ambiguous",
                "label_kind": label_kind(matches[0]["label"]) if len(matches) == 1 else None,
                "official_matches": matches,
            }
            source_records[eid] = record
        assert set(evidence) == needed
        reused = Counter(
            item["official_matches"][0]["line_no"]
            for item in evidence.values()
            if item["match_status"] == "unique"
        )
        for item in evidence.values():
            if (
                item["match_status"] == "unique"
                and reused[item["official_matches"][0]["line_no"]] > 1
            ):
                item["match_status"] = "reused_flow"
        candidates = []
        for number, incident in enumerate(incidents, 1):
            finding = incident["finding"]
            assert finding["rule_id"] == "R05"
            ids = finding["evidence_ids"]
            assert len(ids) == len(set(ids)) == finding["statistics"]["count"]
            assert set(ids) == set(incident["membership"]["evidence_ids"])
            group = finding["group_key"][6:10]
            for eid in ids:
                row = source_records[eid]
                assert group == [row["id.orig_h"], row["id.resp_h"], row["id.resp_p"], row["proto"]]
            items = [evidence[eid] for eid in ids]
            candidate = {
                "number": number,
                "incident_id": incident["id"],
                "finding_id": finding["id"],
                "connection_group": group,
                "start_time": finding["start_time"],
                "end_time": finding["end_time"],
                "evidence_count": len(ids),
                "classification": classify_candidate(items),
                "match_status_counts": dict(Counter(item["match_status"] for item in items)),
                "official_label_counts": dict(
                    Counter(
                        item["official_matches"][0]["label"]
                        for item in items
                        if item["match_status"] == "unique"
                    )
                ),
                "evidence_ids": ids,
            }
            candidates.append(candidate)
            db.execute(
                "INSERT INTO candidates VALUES (?,?)",
                (incident["id"], json.dumps(candidate, ensure_ascii=False)),
            )
        db.executemany(
            "INSERT INTO evidence VALUES (?,?)",
            [(eid, json.dumps(item, ensure_ascii=False)) for eid, item in evidence.items()],
        )
    matched = [
        item["official_matches"][0]
        for item in evidence.values()
        if item["match_status"] == "unique"
    ]
    summary = {
        "candidate_count": len(candidates),
        "unique_evidence_events": len(evidence),
        "candidate_evidence_references": sum(len(x["evidence_ids"]) for x in candidates),
        "candidate_classifications": dict(Counter(x["classification"] for x in candidates)),
        "evidence_match_statuses": dict(Counter(x["match_status"] for x in evidence.values())),
        "evidence_label_kinds": dict(Counter(x["label_kind"] for x in evidence.values())),
        "orientations": dict(Counter(x["orientation"] for x in matched)),
        "max_abs_time_delta_us": max((abs(x["time_delta_us"]) for x in matched), default=None),
        "unique_official_rows_matched": len({x["line_no"] for x in matched}),
        "paid_model_calls": 0,
    }
    result = {
        "version": VERSION,
        "created_at": datetime.now(UTC).isoformat(),
        "summary": summary,
        "input_hashes": frozen,
        "labels_sha256": sha256(label_raw),
        "official_readme_sha256": sha256((audit / "source/official-README.md").read_bytes()),
        "tool_sha256": sha256(Path(__file__).read_bytes()),
        "official_file_statistics": official_stats,
        "matching_policy": {
            "tuple": "TCP five-tuple; either orientation; original label direction unchanged",
            "time": "official CEST (UTC+02:00) start mapped to UTC, +/-1 microsecond",
            "timezone_basis": "Official scenario README: Tue Aug 16 capture timeline in CEST",
            "cardinality": "Unique per event and per official row; conflicts/reuse unknown",
            "background": "unknown; never automatically false positive",
            "metrics": "Candidate composition only; no recall, FPR, accuracy or formal score",
        },
        "candidates": candidates,
    }
    write_json(output / "comparison.json", result)
    with (output / "evidence-matches.jsonl").open("x", encoding="utf-8") as target:
        for eid in sorted(evidence):
            target.write(json.dumps(evidence[eid], ensure_ascii=False) + "\n")
    # No application imports, runtime connections, or model clients exist in this module.
    for name, expected in frozen.items():
        assert sha256((ROOT / name).read_bytes()) == expected
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--audit", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = compare(args.audit.resolve(), args.output.resolve())
    print(json.dumps(result["summary"], ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
