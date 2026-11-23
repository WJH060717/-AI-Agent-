"""Post-run official conn-label audit; never imported by an application process."""

import argparse
import json
import sqlite3
from collections import Counter
from pathlib import Path

from eval.ctu13_label_compare import build_label_index, create_schema, find_matches, label_kind
from scripts.ctu13_sample import sha

ROOT = Path(__file__).resolve().parents[1]


def audit(runtime: Path, samples: Path, output: Path) -> dict:
    output.mkdir(parents=True, exist_ok=False)
    labels = ROOT / "artifacts/ctu13-labels-01/source/capture20110816-2.binetflow"
    database = sqlite3.connect(output / "offline.sqlite")
    database.row_factory = sqlite3.Row
    create_schema(database)
    metadata = build_label_index(database, labels.read_bytes())
    result = {
        "labels_sha256": sha(labels.read_bytes()),
        "official_rows": metadata["records"],
        "basis": "Seen development data; unique conn five-tuple/time labels, not payload truth",
        "cases": {},
    }
    for directory in sorted(
        p for p in runtime.iterdir() if p.is_dir() and (p / "events.json").exists()
    ):
        name = directory.name
        events = {e["event_id"]: e for e in json.loads((directory / "events.json").read_bytes())}
        raw = (samples / name / "zeek.jsonl").read_bytes()
        conn_rows = [json.loads(line) for line in raw.splitlines()]
        details = json.loads((directory / "incident-details.json").read_bytes())
        findings = {
            f["id"]: f for detail in details for f in detail.get("findings", [detail["finding"]])
        }
        cc_findings = [f for f in findings.values() if f["rule_id"] in {"R08", "R09"}]
        covered = {
            event_id for finding in cc_findings for event_id in finding["connection_event_ids"]
        }
        checks = []
        for event in events.values():
            if event["event_type"] != "network.connection":
                continue
            (ref,) = event["source_locators"]
            assert ref["raw_sha256"] == sha(raw)
            record = conn_rows[ref["record_start"] - 1]
            assert record["uid"] == event["network"]["uid"]
            matches = find_matches(database, record)
            category = label_kind(matches[0]["label"]) if len(matches) == 1 else "unknown"
            is_cc = len(matches) == 1 and category == "botnet" and "-CC" in matches[0]["label"]
            http = [
                e
                for e in events.values()
                if e["event_type"] == "network.http"
                and e["network"]["uid"] == record["uid"]
                and e["src"] == event["src"]
                and e["dst"] == event["dst"]
            ]
            reason = (
                "covered"
                if event["event_id"] in covered
                else ("no_imported_http" if not http else "http_present_no_cc_candidate")
            )
            checks.append(
                {
                    "event_id": event["event_id"],
                    "uid": record["uid"],
                    "class": category,
                    "official_cc": is_cc,
                    "covered": event["event_id"] in covered,
                    "http_count": len(http),
                    "coverage_status": reason,
                    "client_shapes": [e["http"].get("client_shape") for e in http],
                    "matches": matches,
                }
            )
        result["cases"][name] = {
            "runtime_events_sha256": sha((directory / "events.json").read_bytes()),
            "runtime_findings_sha256": sha((directory / "incident-details.json").read_bytes()),
            "finding_counts": dict(Counter(f["rule_id"] for f in findings.values())),
            "official_cc_connections": sum(c["official_cc"] for c in checks),
            "covered_official_cc_connections": sum(
                c["official_cc"] and c["covered"] for c in checks
            ),
            "known_normal_connections": sum(c["class"] == "normal" for c in checks),
            "covered_known_normal_connections": sum(
                c["class"] == "normal" and c["covered"] for c in checks
            ),
            "cc_miss_reasons": dict(
                Counter(
                    c["coverage_status"] for c in checks if c["official_cc"] and not c["covered"]
                )
            ),
            "connections": checks,
        }
    database.commit()
    database.close()
    (output / "comparison.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--samples", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = audit(args.runtime, args.samples, args.output)
    print(
        json.dumps(
            {
                name: {key: value for key, value in item.items() if key != "connections"}
                for name, item in result["cases"].items()
            }
        )
    )
