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
        "basis": (
            "Seen development data; unique Bro five-tuple/time labels; "
            "unique full-tuple PCAP correspondence across uncalibrated clocks; "
            "not payload truth"
        ),
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
        cc_findings = [f for f in findings.values() if f["rule_id"] in {"R08", "R09", "R10", "R11"}]
        cross = json.loads((samples / "offline-selection.json").read_bytes())["cross_vantage"]
        pcap_to_bro = {row["pcap_uid"]: row["bro_uid"] for row in cross}
        rules_by_bro = {}
        for finding in cc_findings:
            for event_id in finding["connection_event_ids"]:
                e = events[event_id]
                uid = e["network"]["uid"]
                bro_uid = pcap_to_bro[uid] if e["sensor"]["type"] == "pcap" else uid
                rules_by_bro.setdefault(bro_uid, set()).add(finding["rule_id"])

        checks = []
        for event in events.values():
            if event["event_type"] != "network.connection" or event["sensor"]["type"] != "zeek":
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
            pcap_http = [
                e
                for e in events.values()
                if e["sensor"]["type"] == "pcap"
                and e["event_type"] == "network.http"
                and pcap_to_bro.get(e["network"]["uid"]) == record["uid"]
            ]
            reason = (
                "covered"
                if record["uid"] in rules_by_bro
                else (
                    "no_imported_http"
                    if not http and not pcap_http
                    else "http_present_no_cc_candidate"
                )
            )
            checks.append(
                {
                    "event_id": event["event_id"],
                    "uid": record["uid"],
                    "class": category,
                    "official_cc": is_cc,
                    "covered": record["uid"] in rules_by_bro,
                    "covering_rules": sorted(rules_by_bro.get(record["uid"], set())),
                    "http_count": len(http),
                    "pcap_http_count": len(pcap_http),
                    "pcap_status_counts": dict(
                        Counter(str(e["http"]["status_code"]) for e in pcap_http)
                    ),
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
