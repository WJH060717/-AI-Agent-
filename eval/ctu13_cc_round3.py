"""Offline diagnosis and lossless input adaptation; never imported at runtime."""

import argparse
import json
from collections import Counter
from pathlib import Path

from scripts.bro_protocol_sample import FIELDS, rows
from scripts.ctu13_sample import sha

ROOT = Path(__file__).resolve().parents[1]
ALLOWED = {
    "zeek": FIELDS["zeek"],
    "zeek_http": FIELDS["zeek_http"] | {"user_agent", "uri_b64", "user_agent_b64"},
}


def write_sample(output: Path, sources: dict[str, Path], selected: dict[str, list[dict]]) -> dict:
    output.mkdir(parents=True, exist_ok=False)
    manifest = {"adapter": "ctu13-cc-protocol@2", "evaluation": "development_only", "sources": {}}
    for kind, items in selected.items():
        raw = b"".join(
            (
                json.dumps(
                    {k: v for k, v in item["record"].items() if k in ALLOWED[kind]},
                    ensure_ascii=False,
                )
                + "\n"
            ).encode()
            for item in items
        )
        (output / f"{kind}.jsonl").write_bytes(raw)
        mapping = [
            {
                "output_line": i,
                "source_line": item["source_line"],
                "source_line_sha256": item["source_line_sha256"],
                "uid": item["record"]["uid"],
            }
            for i, item in enumerate(items, 1)
        ]
        (output / f"{kind}-map.json").write_text(json.dumps(mapping, indent=2), encoding="utf-8")
        manifest["sources"][kind] = {
            "original": str(sources[kind].resolve()),
            "original_sha256": sha(sources[kind].read_bytes()),
            "jsonl_sha256": sha(raw),
            "records": len(items),
        }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def prepare(output: Path) -> dict:
    previous = ROOT / "artifacts/cc-round2-labels-02/comparison.json"
    audit = json.loads(previous.read_bytes())["cases"]["cc-only"]["connections"]
    cc = {c["uid"] for c in audit if c["official_cc"]}
    remaining = {c["uid"] for c in audit if c["official_cc"] and not c["covered"]}
    normal_path = ROOT / "artifacts/cc-round2-01/samples-01/normal-control/zeek.jsonl"
    normal = {json.loads(line)["uid"] for line in normal_path.read_bytes().splitlines()}
    sources = {
        "zeek": ROOT / "artifacts/ctu13-source-02/download/conn.prefix.log",
        "zeek_http": ROOT / "artifacts/http-round1-01/source-http/http.log",
    }
    rejected, restored = {kind: [] for kind in sources}, []
    data = {
        kind: rows(
            path,
            allowed=ALLOWED[kind],
            rejected=rejected[kind],
            binary_fields={"uri", "user_agent"} if kind == "zeek_http" else None,
            restored=restored,
        )
        for kind, path in sources.items()
    }
    output.mkdir(parents=True, exist_ok=False)
    selection = {
        "previous_audit_sha256": sha(previous.read_bytes()),
        "remaining_uids": sorted(remaining),
        "cc_uids": sorted(cc),
        "normal_uids": sorted(normal),
        "normal_source_sha256": sha(normal_path.read_bytes()),
        "restored": restored,
        "rejected": rejected,
    }
    (output / "offline-selection.json").write_text(
        json.dumps(selection, indent=2), encoding="utf-8"
    )
    events = json.loads((ROOT / "artifacts/cc-round2-check-02/cc-only/events.json").read_bytes())
    by_id = {e["event_id"]: e for e in events}
    diagnosis = []
    for c in audit:
        if c["uid"] not in remaining:
            continue
        event = by_id[c["event_id"]]
        recovered = [r for r in restored if r["uid"] == c["uid"]]
        http = [
            e
            for e in events
            if e["event_type"] == "network.http" and e["network"]["uid"] == c["uid"]
        ]
        reason = (
            "invalid_uri_row_rejected"
            if recovered
            else ("browser_query_gate" if http else "no_http_zero_payload")
        )
        diagnosis.append(
            {
                "uid": c["uid"],
                "previous_event_id": c["event_id"],
                "official_matches": c["matches"],
                "reason": reason,
                "previous_http_rows": len(http),
                "recovered_source_rows": recovered,
                "bytes_out": event["network"]["bytes_out"],
                "bytes_in": event["network"]["bytes_in"],
                "ua_classes": dict(
                    Counter(e["http"]["client_shape"]["user_agent_class"] for e in http)
                ),
                "with_opaque_hex": sum(
                    e["http"]["client_shape"].get("opaque_hex_count", 0) or 0 for e in http
                ),
                "http_statuses": dict(Counter(str(e["http"]["status_code"]) for e in http)),
            }
        )
    (output / "miss-diagnosis.json").write_text(
        json.dumps(
            {
                "previous_audit_sha256": sha(previous.read_bytes()),
                "counts": dict(Counter(d["reason"] for d in diagnosis)),
                "connections": diagnosis,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    result = {}
    for name, uids in [
        ("remaining-only", remaining),
        ("cc-only", cc),
        ("normal-control", normal),
        ("mixed-control", cc | normal),
    ]:
        result[name] = write_sample(
            output / name,
            sources,
            {
                kind: [entry for entry in entries if entry["record"]["uid"] in uids]
                for kind, entries in data.items()
            },
        )
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = prepare(args.output)
    print(
        json.dumps(
            {
                name: {kind: item["records"] for kind, item in value["sources"].items()}
                for name, value in result.items()
            }
        )
    )
