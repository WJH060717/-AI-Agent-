"""Offline sample selection and cross-vantage mapping. Never imported by runtime."""

import argparse
import json
import shutil
from pathlib import Path

from packages.ingest.pcap import adapt
from scripts.ctu13_sample import sha

ROOT = Path(__file__).resolve().parents[1]


def key(record: dict) -> tuple:
    return tuple(record[k] for k in ("id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p"))


def prepare(output: Path) -> dict:
    prior = ROOT / "artifacts/cc-round3-01/samples-01"
    audit_path = ROOT / "artifacts/cc-round3-labels-02/comparison.json"
    audit = json.loads(audit_path.read_bytes())["cases"]["cc-only"]["connections"]
    remaining = {c["uid"] for c in audit if c["official_cc"] and not c["covered"]}
    selected = [
        json.loads(line) for line in (prior / "cc-only/zeek.jsonl").read_bytes().splitlines()
    ]
    by_key = {key(row): row for row in selected}
    assert len(by_key) == len(selected) == 26 and len(remaining) == 21
    capture = ROOT / "artifacts/cc-round4-01/source-pcap/botnet-capture-20110816-sogou.pcap"
    adapted = adapt(capture.read_bytes(), set(by_key))
    assert not adapted["rejected"] and len(adapted["pcap"]) == 26
    output.mkdir(parents=True, exist_ok=False)
    cross = [
        {
            "bro_uid": by_key[key(row)]["uid"],
            "pcap_uid": row["uid"],
            "tuple": key(row),
            "bro_ts": by_key[key(row)]["ts"],
            "pcap_ts": row["ts"],
            "bro_minus_pcap_seconds": by_key[key(row)]["ts"] - row["ts"],
            "basis": (
                "unique full tuple in selected scope; capture clocks uncalibrated; "
                "correspondence not socket/identity proof"
            ),
        }
        for row in adapted["pcap"]
    ]
    (output / "offline-selection.json").write_text(
        json.dumps(
            {
                "previous_audit_sha256": sha(audit_path.read_bytes()),
                "remaining_uids": sorted(remaining),
                "cross_vantage": cross,
                "pcap_sha256": adapted["capture_sha256"],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    result = {}
    for name in ("remaining-only", "cc-only", "normal-control", "mixed-control"):
        dest = output / name
        original_case = "cc-only" if name == "remaining-only" else name
        shutil.copytree(prior / original_case, dest)
        manifest = json.loads((dest / "manifest.json").read_bytes())
        manifest["adapter"] = "ctu13-cc-pcap@1"
        if name == "remaining-only":
            for source in ("zeek", "zeek_http"):
                records = [
                    json.loads(line)
                    for line in (dest / f"{source}.jsonl").read_bytes().splitlines()
                ]
                mappings = json.loads((dest / f"{source}-map.json").read_bytes())
                kept = [
                    (r, m) for r, m in zip(records, mappings, strict=True) if r["uid"] in remaining
                ]
                raw = b"".join(json.dumps(r).encode() + b"\n" for r, _ in kept)
                (dest / f"{source}.jsonl").write_bytes(raw)
                (dest / f"{source}-map.json").write_text(
                    json.dumps(
                        [{**m, "output_line": i} for i, (_, m) in enumerate(kept, 1)], indent=2
                    ),
                    encoding="utf-8",
                )
                manifest["sources"][source].update(jsonl_sha256=sha(raw), records=len(kept))
        if name != "normal-control":
            allowed = {
                row["pcap_uid"]
                for row in cross
                if name != "remaining-only" or row["bro_uid"] in remaining
            }
            for source in ("pcap", "pcap_http"):
                records = [r for r in adapted[source] if r["uid"] in allowed]
                raw = b"".join(json.dumps(r).encode() + b"\n" for r in records)
                (dest / f"{source}.jsonl").write_bytes(raw)
                manifest["sources"][source] = {
                    "original": str(capture.resolve()),
                    "original_sha256": adapted["capture_sha256"],
                    "jsonl_sha256": sha(raw),
                    "records": len(records),
                    "provenance": "pcap-reassembly@1",
                }
            (dest / "pcap-map.json").write_text(
                json.dumps([m for m in adapted["mapping"] if m["uid"] in allowed], indent=2),
                encoding="utf-8",
            )
        (dest / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        result[name] = {k: v["records"] for k, v in manifest["sources"].items()}
    (output / "summary.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    print(json.dumps(prepare(parser.parse_args().output), indent=2))
