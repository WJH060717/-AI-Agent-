"""Offline development selection; labels never enter runtime upload records."""

import argparse
import json
from pathlib import Path

from scripts.bro_protocol_sample import FIELDS, rows
from scripts.ctu13_sample import sha

ROOT = Path(__file__).resolve().parents[1]
ALLOWED = {"zeek": FIELDS["zeek"], "zeek_http": FIELDS["zeek_http"] | {"user_agent"}}


def write_sample(output: Path, sources: dict[str, Path], selected: dict[str, list[dict]]) -> dict:
    output.mkdir(parents=True, exist_ok=False)
    manifest = {"adapter": "ctu13-cc-protocol@1", "evaluation": "development_only", "sources": {}}
    for kind, items in selected.items():
        raw = b"".join(
            (
                json.dumps(
                    {k: v for k, v in entry["record"].items() if k in ALLOWED[kind]},
                    ensure_ascii=False,
                )
                + "\n"
            ).encode()
            for entry in items
        )
        (output / f"{kind}.jsonl").write_bytes(raw)
        mapping = [
            {
                "output_line": i,
                "source_line": entry["source_line"],
                "source_line_sha256": entry["source_line_sha256"],
                "uid": entry["record"]["uid"],
            }
            for i, entry in enumerate(items, 1)
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
    selection_path = ROOT / "artifacts/ctu13-malicious-01/sample-01/official-selection.json"
    selection = json.loads(selection_path.read_bytes())
    cc = [item for item in selection["matched"] if "-CC" in item["label"]]
    cc_uids = {item["uid"] for item in cc}
    normal_source = ROOT / "artifacts/ctu13-source-04/adapted/conn.jsonl"
    normal_uids = {json.loads(line)["uid"] for line in normal_source.read_bytes().splitlines()}
    sources = {
        "zeek": ROOT / "artifacts/ctu13-source-02/download/conn.prefix.log",
        "zeek_http": ROOT / "artifacts/http-round1-01/source-http/http.log",
    }
    rejected = {kind: [] for kind in sources}
    data = {
        kind: rows(path, rejected=rejected[kind], allowed=ALLOWED[kind])
        for kind, path in sources.items()
    }
    output.mkdir(parents=True, exist_ok=False)
    (output / "offline-selection.json").write_text(
        json.dumps(
            {
                "selection_sha256": sha(selection_path.read_bytes()),
                "cc": cc,
                "normal_source_sha256": sha(normal_source.read_bytes()),
                "normal_uids": sorted(normal_uids),
                "source_rejected": rejected,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    result = {}
    for name, uids in [
        ("cc-only", cc_uids),
        ("normal-control", normal_uids),
        ("mixed-control", cc_uids | normal_uids),
    ]:
        selected = {
            kind: [entry for entry in entries if entry["record"]["uid"] in uids]
            for kind, entries in data.items()
        }
        result[name] = write_sample(output / name, sources, selected)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = prepare(args.output)
    print(
        json.dumps(
            {
                name: {kind: value["records"] for kind, value in item["sources"].items()}
                for name, item in result.items()
            }
        )
    )
