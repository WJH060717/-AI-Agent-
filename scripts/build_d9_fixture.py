"""Synthetic development demos derived from D6/D7; no traffic or attack execution."""

import hashlib
import json
from pathlib import Path

from scripts.build_d6_fixture import build as build_s1
from scripts.build_d7_fixture import build as build_s2


def build(root: Path) -> None:
    first, second = root / "S1", root / "S2"
    build_s1(first)
    build_s2(second)
    context = json.loads((first / "context.json").read_bytes())
    periodic = json.loads((second / "context.json").read_bytes())
    context["egress_baselines"] = periodic["egress_baselines"]
    network_profile = next(s for s in context["sensors"] if s["source_type"] == "zeek")
    context["sensors"].append(network_profile | {"sensor_id": "alert-a", "source_type": "suricata"})
    (first / "context.json").write_text(
        json.dumps(context, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    bulk = json.loads((second / "network.jsonl").read_text(encoding="utf-8").splitlines()[-1])
    bulk.update(ts=1794618120.0, uid="synthetic-d9-transfer-counter")
    with (first / "network.jsonl").open("a", encoding="utf-8") as output:
        output.write(json.dumps(bulk) + "\n")
    alert = {
        "timestamp": "2026-11-14T01:00:40+00:00",
        "synthetic": True,
        "event_type": "alert",
        "src_ip": "192.0.2.10",
        "dest_ip": "10.10.0.20",
        "alert": {"signature_id": 9900001, "signature": "LAB synthetic observation", "severity": 2},
    }
    (first / "alerts.jsonl").write_text(json.dumps(alert) + "\n", encoding="utf-8")
    for folder in (first, second):
        manifest = {
            "version": "d9-demo@1.0.0",
            "scenario_id": folder.name,
            "provenance_type": "synthetic",
            "independent_evaluation_run": False,
            "activity_group": "legacy-development-regression",
            "authorized_scope": "local synthetic fixtures; no network activity",
            "limitations": [
                "Derived from D6/D7 development templates; not 33 independent runs.",
                "Transfer byte counters do not establish file contents, "
                "process sockets or attack causation.",
                "S3 uses S2 without audit; S2 includes monitoring/backup alternative context.",
            ],
            "objects": [
                {"path": p.name, "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
                for p in sorted(folder.iterdir())
                if p.suffix in {".json", ".jsonl"} and p.name != "manifest.json"
            ],
        }
        (folder / "manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )


if __name__ == "__main__":
    build(Path("data/fixtures/d9"))
