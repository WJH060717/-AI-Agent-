"""D7 synthetic development inputs; generates files, no attacks or network traffic."""

import hashlib
import json
from copy import deepcopy
from datetime import timedelta
from pathlib import Path

from scripts.build_d4_fixture import HOST, START, fixture_context


def build(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    context = fixture_context()
    reference = {
        "id": "synthetic-normal-development-v1",
        "version": "1.0.0",
        "asset_id": HOST,
        "sensor_id": "net-a",
        "instance_id": "synthetic-collector-a",
        "observation_domain": "lab-a",
        "provenance_type": "synthetic",
        "source_sha256": hashlib.sha256(b"synthetic normal development reference v1").hexdigest(),
        "samples": [
            {
                "start": (START - timedelta(seconds=300 * (i + 1))).isoformat(),
                "end": (START - timedelta(seconds=300 * i)).isoformat(),
                "bytes_out": 1_000_000,
            }
            for i in range(30)
        ],
    }
    context["egress_baselines"] = [reference]
    normal = deepcopy(context)
    for window in normal["egress_baselines"][0]["samples"]:
        window["bytes_out"] = 8_000_000
    normal["egress_baselines"][0]["id"] = "synthetic-normal-backup-development-v1"
    normal["egress_baselines"][0]["source_sha256"] = hashlib.sha256(
        b"synthetic normal backup development reference v1"
    ).hexdigest()
    network = [
        {
            "ts": (START + timedelta(seconds=10 + 60 * i)).timestamp(),
            "uid": f"periodic-{i}",
            "id.orig_h": "10.10.0.20",
            "id.orig_p": 40000 + i,
            "id.resp_h": "198.51.100.10",
            "id.resp_p": 8443,
            "proto": "tcp",
            "orig_bytes": 1000,
            "resp_bytes": 100,
            "synthetic": True,
        }
        for i in range(8)
    ]
    network.append(
        {
            "ts": (START + timedelta(seconds=20)).timestamp(),
            "uid": "bulk-counter",
            "id.orig_h": "10.10.0.20",
            "id.orig_p": 43000,
            "id.resp_h": "198.51.100.20",
            "id.resp_p": 443,
            "proto": "tcp",
            "orig_bytes": 12_000_000,
            "resp_bytes": 100,
            "synthetic": True,
        }
    )
    irregular = deepcopy(network)
    for row, second in zip(irregular[:8], [10, 15, 35, 80, 210, 305, 400, 430], strict=True):
        row["ts"] = (START + timedelta(seconds=second)).timestamp()
    irregular[-1]["orig_bytes"] = 1000
    audit = []
    for pid, second, executable in ((80, 60, "/usr/bin/node_exporter"), (90, 25, "/usr/bin/rsync")):
        common = {
            "timestamp": (START + timedelta(seconds=second)).isoformat(),
            "host": "host-a",
            "boot_id": "boot-a",
            "audit_serial": str(pid),
            "synthetic": True,
        }
        audit += [
            common
            | {
                "record_type": "SYSCALL",
                "user": {"uid": "1001", "name": "demo-user", "realm": "local"},
                "process": {
                    "pid": pid,
                    "action": "create",
                    "start_ticks": pid * 100,
                    "identity_basis": "lifecycle_record",
                    "executable": executable,
                },
            },
            common | {"record_type": "EOE"},
        ]
    for name, data in (("context", context), ("normal_context", normal)):
        (root / f"{name}.json").write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    objects = []
    for name, rows in (("network", network), ("audit", audit), ("irregular_network", irregular)):
        content = b"".join((json.dumps(row) + "\n").encode() for row in rows)
        (root / f"{name}.jsonl").write_bytes(content)
        objects.append(
            {
                "path": name + ".jsonl",
                "records": len(rows),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        )
    (root / "manifest.json").write_text(
        json.dumps(
            {
                "provenance_type": "synthetic",
                "split": "development",
                "scope": "Local files only; no traffic, attacks or ground-truth inputs to runtime",
                "context_sha256": hashlib.sha256((root / "context.json").read_bytes()).hexdigest(),
                "normal_context_sha256": hashlib.sha256(
                    (root / "normal_context.json").read_bytes()
                ).hexdigest(),
                "objects": objects,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    build(Path("data/fixtures/d7"))
    print("Generated D7 synthetic development fixtures; no real capture or LLM evaluation")
