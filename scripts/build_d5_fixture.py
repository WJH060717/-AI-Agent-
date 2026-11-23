"""Safe local D5 development inputs; no scanning, attacks, or external collection."""

import hashlib
import json
from pathlib import Path

from scripts.build_d4_fixture import START, auth, fixture_context


def build(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "context.json").write_text(
        json.dumps(fixture_context(), indent=2) + "\n", encoding="utf-8"
    )
    network = [
        {
            "ts": START.timestamp() + i,
            "uid": f"synthetic-scan-{i}",
            "id.orig_h": "192.0.2.10",
            "id.orig_p": 42000 + i,
            "id.resp_h": "10.10.0.20",
            "id.resp_p": i + 1,
            "proto": "tcp",
            "synthetic": True,
        }
        for i in range(24)
    ]
    authentication = [auth(i) for i in range(5, 10)] + [auth(22, True)]
    authentication[-1]["src_port"] = 42021
    audit = []
    for pid, ppid, birth, parent_birth, second in ((10, 1, 50, 1, 30), (42, 10, 100, 50, 40)):
        timestamp = f"2026-11-14T01:00:{second}Z"
        base = {
            "timestamp": timestamp,
            "host": "host-a",
            "boot_id": "boot-a",
            "audit_serial": str(pid),
            "synthetic": True,
        }
        audit += [
            base
            | {
                "record_type": "SYSCALL",
                "session_id": "ses-1",
                "user": {"uid": "1001", "name": "demo-user", "realm": "local"},
                "process": {
                    "pid": pid,
                    "ppid": ppid,
                    "start_ticks": birth,
                    "parent_start_ticks": parent_birth,
                    "action": "create",
                    "identity_basis": "lifecycle_record",
                    "executable": "/lab/client",
                },
            },
            base | {"record_type": "EOE"},
        ]
    no_session = [{k: v for k, v in row.items() if k != "session_id"} for row in audit]
    objects = []
    for name, records in {
        "network": network,
        "auth": authentication,
        "audit": audit,
        "audit_without_session": no_session,
    }.items():
        content = b"".join((json.dumps(record) + "\n").encode() for record in records)
        (root / f"{name}.jsonl").write_bytes(content)
        objects.append(
            {
                "path": f"{name}.jsonl",
                "records": len(records),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        )
    (root / "manifest.json").write_text(
        json.dumps(
            {
                "provenance_type": "synthetic",
                "split": "development",
                "scope": "Local generation only; no attacks or network traffic generated",
                "context_sha256": hashlib.sha256((root / "context.json").read_bytes()).hexdigest(),
                "objects": objects,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    build(Path("data/fixtures/d5"))
    print("Generated D5 development fixtures; use new datasets for counterexamples")
