"""D6 local development fixtures. No attack execution or real network traffic."""

import hashlib
import json
from pathlib import Path

from scripts.build_d4_fixture import START, auth, fixture_context

B = "44444444-4444-4444-8444-444444444444"


def build(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    context = fixture_context()
    context["assets"].append(
        {
            "asset_id": B,
            "hostnames": ["host-b"],
            "addresses": [
                {
                    "ip": "10.10.0.30",
                    "observation_domain": "lab-a",
                    "valid_from": "2026-11-14T00:00:00Z",
                    "valid_to": "2026-11-15T00:00:00Z",
                }
            ],
        }
    )
    context["sensors"].append(context["sensors"][0] | {"sensor_id": "auth-b", "asset_id": B})
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
    network.append(
        {
            "ts": START.timestamp() + 50,
            "uid": "synthetic-remote",
            "id.orig_h": "10.10.0.20",
            "id.orig_p": 43000,
            "id.resp_h": "10.10.0.30",
            "id.resp_p": 22,
            "proto": "tcp",
            "synthetic": True,
        }
    )
    authentication = [auth(i) for i in range(5, 10)] + [auth(22, True)]
    authentication[-1]["src_port"] = 42021
    remote = auth(51, True) | {
        "host": "host-b",
        "boot_id": "boot-b",
        "src_ip": "10.10.0.20",
        "src_port": 43000,
        "dest_ip": "10.10.0.30",
        "dest_port": 22,
        "session_id": "b-session",
    }
    audit, normal_audit = [], []
    for pid, ppid, birth, parent_birth, second, exe in (
        (10, 1, 50, 1, 30, "/usr/sbin/nginx"),
        (42, 10, 100, 50, 40, "/bin/sh"),
        (77, 42, 150, 100, 45, "/lab/helper"),
    ):
        base = {
            "timestamp": f"2026-11-14T01:00:{second}Z",
            "host": "host-a",
            "boot_id": "boot-a",
            "audit_serial": str(pid),
            "synthetic": True,
        }
        call = base | {
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
                "executable": exe,
            },
        }
        audit += [call, base | {"record_type": "EOE"}]
        normal_call = call | {
            "process": call["process"] | {"executable": "/usr/sbin/nginx" if pid == 42 else exe}
        }
        normal_audit += [normal_call, base | {"record_type": "EOE"}]
    objects = []
    payloads = {
        "network": network,
        "auth_a": authentication,
        "audit": audit,
        "auth_b": [remote],
        "normal_network": network[-1:],
        "normal_auth_a": authentication[-1:],
        "normal_audit": normal_audit,
    }
    (root / "context.json").write_text(json.dumps(context, indent=2) + "\n", encoding="utf-8")
    for name, records in payloads.items():
        content = b"".join((json.dumps(row) + "\n").encode() for row in records)
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
                "scope": "Local fixture generation only; no network traffic or attacks",
                "context_sha256": hashlib.sha256((root / "context.json").read_bytes()).hexdigest(),
                "objects": objects,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    build(Path("data/fixtures/d6"))
    print("Generated D6 synthetic development fixtures; test models are not real LLM inference")
