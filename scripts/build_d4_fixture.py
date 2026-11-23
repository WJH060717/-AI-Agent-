"""Local synthetic Linux collector protocol examples; generates no network traffic."""

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

HOST = "33333333-3333-4333-8333-333333333333"
START = datetime(2026, 11, 14, 1, tzinfo=UTC)


def fixture_context() -> dict:
    return {
        "assets": [
            {
                "asset_id": HOST,
                "hostnames": ["host-a"],
                "addresses": [
                    {
                        "ip": "10.10.0.20",
                        "observation_domain": "lab-a",
                        "valid_from": "2026-11-14T00:00:00Z",
                        "valid_to": "2026-11-15T00:00:00Z",
                    }
                ],
            }
        ],
        "sensors": [
            {
                "sensor_id": sensor,
                "source_type": source,
                "asset_id": HOST if source.startswith("linux_") else None,
                "instance_id": "synthetic-collector-a",
                "observation_domain": "lab-a",
                "realm_type": "local",
                "realm": "local",
                "offset_ms": 0,
                "uncertainty_ms": 0,
                "clock_basis": "synthetic_clock",
            }
            for sensor, source in (
                ("auth-a", "linux_auth"),
                ("audit-a", "linux_audit"),
                ("net-a", "zeek"),
            )
        ],
    }


def auth(second: int, success: bool = False, uid: str = "1001") -> dict:
    return {
        "timestamp": (START + timedelta(seconds=second)).isoformat(),
        "host": "host-a",
        "boot_id": "boot-a",
        "src_ip": "192.0.2.10",
        "src_port": 42000 + second,
        "dest_ip": "10.10.0.20",
        "dest_port": 22,
        "user": {"name": "demo-user", "uid": uid, "realm": "local"},
        "auth": {
            "outcome": "success" if success else "failure",
            "method": "password",
            "service": "ssh",
        },
        "session_id": "ses-1" if success else None,
        "synthetic": True,
    }


def build(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "context.json").write_text(
        json.dumps(fixture_context(), indent=2) + "\n", encoding="utf-8"
    )
    positive = [auth(i) for i in range(5)] + [auth(10, True)]
    audit = [
        {
            "timestamp": (START + timedelta(seconds=20)).isoformat(),
            "host": "host-a",
            "boot_id": "boot-a",
            "audit_serial": "1",
            "record_type": kind,
            "synthetic": True,
        }
        for kind in ("SYSCALL", "EXECVE", "EOE")
    ]
    audit[0].update(
        process={
            "pid": 42,
            "ppid": 10,
            "action": "exec",
            "start_ticks": 100,
            "parent_start_ticks": 50,
            "identity_basis": "lifecycle_record",
            "executable": "/lab/client",
        },
        user={"name": "demo-user", "uid": "1001", "realm": "local"},
        session_id="ses-1",
    )
    network = [
        {
            "ts": START.timestamp() + i - 1,
            "uid": f"synthetic-auth-{i}",
            "id.orig_h": "192.0.2.10",
            "id.orig_p": 42000 + i,
            "id.resp_h": "10.10.0.20",
            "id.resp_p": 22,
            "proto": "tcp",
            "synthetic": True,
        }
        for i in (0, 1, 2, 3, 4, 10)
    ]
    objects = []
    for name, records in {
        "auth_positive": positive,
        "audit": audit,
        "network": network,
        "auth_below_threshold": positive[:4] + [auth(10, True)],
        "auth_other_account": positive[:5] + [auth(10, True, "2002")],
        "auth_reverse_time": [auth(0, True)] + [auth(i) for i in range(1, 6)],
    }.items():
        content = b"".join((json.dumps(r) + "\n").encode() for r in records)
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
                "scope": "Local fixture generation only; no attacks or network traffic generated",
                "context_sha256": hashlib.sha256((root / "context.json").read_bytes()).hexdigest(),
                "objects": objects,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    build(Path("data/fixtures/d4"))
    print(
        "Generated D4 synthetic development inputs; import counterexamples into separate datasets"
    )
