import hashlib
import json
from uuid import uuid4

from packages.ingest.parsers import ParseContext

HOST = "33333333-3333-4333-8333-333333333333"
OTHER = "44444444-4444-4444-8444-444444444444"


def context_payload():
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
                "sensor_id": "auth-a",
                "source_type": "linux_auth",
                "asset_id": HOST,
                "instance_id": "collector-a",
                "observation_domain": "lab-a",
                "realm": "local",
                "realm_type": "local",
                "offset_ms": 0,
                "uncertainty_ms": 0,
                "clock_basis": "synthetic_clock",
            },
            {
                "sensor_id": "audit-a",
                "source_type": "linux_audit",
                "asset_id": HOST,
                "instance_id": "collector-a",
                "observation_domain": "lab-a",
                "realm": "local",
                "realm_type": "local",
                "offset_ms": 0,
                "uncertainty_ms": 0,
                "clock_basis": "synthetic_clock",
            },
        ],
    }


def auth_record(i=0, outcome="failure"):
    return {
        "timestamp": f"2026-11-14T01:00:{i:02d}Z",
        "host": "host-a",
        "boot_id": "boot-a",
        "src_ip": "192.0.2.10",
        "src_port": 42000 + i,
        "user": {"name": "alice", "uid": "1001", "realm": "local"},
        "auth": {"outcome": outcome, "method": "password", "service": "ssh"},
        "session_id": "ses-1" if outcome == "success" else None,
        "synthetic": True,
    }


def audit_record(kind, serial="1", **changes):
    record = {
        "timestamp": "2026-11-14T01:00:10Z",
        "host": "host-a",
        "boot_id": "boot-a",
        "audit_serial": serial,
        "record_type": kind,
        "synthetic": True,
    }
    if kind == "SYSCALL":
        record["process"] = {
            "pid": 42,
            "ppid": 10,
            "action": "exec",
            "start_ticks": 100,
            "parent_start_ticks": 50,
            "identity_basis": "lifecycle_record",
            "executable": "/lab/client",
        }
        record["user"] = {"uid": "1001", "name": "alice", "realm": "local"}
        record["session_id"] = "ses-1"
    return record | changes


def parse_context(source, raw, payload=None):
    return ParseContext(
        str(uuid4()),
        str(uuid4()),
        str(uuid4()),
        hashlib.sha256(raw).hexdigest(),
        "auth-a" if source == "linux_auth" else "audit-a",
        source,
        "UTC",
        metadata=payload or context_payload(),
        identity_salt="a" * 64,
    )


def raw_lines(records):
    return b"".join((json.dumps(record) + "\n").encode() for record in records)
