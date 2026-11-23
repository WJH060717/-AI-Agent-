"""Generate explicitly synthetic D1 samples; this is not a production log parser."""

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

from packages.contracts.models import NormalizedEvent, SourceLocator, stable_event_id

WORKSPACE = UUID("11111111-1111-4111-8111-111111111111")
DATASET = UUID("77777777-7777-4777-8777-777777777777")
HOST_A = "33333333-3333-4333-8333-333333333333"
HOST_B = "44444444-4444-4444-8444-444444444444"


def main() -> None:
    root = Path("data/fixtures/d1")
    root.mkdir(parents=True, exist_ok=True)
    start = datetime(2026, 11, 14, 1, tzinfo=UTC)
    objects = []
    events = []
    for group, (sensor_type, count) in enumerate(
        [("zeek", 8), ("linux_auth", 8), ("linux_audit", 4), ("suricata", 4)], start=1
    ):
        rows = []
        payloads = []
        for i in range(count):
            ts = start + timedelta(seconds=i + group * 10)
            base = {"timestamp": ts.isoformat(), "synthetic": True}
            src = {"ip": "192.0.2.10", "port": 42000 + i}
            dst = {
                "ip": "10.10.0.20",
                "port": 22,
                "asset_id": HOST_A,
                "resolution_quality": "inventory_interval",
            }
            if sensor_type == "zeek":
                raw = {
                    "ts": ts.timestamp(),
                    "uid": f"synthetic-C{i}",
                    "id.orig_h": src["ip"],
                    "id.orig_p": src["port"],
                    "id.resp_h": dst["ip"],
                    "id.resp_p": 22,
                    "proto": "tcp",
                    "orig_bytes": 120,
                    "resp_bytes": 240,
                    "synthetic": True,
                }
                payload = {
                    "event_type": "network.connection",
                    "src": src,
                    "dst": dst,
                    "network": {
                        "transport": "tcp",
                        "uid": raw["uid"],
                        "bytes_out": 120,
                        "bytes_in": 240,
                    },
                }
            elif sensor_type == "linux_auth":
                auth = {
                    "outcome": "success" if i == 7 else "failure",
                    "method": "password",
                    "service": "ssh",
                }
                session_id = "synthetic-s1" if auth["outcome"] == "success" else None
                raw = base | {
                    "host": "host-a",
                    "src": src,
                    "auth": auth,
                    "user": "u01",
                    "session_id": session_id,
                }
                payload = {
                    "event_type": "auth.login",
                    "src": src,
                    "dst": dst,
                    "asset_id": HOST_A,
                    "auth": auth,
                    "user": {
                        "entity_id": "user:lab-a:u01",
                        "name_redacted": "u01",
                        "realm": "lab-a",
                        "session_id": session_id,
                    },
                }
            elif sensor_type == "linux_audit":
                process = {
                    "pid": 100 + i,
                    "action": "create",
                    "boot_id": "synthetic-boot-a",
                    "start_ticks": 1000 + i,
                    "entity_id": f"proc:synthetic:{i}",
                    "identity_basis": "lifecycle_record",
                    "executable": "/lab/test-client",
                }
                if i:
                    process["parent_entity_id"] = f"proc:synthetic:{i - 1}"
                raw = base | {"audit_serial": str(i), "process": process, "host": "host-a"}
                payload = {"event_type": "host.process", "process": process, "asset_id": HOST_A}
            else:
                alert = {
                    "rule_id": "synthetic-lab-001",
                    "signature": "LAB test signal",
                    "native_severity": 2,
                    "category": "synthetic",
                }
                raw = base | {
                    "event_type": "alert",
                    "src_ip": src["ip"],
                    "dest_ip": dst["ip"],
                    "alert": alert,
                }
                payload = {"event_type": "security.alert", "src": src, "dst": dst, "alert": alert}
            rows.append(raw)
            payloads.append((ts, payload))
        raw_bytes = ("\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n").encode()
        name = f"{sensor_type}.jsonl"
        (root / name).write_bytes(raw_bytes)
        digest = hashlib.sha256(raw_bytes).hexdigest()
        object_id = UUID(f"22222222-2222-4222-8222-{group:012d}")
        objects.append(
            {
                "object_id": str(object_id),
                "path": name,
                "sha256": digest,
                "byte_size": len(raw_bytes),
                "record_count": count,
            }
        )
        for i, (ts, payload) in enumerate(payloads, start=1):
            locator = SourceLocator(
                object_id=object_id, record_start=i, record_end=i, raw_sha256=digest
            )
            sensor_id = f"synthetic-{sensor_type}"
            event = NormalizedEvent.model_validate(
                {
                    "schema_version": "1.0",
                    "workspace_id": WORKSPACE,
                    "dataset_id": DATASET,
                    "event_id": stable_event_id(WORKSPACE, DATASET, sensor_id, [locator]),
                    "event_time": ts,
                    "ingested_at": ts + timedelta(seconds=1),
                    "time_quality": {
                        "original": ts.isoformat(),
                        "timezone": "UTC",
                        "offset_ms": 0,
                        "uncertainty_ms": 0,
                        "basis": "synthetic_fixture",
                    },
                    "sensor": {
                        "sensor_id": sensor_id,
                        "type": sensor_type,
                        "instance_id": "synthetic-boot-a",
                        "observation_domain": "lab-a",
                    },
                    "source_locators": [locator],
                    "parser_version": "synthetic-generator@1.0.0",
                    "quality_flags": ["synthetic"],
                    **payload,
                }
            )
            events.append(event.model_dump_json())
    (root / "events.jsonl").write_bytes(("\n".join(events) + "\n").encode())
    manifest = {
        "schema_version": "1.0",
        "workspace_id": str(WORKSPACE),
        "dataset_id": str(DATASET),
        "provenance_type": "synthetic",
        "split": "development",
        "authorized_scope": "local fixture generation only; no network activity",
        "strong_identity_basis": "synthetic lifecycle data, NOT real host collection",
        "event_count": len(events),
        "raw_objects": objects,
        "events_sha256": hashlib.sha256((root / "events.jsonl").read_bytes()).hexdigest(),
    }
    (root / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (root / "assets.json").write_text(
        json.dumps(
            [
                {"asset_id": HOST_A, "name": "host-a", "ip": "10.10.0.20"},
                {"asset_id": HOST_B, "name": "host-b", "ip": "10.10.0.30"},
            ],
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"Generated {len(events)} synthetic events; raw SHA-256 manifest written")


if __name__ == "__main__":
    main()
