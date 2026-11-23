"""Measured existing-event replay over real local HTTP; synthetic engineering data only."""

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import httpx
from sqlalchemy import select

from packages.storage import schema_v6 as t
from packages.storage.database import Database
from packages.storage.service import DataService
from scripts.benchmark_d11 import (
    ROOT,
    benchmark_settings,
    percentile,
    process_environment,
    records,
    runtime_files,
    stop_process,
)
from scripts.browser_d3 import port, wait_for


def source_records(count: int) -> bytes:
    return b"".join(records(offset, min(500, count - offset)) for offset in range(0, count, 500))


def event_digest(db: Database, workspace: str) -> tuple[int, str]:
    h = hashlib.sha256()
    count = 0
    with db.engine.connect() as conn:
        for row in conn.execution_options(yield_per=500).execute(
            select(t.events.c.event_id, t.events.c.payload)
            .where(t.events.c.workspace_id == workspace)
            .order_by(t.events.c.event_id)
        ):
            h.update(json.dumps(list(row), sort_keys=True, separators=(",", ":")).encode())
            count += 1
    return count, h.hexdigest()


def measured_sources() -> dict[str, str]:
    return runtime_files() | {
        "scripts/benchmark_p1_replay.py": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    }


def poll_status(
    client: httpx.Client, path: str, deadline: float, record: Callable[[dict], None]
) -> dict:
    """Only transient read unavailability is retried, visibly and within the job deadline."""
    while True:
        reply = client.get(path)
        if reply.status_code != 503:
            reply.raise_for_status()
            return reply.json()
        record({"kind": "transient_poll_error", "path": path, "status": 503})
        if time.monotonic() >= deadline:
            raise TimeoutError("STATUS_POLL_TIMEOUT")
        time.sleep(0.25)


def run(output: Path, count: int, rate: int, full_detection: bool = False) -> dict:
    output.mkdir(parents=True, exist_ok=False)
    private = ROOT / ".tools" / output.name
    private.mkdir(exist_ok=False)
    settings = benchmark_settings(private)
    if full_detection:
        settings.detection_event_limit = 100000
    db = Database(settings)
    db.migrate()
    service = DataService(db, settings)
    workspace, tokens = service.init_workspace("P1 synthetic replay measurement")
    source_hashes = measured_sources()
    knowledge_hashes = {
        p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in (ROOT / "knowledge/attack-18.1").iterdir()
        if p.is_file()
    }
    protocol = {
        "started_at": datetime.now(UTC).isoformat(),
        "input_mode": "replay",
        "provenance_type": "synthetic",
        "model": "disabled",
        "events": count,
        "rate_eps": rate,
        "query_requests": 100,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "runtime_files": source_hashes,
        "knowledge_files": knowledge_hashes,
        "database": "new isolated SQLite",
        "new_ingestion_throughput_measured": False,
        "full_detection_required": full_detection,
        "detection_event_limit": settings.detection_event_limit,
    }
    (output / "protocol.json").write_text(json.dumps(protocol, indent=2), encoding="utf8")
    processes, samples = [], []
    api_port = port()
    env = process_environment(settings, api_port)
    result = {"passed": False}
    with (
        (output / "services.log").open("x", encoding="utf8") as log,
        (output / "samples.jsonl").open("x", encoding="utf8") as journal,
    ):

        def record(item: dict) -> None:
            value = {"recorded_at": datetime.now(UTC).isoformat(), **item}
            samples.append(value)
            journal.write(json.dumps(value) + "\n")
            journal.flush()

        try:
            for module in ("apps.api.main", "apps.worker"):
                processes.append(
                    subprocess.Popen(
                        [sys.executable, "-m", module],
                        cwd=private,
                        env=env,
                        stdout=log,
                        stderr=log,
                        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                    )
                )
            base = f"http://127.0.0.1:{api_port}"
            wait_for(base + "/api/v1/health/live")
            with httpx.Client(
                base_url=base + "/api/v1",
                headers={"Authorization": f"Bearer {tokens['admin']}"},
                timeout=120,
            ) as client:
                reply = client.post(
                    "/datasets",
                    headers={"Idempotency-Key": "dataset"},
                    json={"name": "P1 replay benchmark", "provenance_type": "synthetic"},
                )
                reply.raise_for_status()
                dataset = reply.json()
                raw = source_records(count)
                record(
                    {
                        "kind": "source",
                        "records": count,
                        "sha256": hashlib.sha256(raw).hexdigest(),
                        "bytes": len(raw),
                    }
                )
                uploaded = client.post(
                    "/imports",
                    headers={"Idempotency-Key": "input"},
                    data={
                        "dataset_id": dataset["dataset_id"],
                        "source_type": "zeek",
                        "sensor_id": "p1-benchmark",
                        "timezone": "UTC",
                    },
                    files={"file": ("synthetic.jsonl", raw, "application/x-ndjson")},
                )
                uploaded.raise_for_status()
                deadline = time.monotonic() + 600
                while True:
                    batch = poll_status(
                        client, "/imports/" + uploaded.json()["batch_id"], deadline, record
                    )
                    if batch["status"] not in {"queued", "running"}:
                        break
                    if time.monotonic() > deadline:
                        raise TimeoutError("SOURCE_PREPARATION_TIMEOUT")
                    time.sleep(0.25)
                record({"kind": "source_import", **batch})
                if batch["accepted"] != count or batch["quarantined"] or batch["duplicate"]:
                    raise RuntimeError("SOURCE_ACCOUNTING")
                before_count, before_hash = event_digest(db, workspace)
                reply = client.post(
                    f"/datasets/{dataset['dataset_id']}/replays",
                    headers={"Idempotency-Key": "replay"},
                    json={"source_session_id": dataset["default_session_id"], "rate_eps": rate},
                )
                reply.raise_for_status()
                replay = reply.json()
                started = time.perf_counter()
                deadline = time.monotonic() + count / rate + 120
                while True:
                    state = poll_status(client, "/replays/" + replay["job_id"], deadline, record)
                    record(
                        {
                            "kind": "progress",
                            "elapsed_seconds": time.perf_counter() - started,
                            **state,
                        }
                    )
                    if state["state"] not in {"queued", "running"}:
                        break
                    if time.monotonic() > deadline:
                        raise TimeoutError("REPLAY_TIMEOUT")
                    time.sleep(0.25)
                duration = time.perf_counter() - started
                params = {"dataset_id": dataset["dataset_id"], "session_id": replay["session_id"]}
                for i in range(100):
                    path = "/overview" if i % 2 else "/events"
                    at = time.perf_counter()
                    reply = client.get(path, params=params if i % 2 else params | {"limit": 100})
                    record(
                        {
                            "kind": "query",
                            "path": path,
                            "status": reply.status_code,
                            "elapsed_ms": (time.perf_counter() - at) * 1000,
                        }
                    )
                    reply.raise_for_status()
                after_count, after_hash = event_digest(db, workspace)
                with db.engine.connect() as conn:
                    source_ids, replay_ids = [
                        set(
                            conn.execute(
                                select(t.members.c.event_id).where(
                                    t.members.c.workspace_id == workspace,
                                    t.members.c.session_id == session,
                                )
                            ).scalars()
                        )
                        for session in (dataset["default_session_id"], replay["session_id"])
                    ]
                times = [s["elapsed_ms"] for s in samples if s["kind"] == "query"]
                result = {
                    "input_mode": "replay",
                    "source_events": before_count,
                    "published_events": state["published_events"],
                    "requested_eps": rate,
                    "measured_seconds": duration,
                    "observed_visibility_eps": count / duration,
                    "source_events_unchanged": before_count == after_count == count
                    and before_hash == after_hash,
                    "member_sets_equal": source_ids == replay_ids and len(source_ids) == count,
                    "source_import_status": batch["status"],
                    "events_sha256_before": before_hash,
                    "events_sha256_after": after_hash,
                    "query_requests": len(times),
                    "query_p95_ms": percentile(times, 0.95),
                    "detection_status": state["detection_status"],
                    "warnings": state["warnings"],
                    "terminal_state": state["state"],
                    "new_ingestion_throughput_measured": False,
                    "formal_detection_evaluation": False,
                    "transient_poll_errors": sum(
                        s["kind"] == "transient_poll_error" for s in samples
                    ),
                }
                result["passed"] = (
                    result["source_events_unchanged"]
                    and result["member_sets_equal"]
                    and state["published_events"] == count
                    and state["state"] in {"completed", "partial"}
                    and duration >= count / rate * 0.98
                    and len(times) == 100
                    and result["query_p95_ms"] <= 2000
                    and (
                        not full_detection
                        or (
                            state["state"] == "completed"
                            and state["detection_status"] == "complete"
                            and batch["status"] == "succeeded"
                        )
                    )
                )
        except Exception as exc:
            result = {"passed": False, "error_type": type(exc).__name__, "input_mode": "replay"}
            record({"kind": "failure", "type": type(exc).__name__})
        finally:
            for process in reversed(processes):
                stop_process(process)
            db.engine.dispose()
    result["runtime_unchanged"] = source_hashes == measured_sources()
    result["passed"] &= result["runtime_unchanged"]
    result["samples_sha256"] = hashlib.sha256((output / "samples.jsonl").read_bytes()).hexdigest()
    (output / "summary.json").write_text(json.dumps(result, indent=2), encoding="utf8")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--count", type=int, default=100000)
    parser.add_argument("--rate", type=int, default=1000)
    parser.add_argument("--full-detection", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.count <= 100000 or not 1 <= args.rate <= 1000:
        parser.error("count must be 1..100000 and rate 1..1000")
    summary = run(args.output.resolve(), args.count, args.rate, args.full_detection)
    print(json.dumps(summary, indent=2))
    raise SystemExit(0 if summary["passed"] else 1)
