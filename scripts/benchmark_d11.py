"""Real local HTTP ingestion/query measurements. Synthetic input; never a formal detection score."""

import argparse
import hashlib
import json
import math
import os
import platform
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

import httpx

from packages.config import Settings
from packages.storage.database import Database
from packages.storage.service import DataService
from scripts.browser_d3 import port, wait_for
from scripts.release_manifest import encoded, write_new

ROOT = Path(__file__).resolve().parents[1]
BENCHMARK_CONFIG = {
    "app_env": "test",
    "app_bind": "127.0.0.1",
    "model_provider": "disabled",
    "model_test_stub": False,
    "detection_event_limit": 10000,
    "import_chunk_lines": 500,
    "snapshot_event_limit": 250,
    "worker_poll_seconds": 0.05,
    "worker_lease_seconds": 60,
    "worker_heartbeat_seconds": 10,
    "worker_max_attempts": 3,
    "api_read_requests_per_minute": 6000,
    "api_write_requests_per_minute": 1000,
    "api_rate_max_identities": 1024,
    "max_upload_mb": 100,
}


def benchmark_settings(folder: Path) -> Settings:
    values = {key: field.get_default() for key, field in Settings.model_fields.items()}
    values.update(BENCHMARK_CONFIG)
    values.update(
        database_url=f"sqlite:///{folder / 'test.db'}",
        raw_store=folder / "raw",
        staging_store=folder / "staging",
    )
    return Settings(_env_file=None, **values)


def process_environment(settings: Settings, api_port: int) -> dict[str, str]:
    # Child cwd is the fresh temporary folder, so no repository .env is read.
    # Remove ALL inherited Settings keys, including model credentials, then set
    # only the explicit test settings. No environment-supplied workload shortcuts.
    keys = {key.upper() for key in Settings.model_fields}
    env = {key: value for key, value in os.environ.items() if key.upper() not in keys}
    for key, value in settings.model_dump(mode="json", exclude_none=True).items():
        if key != "database_url":
            env[key.upper()] = str(value).lower() if isinstance(value, bool) else str(value)
    env.update(
        DATABASE_URL=settings.database_url.get_secret_value(),
        APP_PORT=str(api_port),
        PYTHONPATH=str(ROOT),
    )
    return env


def records(offset: int, count: int) -> bytes:
    if offset < 0 or not 1 <= count <= 500:
        raise ValueError("INVALID_FRAGMENT")
    return b"".join(
        (
            json.dumps(
                {
                    "ts": 1794618000 + i / 50,
                    "uid": f"d11-synthetic-{i}",
                    "id.orig_h": "192.0.2.10",
                    "id.orig_p": 40000 + i % 20000,
                    "id.resp_h": "10.10.0.20",
                    "id.resp_p": 443,
                    "proto": "tcp",
                    "synthetic": True,
                },
                separators=(",", ":"),
            )
            + "\n"
        ).encode()
        for i in range(offset, offset + count)
    )


def percentile(values: list[float], fraction: float) -> float | None:
    return sorted(values)[max(0, math.ceil(len(values) * fraction) - 1)] if values else None


def summarize(
    samples: list[dict],
    *,
    profile: str,
    final_count: int,
    drain_seconds: float,
    duration_seconds: float,
) -> dict:
    batches = [s for s in samples if s["kind"] == "batch" and s["phase"] == "ingest"]
    queries = [s for s in samples if s["kind"] == "query"]
    expected = sum(s["expected"] for s in batches)
    counts = {
        key: sum(s.get(key, 0) for s in batches)
        for key in ("accepted", "duplicate", "quarantined", "raw_records")
    }
    accounted = sum(counts[k] for k in ("accepted", "duplicate", "quarantined"))
    p95 = percentile([s["elapsed_ms"] for s in queries], 0.95)
    query_failures = sum(s["status"] != 200 for s in queries)
    failures = sum(s["status"] not in {"succeeded", "partial"} for s in batches)
    coverage = (
        "partial"
        if any(s.get("error_code") == "RULE_SCOPE_TOO_LARGE" for s in batches)
        else "complete"
    )
    return {
        "profile": profile,
        "input_mode": "new_ingestion",
        "provenance_type": "synthetic",
        "submitted_batches": len(batches),
        "record_accounting": {"numerator": accounted, "denominator": expected},
        **counts,
        "failed_batches": failures,
        "duration_seconds": duration_seconds,
        "drain_seconds": drain_seconds,
        "query_dataset_events": final_count,
        "queries": len(queries),
        "query_failures": query_failures,
        "query_p50_ms": percentile([s["elapsed_ms"] for s in queries], 0.5),
        "query_p95_ms": p95,
        "detection_coverage": coverage,
        "full_protocol_passed": (
            profile == "full"
            and len(batches) == 180
            and expected == accounted == 90000
            and counts["raw_records"] == 90000
            and counts["duplicate"] == 0
            and failures == 0
            and 1800 <= duration_seconds
            and drain_seconds <= 60
            and final_count == 100000
            and len(queries) == 100
            and query_failures == 0
            and p95 is not None
            and p95 <= 2000
        ),
        "replay": {"status": "not_implemented", "rate": None},
        "limitations": [
            "Synthetic local engineering benchmark; not formal evaluation or production capacity.",
            "Durable ingestion does not make partial detection coverage complete.",
            "Replay is not measured; TC-038 stays partial even if ingestion/query targets pass.",
        ],
    }


def runtime_files() -> dict[str, str]:
    paths = [ROOT / "pyproject.toml", ROOT / "requirements-dev.lock", Path(__file__).resolve()]
    paths.extend(ROOT / name for name in ("scripts/browser_d3.py", "scripts/release_manifest.py"))
    for folder in ("apps/api", "apps/worker", "packages", "migrations"):
        paths.extend(p for p in (ROOT / folder).rglob("*.py") if "__pycache__" not in p.parts)
    paths.extend((ROOT / "rules").glob("*.json"))
    return {
        p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(paths)
    }


def resources(processes: list[subprocess.Popen]) -> dict:
    if os.name != "nt":
        return {"status": "unsupported_platform", "processes": []}
    ids = ",".join(str(p.pid) for p in processes)
    command = (
        f"$benchIds=@({ids}); $frontier=$benchIds; "
        "foreach($depth in 1..3) { $children=@(foreach($pidValue in $frontier) { "
        "Get-CimInstance Win32_Process -Filter ('ParentProcessId = '+$pidValue) | "
        "Select-Object -ExpandProperty ProcessId }); "
        "$benchIds += $children; $frontier=$children }; "
        "@(Get-Process -Id ($benchIds | Sort-Object -Unique) -ErrorAction SilentlyContinue | "
        "Select-Object Id,CPU,WorkingSet64,PrivateMemorySize64) | ConvertTo-Json -Compress"
    )
    result = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        timeout=8,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    if result.returncode:
        return {"status": "sample_failed", "processes": []}
    value = json.loads(result.stdout or b"[]")
    return {"status": "measured", "processes": value if isinstance(value, list) else [value]}


def stop_process(process: subprocess.Popen) -> None:
    if process.poll() is None:
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], capture_output=True)
        else:
            process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def run(output: Path, profile: str) -> dict:
    output.mkdir(parents=True, exist_ok=False)
    source_hashes = runtime_files()
    full = profile == "full"
    batches, interval, target, query_count = (
        (180, 10.0, 100000, 100) if full else (2, 0.1, 1000, 10)
    )
    samples: list[dict] = []
    processes: list[subprocess.Popen] = []
    errors: list[dict] = []
    metadata = {
        "started_at": datetime.now(UTC).isoformat(),
        "profile": profile,
        "platform": platform.platform(),
        "python": platform.python_version(),
        "cpu_count": os.cpu_count(),
        "database": "SQLite, new isolated database",
        "model": "disabled",
        "concurrency": 1,
        "batch_records": 500,
        "batch_interval_seconds": interval,
        "scheduled_batches": batches,
        "duration_seconds": batches * interval,
        "query_target_events": target,
        "query_requests": query_count,
        "query_mix": "alternating /events?limit=100 and /overview, serial HTTP client timing",
        "api_read_requests_per_minute": 6000,
        "api_write_requests_per_minute": 1000,
        "effective_settings": BENCHMARK_CONFIG,
        "settings_source": (
            "explicit defaults and benchmark overrides; isolated cwd; inherited settings removed"
        ),
        "runtime_files": source_hashes,
    }
    write_new(output / "protocol.json", encoded(metadata))
    with (output / "samples.jsonl").open("x", encoding="utf-8") as journal:

        def append(value: dict) -> None:
            entry = {"recorded_at": datetime.now(UTC).isoformat(), **value}
            samples.append(entry)
            journal.write(json.dumps(entry, ensure_ascii=False) + "\n")
            journal.flush()

        with tempfile.TemporaryDirectory(
            prefix="trace-d11-bench-", ignore_cleanup_errors=True
        ) as temp:
            folder = Path(temp)
            settings = benchmark_settings(folder)
            db = Database(settings)
            db.migrate()
            _, tokens = DataService(db, settings).init_workspace("D11 synthetic benchmark")
            db.engine.dispose()
            api_port = port()
            env = process_environment(settings, api_port)
            with (output / "services.log").open("x", encoding="utf-8") as log:
                try:
                    for module in ("apps.api.main", "apps.worker"):
                        processes.append(
                            subprocess.Popen(
                                [sys.executable, "-m", module],
                                cwd=folder,
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
                        timeout=60,
                    ) as client:
                        response = client.post(
                            "/datasets",
                            headers={"Idempotency-Key": "benchmark"},
                            json={"name": "D11 synthetic load", "provenance_type": "synthetic"},
                        )
                        response.raise_for_status()
                        dataset = response.json()
                        scope = {
                            "dataset_id": dataset["dataset_id"],
                            "session_id": dataset["default_session_id"],
                        }
                        assert client.get("/overview", params=scope).json()["event_count"] == 0
                        uploaded = []

                        def upload(index: int, phase: str) -> None:
                            raw = records(index * 500, 500)
                            started = time.perf_counter()
                            result = client.post(
                                "/imports",
                                headers={"Idempotency-Key": f"fragment-{index}"},
                                data={
                                    "dataset_id": dataset["dataset_id"],
                                    "source_type": "zeek",
                                    "sensor_id": "d11-benchmark",
                                    "timezone": "UTC",
                                },
                                files={"file": ("fragment.jsonl", raw, "application/x-ndjson")},
                            )
                            append(
                                {
                                    "kind": "upload",
                                    "phase": phase,
                                    "index": index,
                                    "offset": index * 500,
                                    "expected": 500,
                                    "sha256": hashlib.sha256(raw).hexdigest(),
                                    "status": result.status_code,
                                    "elapsed_ms": (time.perf_counter() - started) * 1000,
                                }
                            )
                            if result.status_code == 202:
                                uploaded.append((result.json()["batch_id"], phase, index))
                            else:
                                append(
                                    {
                                        "kind": "batch",
                                        "phase": phase,
                                        "index": index,
                                        "expected": 500,
                                        "status": "upload_failed",
                                    }
                                )

                        def drain(deadline: float) -> None:
                            while uploaded:
                                remaining = []
                                for batch_id, phase, index in uploaded:
                                    reply = client.get(f"/imports/{batch_id}")
                                    reply.raise_for_status()
                                    value = reply.json()
                                    if (
                                        value["status"] in {"queued", "running"}
                                        and time.monotonic() < deadline
                                    ):
                                        remaining.append((batch_id, phase, index))
                                    else:
                                        append(
                                            {
                                                "kind": "batch",
                                                "phase": phase,
                                                "index": index,
                                                "expected": 500,
                                                **value,
                                            }
                                        )
                                uploaded[:] = remaining
                                if uploaded:
                                    time.sleep(0.2)

                        started = time.monotonic()
                        for index in range(batches):
                            time.sleep(max(0, started + index * interval - time.monotonic()))
                            append(
                                {
                                    "kind": "schedule",
                                    "index": index,
                                    "lag_seconds": time.monotonic() - started - index * interval,
                                }
                            )
                            upload(index, "ingest")
                            if full or index == 0:
                                append({"kind": "resources", **resources(processes)})
                        time.sleep(max(0, started + batches * interval - time.monotonic()))
                        scheduled_end = started + batches * interval
                        drain(scheduled_end + 60)
                        drain_seconds = max(0.0, time.monotonic() - scheduled_end)
                        duration = max(
                            batches * interval, time.monotonic() - started - drain_seconds
                        )
                        for index in range(batches, target // 500):
                            upload(index, "query_preload")
                        drain(time.monotonic() + 120)
                        total = client.get("/overview", params=scope)
                        total.raise_for_status()
                        final_count = total.json()["event_count"]
                        for index in range(query_count):
                            route = "/events" if index % 2 == 0 else "/overview"
                            before = time.perf_counter()
                            result = client.get(
                                route, params=scope | ({"limit": 100} if route == "/events" else {})
                            )
                            append(
                                {
                                    "kind": "query",
                                    "route": route,
                                    "status": result.status_code,
                                    "elapsed_ms": (time.perf_counter() - before) * 1000,
                                }
                            )
                        summary = summarize(
                            samples,
                            profile=profile,
                            final_count=final_count,
                            drain_seconds=drain_seconds,
                            duration_seconds=duration,
                        )
                except Exception as exc:
                    errors.append({"type": type(exc).__name__})
                    append({"kind": "fatal_error", "type": type(exc).__name__})
                    summary = {"profile": profile, "full_protocol_passed": False}
                finally:
                    for process in reversed(processes):
                        stop_process(process)
    summary["errors"] = errors
    summary["runtime_unchanged"] = source_hashes == runtime_files()
    if errors or not summary["runtime_unchanged"]:
        summary["full_protocol_passed"] = False
    summary["samples_sha256"] = hashlib.sha256((output / "samples.jsonl").read_bytes()).hexdigest()
    write_new(output / "summary.json", encoded(summary))
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=["smoke", "full"], default="smoke")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = run(args.output.resolve(), args.profile)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        if result["errors"] or not result["runtime_unchanged"]:
            raise SystemExit(1)
        if args.profile == "full" and not result["full_protocol_passed"]:
            raise SystemExit(2)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"BENCHMARK_FAILED:{type(exc).__name__}\n")


if __name__ == "__main__":
    main()
