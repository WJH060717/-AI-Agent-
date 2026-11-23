"""Real CTU-13 derived sample through installed API/worker/web, isolated from 8080."""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import httpx

from scripts.browser_installed_audit import command, production_fingerprint
from scripts.ctu13_environment import isolated

ROOT = Path(__file__).resolve().parents[1]


def save(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def wait_terminal(client: httpx.Client, path: str, field: str, timeout: int = 180) -> dict:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        response = client.get(path)
        response.raise_for_status()
        status = response.json()
        if status[field] not in {"queued", "running"}:
            return status
        time.sleep(0.3)
    raise RuntimeError(f"timeout_waiting_for_{field}")


def pages(client: httpx.Client, path: str, params: dict | None = None) -> list[dict]:
    params = {**(params or {}), "limit": 100}
    result: list[dict] = []
    while True:
        response = client.get(path, params=params)
        response.raise_for_status()
        body = response.json()
        result.extend(body["items"])
        if not body.get("next_cursor"):
            return result
        params["cursor"] = body["next_cursor"]


def verify(env: dict, source: Path, output: Path) -> dict:
    manifest = json.loads((source / "manifest.json").read_text(encoding="utf-8"))
    raw = (source / "conn.jsonl").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == manifest["jsonl_sha256"]
    rows = [json.loads(line) for line in raw.splitlines()]
    mapping = [json.loads(line) for line in (source / "line-map.jsonl").read_bytes().splitlines()]
    original = (source / "source-sample.log").read_bytes().splitlines(keepends=True)
    assert len(rows) == len(mapping) == manifest["accepted_records"]
    fields = (
        next(line for line in original if line.startswith(b"#fields\t"))
        .decode()
        .strip()
        .split("\t")[1:]
    )
    assert hashlib.sha256(b"".join(original)).hexdigest() == manifest["sample_sha256"]
    for index, entry in enumerate(mapping, 1):
        assert (
            hashlib.sha256(original[entry["source_line"] - 1]).hexdigest()
            == entry["source_line_sha256"]
        )
        assert entry["output_line"] == index and entry["uid"] == rows[index - 1]["uid"]
        cells = original[entry["source_line"] - 1].decode().rstrip("\r\n").split("\t")
        upstream = dict(zip(fields, cells, strict=True))
        derived = rows[index - 1]
        assert upstream["uid"] == derived["uid"]
        assert float(upstream["ts"]) == derived["ts"]
        for prefix in ["orig", "resp"]:
            assert upstream[f"id.{prefix}_h"] == derived[f"id.{prefix}_h"]
            port_key = f"id.{prefix}_p"
            if derived["proto"] in {"icmp", "icmpv6"}:
                target_key = "icmp_type" if prefix == "orig" else "icmp_code"
            else:
                target_key = port_key
            assert derived.get(target_key) == (
                None if upstream[port_key] == "-" else int(upstream[port_key])
            )
        for name in ["orig_bytes", "resp_bytes", "duration"]:
            source_value = upstream[name]
            expected = (
                None
                if source_value == "-"
                else float(source_value)
                if name == "duration"
                else int(source_value)
            )
            assert derived.get(name) == expected
    base = env["url"] + "/api/v1"
    with httpx.Client(
        base_url=base,
        headers={"Authorization": f"Bearer {env['tokens']['admin']}"},
        timeout=90,
        trust_env=False,
    ) as client:
        response = client.post(
            "/datasets",
            headers={"Idempotency-Key": str(uuid4())},
            json={"name": "CTU-13 场景7 · 实采派生小样本", "provenance_type": "derived"},
        )
        response.raise_for_status()
        dataset = response.json()
        save(output / "dataset.json", dataset)
        scope = {"dataset_id": dataset["dataset_id"], "session_id": dataset["default_session_id"]}
        imports = []
        for attempt in range(2):
            response = client.post(
                "/imports",
                headers={"Idempotency-Key": str(uuid4())},
                data={
                    "dataset_id": dataset["dataset_id"],
                    "source_type": "zeek",
                    "sensor_id": "ctu13-s07-bro",
                    "timezone": "UTC",
                },
                files={"file": ("ctu13-s07-prefix.jsonl", raw, "application/json")},
            )
            response.raise_for_status()
            batch = response.json()
            status = wait_terminal(client, f"/imports/{batch['batch_id']}", "status")
            imports.append(status)
            save(output / f"import-{attempt + 1}.json", status)
            print(
                f"Import {attempt + 1}: {status['status']} accepted={status['accepted']} "
                f"duplicate={status['duplicate']} quarantined={status['quarantined']}",
                flush=True,
            )
            assert status["status"] == "succeeded", status
            assert status["quarantined"] == 0
            assert status["accepted"] == (len(rows) if attempt == 0 else 0)
            assert status["duplicate"] == (0 if attempt == 0 else len(rows))
        events = pages(client, "/events", scope)
        assert len(events) == len(rows)
        assert len({e["event_id"] for e in events}) == len(rows)
        source_lines: set[int] = set()
        for event in events:
            (ref,) = event["source_locators"]
            line = ref["record_start"]
            assert line == ref["record_end"] and ref["raw_sha256"] == manifest["jsonl_sha256"]
            record = rows[line - 1]
            source_lines.add(line)
            assert event["network"]["uid"] == record["uid"]
            assert event["event_time"] == datetime.fromtimestamp(
                record["ts"], UTC
            ).isoformat().replace("+00:00", "Z")
            for endpoint, prefix in [("src", "orig"), ("dst", "resp")]:
                assert event[endpoint]["ip"] == record[f"id.{prefix}_h"]
                assert event[endpoint]["port"] == record.get(f"id.{prefix}_p")
                assert event[endpoint]["asset_id"] is None
            assert event["network"]["transport"] == record["proto"]
            assert event["network"]["bytes_out"] == record.get("orig_bytes")
            assert event["network"]["bytes_in"] == record.get("resp_bytes")
            assert event["network"]["duration_ms"] == (
                record["duration"] * 1000 if "duration" in record else None
            )
            assert (
                "synthetic" not in event["quality_flags"]
                and "clock_uncertain" in event["quality_flags"]
            )
            assert event["process"] is None and event["auth"] is None and event["host"] is None
        assert len(source_lines) == len(rows)
        overview = client.get("/overview", params=scope)
        overview.raise_for_status()
        save(output / "overview.json", overview.json())
        incidents = pages(client, "/incidents", scope)
        save(output / "incidents.json", incidents)
        print(
            f"Verified {len(events)} events field-by-field; incidents={len(incidents)}", flush=True
        )
        details = []
        reports = []
        blocked = []
        for index, incident in enumerate(incidents):
            response = client.get(f"/incidents/{incident['id']}")
            response.raise_for_status()
            details.append(response.json())
            response = client.post(
                f"/incidents/{incident['id']}/investigations",
                headers={"Idempotency-Key": str(uuid4())},
                json={"mode": "deterministic"},
            )
            if response.status_code == 422:
                body = response.json()
                save(output / f"investigation-refused-{index + 1}.json", body)
                if body.get("error", {}).get("code") == "SNAPSHOT_EMPTY_OR_TOO_LARGE":
                    blocked.append(
                        {"incident_id": incident["id"], "reason": "SNAPSHOT_EMPTY_OR_TOO_LARGE"}
                    )
                    continue
            response.raise_for_status()
            created = response.json()
            run = wait_terminal(client, f"/investigations/{created['run_id']}", "state")
            save(output / f"run-{index + 1}.json", run)
            assert run["state"] in {"completed", "partial"}, run
            assert run["budget_used"]["model_calls"] == 0
            response = client.get(f"/reports/{run['report_id']}")
            response.raise_for_status()
            report = response.json()
            save(output / f"report-{index + 1}.json", report)
            assert report["mode"] == "deterministic_fallback"
            assert report["validation"] == "passed", report
            timeline = pages(client, f"/investigations/{created['run_id']}/timeline")
            snapshot_ids = {event["event_id"] for event in timeline}
            evidence_checked = 0
            for claim in report["claims"]:
                for ref in claim.get("evidence_refs", []):
                    assert ref["event_id"] in snapshot_ids
                    response = client.get(
                        f"/evidence/{ref['event_id']}", params={"snapshot_id": run["snapshot_id"]}
                    )
                    response.raise_for_status()
                    evidence = response.json()
                    for fragment in evidence["fragments"]:
                        assert fragment["sha256"] == manifest["jsonl_sha256"]
                        for item in fragment["lines"]:
                            projected = json.loads(item["text"])
                            expected = rows[item["line"] - 1]
                            assert all(expected[k] == v for k, v in projected.items())
                    evidence_checked += 1
            graph = client.get(f"/investigations/{created['run_id']}/graph")
            graph.raise_for_status()
            save(output / f"graph-{index + 1}.json", graph.json())
            graph_ids = {node["entity_id"] for node in graph.json()["nodes"]}
            assert all(
                edge["source"] in graph_ids and edge["target"] in graph_ids
                for edge in graph.json()["edges"]
            )
            for format in ["json", "html"]:
                response = client.get(
                    f"/reports/{run['report_id']}/export", params={"format": format}
                )
                response.raise_for_status()
                (output / f"report-{index + 1}-export.{format}").write_bytes(response.content)
                if format == "json":
                    bundle = response.json()
                    assert bundle["report"] == report
                    assert set(bundle["snapshot"]["event_ids"]) == snapshot_ids
                    assert len(bundle["evidence"]) == len(snapshot_ids)
                    assert all(item["verified"] and item["redacted"] for item in bundle["evidence"])
            reports.append(
                {
                    "report_id": report["report_id"],
                    "run_id": created["run_id"],
                    "incident_id": incident["id"],
                    "state": run["state"],
                    "snapshot_events": len(snapshot_ids),
                    "evidence_checks": evidence_checked,
                    "validation": report["validation"],
                    "mode": report["mode"],
                    "graph_truncated": graph.json()["truncated"],
                    "stop_reason": run.get("stop_reason"),
                }
            )
            print(
                f"Report {index + 1}: {run['state']}/{report['mode']}/{report['validation']} "
                f"snapshot={len(snapshot_ids)} references={evidence_checked}",
                flush=True,
            )
        save(output / "incident-details.json", details)
        save(output / "blocked-investigations.json", blocked)
        env_test = os.environ.copy()
        env_test.update(
            CTU_E2E_URL=env["url"],
            CTU_E2E_TOKEN=env["tokens"]["admin"],
            CTU_E2E_DATASET=dataset["dataset_id"],
            CTU_E2E_COUNT=str(len(events)),
            CTU_E2E_INCIDENTS=str(len(incidents)),
            CTU_E2E_REPORTS=str(len(reports)),
            CTU_E2E_BLOCKED=str(len(blocked)),
            TRACE_E2E_ARTIFACTS=str(output),
            PLAYWRIGHT_BROWSERS_PATH=str(ROOT / ".tools/pw-browsers"),
        )
        node = shutil.which("node")
        assert node
        browser = subprocess.run(
            [
                node,
                "node_modules/@playwright/test/cli.js",
                "test",
                "ctu13.spec.ts",
                "--output",
                str(output / "browser"),
                "--reporter=list",
            ],
            cwd=ROOT / "apps/web",
            env=env_test,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=180,
        )
        (output / "browser.log").write_text(browser.stdout + browser.stderr, encoding="utf-8")
        print(browser.stdout.encode("ascii", errors="backslashreplace").decode(), flush=True)
        assert browser.returncode == 0
        counts = command(
            "docker",
            "exec",
            env["prefix"] + "-db",
            "psql",
            "-U",
            "trace_owner",
            "-d",
            "trace",
            "-At",
            "-c",
            "SELECT payload->>'rule_id',count(*) FROM findings "
            "GROUP BY payload->>'rule_id' ORDER BY 1;",
        )
        (output / "finding-counts.txt").write_text(counts, encoding="utf-8")
        return {
            "events": len(events),
            "event_protocols": dict(Counter(e["network"]["transport"] for e in events)),
            "initial_accepted": imports[0]["accepted"],
            "repeat_duplicates": imports[1]["duplicate"],
            "quarantined": imports[0]["quarantined"],
            "incident_count": len(incidents),
            "reports": reports,
            "paid_model_calls": 0,
            "browser_exit_code": browser.returncode,
            "source_mapping_checked": len(mapping),
            "field_comparisons_checked": len(events),
            "report_test_available": bool(reports),
            "blocked_investigations": blocked,
        }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--backend-image")
    args = parser.parse_args()
    output = args.artifacts.resolve()
    output.mkdir(parents=True, exist_ok=False)
    before = production_fingerprint()
    (output / "production-before.txt").write_text(before, encoding="utf-8")
    summary: dict = {"status": "failed"}
    try:
        with isolated(output, args.backend_image) as environment:
            summary = {"status": "passed", **verify(environment, args.source.resolve(), output)}
    finally:
        after = production_fingerprint()
        (output / "production-after.txt").write_text(after, encoding="utf-8")
        summary["production_unchanged"] = before == after
        save(output / "result.json", summary)
        assert before == after, "Production changed during verification"


if __name__ == "__main__":
    main()
