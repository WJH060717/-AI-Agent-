"""Independent C&C protocol API/worker/web verification; no label access."""

import argparse
import json
import os
import shutil
import subprocess
from collections import Counter
from pathlib import Path
from uuid import uuid4

import httpx

from scripts.browser_installed_audit import production_fingerprint
from scripts.ctu13_sample import sha
from scripts.http_round1_environment import isolated
from scripts.verify_ctu13 import pages, save, wait_terminal

ROOT = Path(__file__).resolve().parents[1]


def verify(environment: dict, sample: Path, output: Path) -> dict:
    output.mkdir(exist_ok=False)
    manifest = json.loads((sample / "manifest.json").read_bytes())
    source_rows = {}
    for source, metadata in manifest["sources"].items():
        raw = (sample / f"{source}.jsonl").read_bytes()
        assert sha(raw) == metadata["jsonl_sha256"]
        original = Path(metadata["original"]).read_bytes()
        assert sha(original) == metadata["original_sha256"]
        original_lines = original.splitlines(keepends=True)
        mapping = json.loads((sample / f"{source}-map.json").read_bytes())
        records = [json.loads(line) for line in raw.splitlines()]
        assert len(records) == metadata["records"] == len(mapping)
        for index, entry in enumerate(mapping):
            assert entry["output_line"] == index + 1 and entry["uid"] == records[index]["uid"]
            assert sha(original_lines[entry["source_line"] - 1]) == entry["source_line_sha256"]
        source_rows[metadata["jsonl_sha256"]] = records
    with httpx.Client(
        base_url=environment["url"] + "/api/v1",
        timeout=90,
        trust_env=False,
        headers={"Authorization": f"Bearer {environment['tokens']['admin']}"},
    ) as client:
        response = client.post(
            "/datasets",
            headers={"Idempotency-Key": str(uuid4())},
            json={"name": "CTU-13 round2 " + sample.name, "provenance_type": "derived"},
        )
        response.raise_for_status()
        dataset = response.json()
        save(output / "dataset.json", dataset)
        scope = {"dataset_id": dataset["dataset_id"], "session_id": dataset["default_session_id"]}
        imports = []
        for source, metadata in manifest["sources"].items():
            raw = (sample / f"{source}.jsonl").read_bytes()
            if not raw:
                continue
            for repeat in range(2):
                response = client.post(
                    "/imports",
                    headers={"Idempotency-Key": str(uuid4())},
                    data={
                        "dataset_id": dataset["dataset_id"],
                        "source_type": source,
                        "sensor_id": "ctu13-s07-bro",
                        "timezone": "UTC",
                    },
                    files={"file": (f"{source}.jsonl", raw, "application/json")},
                )
                response.raise_for_status()
                batch = response.json()
                status = wait_terminal(client, f"/imports/{batch['batch_id']}", "status")
                save(output / f"import-{source}-{repeat}.json", status)
                imports.append(status)
                assert status["status"] == "succeeded", status
                assert status["quarantined"] == 0, status
                assert status["accepted"] == (0 if repeat else metadata["records"]), status
                assert status["duplicate"] == (metadata["records"] if repeat else 0), status
        events = pages(client, "/events", scope)
        save(output / "events.json", events)
        assert len(events) == sum(m["records"] for m in manifest["sources"].values())
        for event in events:
            ref = event["source_locators"][0]
            row = source_rows[ref["raw_sha256"]][ref["record_start"] - 1]
            assert event["network"]["uid"] == row["uid"]
            for side, prefix in (("src", "orig"), ("dst", "resp")):
                assert event[side]["ip"] == row[f"id.{prefix}_h"]
                assert event[side]["port"] == row[f"id.{prefix}_p"]
            assert not {"uri", "password", "username", "user_agent"}.intersection(event)
        response = client.get("/overview", params=scope)
        response.raise_for_status()
        save(output / "overview.json", response.json())
        incidents = pages(client, "/incidents", scope)
        save(output / "incidents.json", incidents)
        details, reports = [], []
        for index, incident in enumerate(incidents, 1):
            response = client.get(f"/incidents/{incident['id']}")
            response.raise_for_status()
            details.append(response.json())
            response = client.post(
                f"/incidents/{incident['id']}/investigations",
                headers={"Idempotency-Key": str(uuid4())},
                json={"mode": "deterministic"},
            )
            response.raise_for_status()
            run_id = response.json()["run_id"]
            run = wait_terminal(client, f"/investigations/{run_id}", "state")
            save(output / f"run-{index}.json", run)
            assert run["state"] == "completed" and run["budget_used"]["model_calls"] == 0, run
            response = client.get(f"/reports/{run['report_id']}")
            response.raise_for_status()
            report = response.json()
            save(output / f"report-{index}.json", report)
            assert report["mode"] == "deterministic_fallback" and report["validation"] == "passed"
            timeline = pages(client, f"/investigations/{run_id}/timeline")
            assert {e["event_id"] for e in timeline} == set(report["timeline"])
            for event_id in report["timeline"]:
                response = client.get(
                    f"/evidence/{event_id}", params={"snapshot_id": run["snapshot_id"]}
                )
                response.raise_for_status()
                evidence = response.json()
                assert evidence["verified"] and evidence["redacted"]
                for fragment in evidence["fragments"]:
                    assert fragment["sha256"] in source_rows
                    for line in fragment["lines"]:
                        value = json.loads(line["text"])
                        assert not {
                            "uri",
                            "password",
                            "username",
                            "referrer",
                            "answers",
                        }.intersection(value)
            for fmt in ("html", "json"):
                response = client.get(f"/reports/{run['report_id']}/export", params={"format": fmt})
                response.raise_for_status()
                (output / f"export-{index}.{fmt}").write_bytes(response.content)
                if fmt == "json":
                    assert response.json()["report"] == report
            reports.append(
                {
                    "report_id": report["report_id"],
                    "run_id": run_id,
                    "state": run["state"],
                    "mode": report["mode"],
                    "validation": report["validation"],
                    "evidence_events": len(timeline),
                }
            )
        save(output / "incident-details.json", details)
        findings = {
            f["id"]: f for detail in details for f in detail.get("findings", [detail["finding"]])
        }
        rule_counts = dict(Counter(f["rule_id"] for f in findings.values()))
        cc_ids = {
            event_id
            for f in findings.values()
            if f["rule_id"] in {"R08", "R09"}
            for event_id in f["connection_event_ids"]
        }
        env = os.environ.copy()
        env.update(
            CC_E2E_URL=environment["url"],
            CC_E2E_TOKEN=environment["tokens"]["admin"],
            CC_E2E_DATASET=dataset["dataset_id"],
            CC_E2E_REPORTS=str(len(reports)),
            CC_E2E_COUNT=str(rule_counts.get("R08", 0) + rule_counts.get("R09", 0)),
            CC_E2E_SAMPLE=str(sample),
            CC_E2E_ARTIFACTS=str(output),
            PLAYWRIGHT_BROWSERS_PATH=str(ROOT / ".tools/pw-browsers"),
        )
        browser = subprocess.run(
            [
                shutil.which("node"),
                "node_modules/@playwright/test/cli.js",
                "test",
                "cc-round2.spec.ts",
                "--reporter=list",
                "--output",
                str(output / "browser"),
            ],
            cwd=ROOT / "apps/web",
            env=env,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=180,
        )
        (output / "browser.log").write_text(browser.stdout + browser.stderr, encoding="utf-8")
        assert browser.returncode == 0, "browser_failed_see_log"
        result = {
            "events": len(events),
            "incidents": len(incidents),
            "reports": reports,
            "accepted": sum(i["accepted"] for i in imports),
            "duplicates": sum(i["duplicate"] for i in imports),
            "quarantined": sum(i["quarantined"] for i in imports),
            "paid_model_calls": 0,
            "browser_exit": browser.returncode,
            "finding_counts": rule_counts,
            "cc_connection_event_ids": sorted(cc_ids),
        }
        save(output / "result.json", result)
        print(
            json.dumps(
                {
                    "sample": sample.name,
                    "events": len(events),
                    "incidents": len(incidents),
                    "reports": len(reports),
                }
            ),
            flush=True,
        )
        return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--samples", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--backend", required=True)
    parser.add_argument("--frontend", required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    before = production_fingerprint()
    (output / "production-before.txt").write_text(before, encoding="utf-8")
    result = {"status": "failed", "cases": {}}
    try:
        with isolated(output, args.backend, args.frontend) as environment:
            for name in ("cc-only", "normal-control", "mixed-control"):
                result["cases"][name] = verify(
                    environment, args.samples.resolve() / name, output / name
                )
        result["status"] = "passed"
    finally:
        after = production_fingerprint()
        (output / "production-after.txt").write_text(after, encoding="utf-8")
        result["production_unchanged"] = before == after
        save(output / "result.json", result)
        assert before == after


if __name__ == "__main__":
    main()
