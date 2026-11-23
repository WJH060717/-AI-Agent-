"""Offline acceptance of fixed CICIoT2023 packet captures in a disposable SQLite database."""

import argparse
import hashlib
import json
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from fastapi.testclient import TestClient

from apps.api.main import create_app
from packages.config import Settings
from packages.ingest.pcap_packet import PARSER_VERSION
from packages.storage.database import Database
from packages.storage.service import DataService

MANIFEST_SHA256 = "42cdaa4ae8f6c556ed1c993a41e880650e9510b52a04a0d7ca80c63b4b0a2a40"
SOURCE_FILES = (
    "PROJECT_SPEC.md",
    "pyproject.toml",
    "tests/integration/test_pcap_packet.py",
    "apps/api/main.py",
    "packages/contracts/models.py",
    "packages/contracts/api.py",
    "packages/contracts/evidence.py",
    "packages/ingest/pcap_packet.py",
    "packages/ingest/identity.py",
    "packages/storage/service.py",
    "packages/storage/worker.py",
    "packages/storage/queue.py",
    "packages/storage/context.py",
    "packages/storage/analysis.py",
    "packages/storage/reports.py",
    "scripts/verify_pcap_packet.py",
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify(manifest_path: Path) -> list[dict]:
    raw = manifest_path.read_bytes()
    if sha256(raw) != MANIFEST_SHA256:
        raise ValueError("fixed sample manifest changed")
    samples = json.loads(raw)["samples"]
    results = []
    with tempfile.TemporaryDirectory(prefix="trace-pcap-acceptance-") as temporary:
        root = Path(temporary)
        settings = Settings(
            _env_file=None,
            app_env="test",
            model_provider="disabled",
            database_url=f"sqlite:///{(root / 'test.db').as_posix()}",
            staging_store=root / "staging",
            raw_store=root / "raw",
        )
        database = Database(settings)
        database.migrate()
        service = DataService(database, settings)
        try:
            workspace, tokens = service.init_workspace("fixed PCAP acceptance")
            actor = service.system_actor(workspace)
            headers = {"Authorization": f"Bearer {tokens['admin']}"}
            with TestClient(create_app(settings)) as client:
                for index, sample in enumerate(samples, 1):
                    neutral_name = f"capture-{index:02d}"
                    dataset = service.create_dataset(
                        actor,
                        {"name": neutral_name, "provenance_type": "real_capture"},
                        neutral_name,
                    )
                    payload = (manifest_path.parent / sample["sample_file"]).read_bytes()
                    if sha256(payload) != sample["sample_sha256"]:
                        raise ValueError(f"sample digest mismatch for {neutral_name}")
                    upload = client.post(
                        "/api/v1/imports",
                        headers={**headers, "Idempotency-Key": neutral_name},
                        data={
                            "dataset_id": dataset["dataset_id"],
                            "source_type": "pcap_packet",
                            "sensor_id": "local-probe",
                            "timezone": "UTC",
                        },
                        files={
                            "file": (neutral_name + ".pcap", payload, "application/octet-stream")
                        },
                    )
                    row = {
                        "scenario_label": sample["scenario_label"],
                        "sample_sha256": sample["sample_sha256"],
                        "expected_records": sample["packet_records"],
                        "upload_status": upload.status_code,
                        "passed": False,
                    }
                    results.append(row)
                    if upload.status_code != 202:
                        row["failure"] = upload.json().get("error", {}).get("code")
                        continue
                    job = upload.json()
                    try:
                        service.process_one()
                    except Exception as exc:
                        row["worker_failure_type"] = type(exc).__name__
                    response = client.get(f"/api/v1/imports/{job['batch_id']}", headers=headers)
                    status = response.json()
                    for key in (
                        "status",
                        "error_code",
                        "capture_failure",
                        "raw_records",
                        "accepted",
                        "duplicate",
                        "skipped",
                        "quarantined",
                        "packet_issue_counts",
                        "packet_quality_counts",
                    ):
                        if key in status:
                            row[key] = status[key]
                    row["passed"] = (
                        response.status_code == 200
                        and status["status"] in {"succeeded", "partial"}
                        and status["error_code"] is None
                        and status["raw_records"]
                        == row["expected_records"]
                        == sum(
                            status[key]
                            for key in ("accepted", "duplicate", "skipped", "quarantined")
                        )
                        and status["accepted"] > 0
                        and status["duplicate"] == 0
                    )
                    if row["passed"]:
                        checks = verify_evidence(
                            client,
                            headers,
                            dataset,
                            sample["sample_sha256"],
                            fragments=sample["scenario_label"] == "DDoS-ACK_Fragmentation",
                        )
                        row["verified_packet_evidence"] = checks
                        row["passed"] = all(checks.values())
        finally:
            database.engine.dispose()
    return results


def verify_evidence(client, headers, dataset, source_sha256, *, fragments: bool) -> dict:
    params = {"dataset_id": dataset["dataset_id"], "session_id": dataset["default_session_id"]}
    selected = {}
    for _ in range(21 if fragments else 1):
        page_response = client.get(
            "/api/v1/events", headers=headers, params={**params, "limit": 100 if fragments else 1}
        )
        if page_response.status_code != 200:
            break
        page = page_response.json()
        for event in page["items"]:
            if event["event_type"] != "network.packet":
                continue
            packet = event["packet"]
            if not fragments:
                key = "one_published_packet"
            elif packet["protocol_number"] != 6:
                continue
            elif packet["fragment_offset_bytes"] != 0:
                if packet["tcp_flags"] is not None or event["dst"]["port"] is not None:
                    return {"fragment_transport_fields_unknown": False}
                key = "noninitial_fragment"
            elif packet["more_fragments"] and (packet["tcp_flags"] or 0) & 16:
                key = "readable_initial_ack_fragment"
            else:
                continue
            selected.setdefault(key, (event, page.get("packet_evidence_scope")))
        if len(selected) >= (2 if fragments else 1) or not page["next_cursor"]:
            break
        params["cursor"] = page["next_cursor"]
    checks = {}
    keys = (
        ("readable_initial_ack_fragment", "noninitial_fragment")
        if fragments
        else ("one_published_packet",)
    )
    for key in keys:
        checks[key] = False
        if key not in selected or not selected[key][1]:
            continue
        event, token = selected[key]
        response = client.get(
            f"/api/v1/evidence/{event['event_id']}", headers=headers, params={"packet_scope": token}
        )
        if response.status_code == 200:
            body = response.json()
            [fragment] = body["fragments"]
            checks[key] = (
                body["verified"]
                and fragment["sha256"] == source_sha256
                and fragment["pcap_record"]["record_number"]
                == event["source_locators"][0]["record_start"]
                and fragment["pcap_record"]["packet"] == event["packet"]
            )
    return checks


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--result", type=Path, required=True)
    args = parser.parse_args()
    if args.result.exists():
        parser.error("result path already exists")
    results = verify(args.manifest)
    summary = {
        "at_utc": datetime.now(UTC).isoformat(),
        "mode": "offline_isolated_sqlite_asgi",
        "scope": "packet ingestion, count reconciliation and published packet evidence",
        "manifest_sha256": sha256(args.manifest.read_bytes()),
        "parser_version": PARSER_VERSION,
        "application_version": create_app(Settings(_env_file=None, database_url=None)).version,
        "source_sha256": {name: sha256(Path(name).read_bytes()) for name in SOURCE_FILES},
        "rule_config_sha256": {
            path.name: sha256(path.read_bytes()) for path in sorted(Path("rules").glob("*.json"))
        },
        "fixtures_passed": sum(row["passed"] for row in results),
        "fixtures_total": len(results),
        "record_totals": {
            key: sum(row.get(key, 0) for row in results)
            for key in ("raw_records", "accepted", "duplicate", "skipped", "quarantined")
        },
        "fixtures": results,
    }
    args.result.parent.mkdir(parents=True, exist_ok=True)
    with args.result.open("x", encoding="utf-8") as output:
        json.dump(summary, output, indent=2, ensure_ascii=False)
        output.write("\n")
    print({key: summary[key] for key in ("fixtures_passed", "fixtures_total", "record_totals")})
    if summary["fixtures_passed"] != 12 or summary["record_totals"]["raw_records"] != 24_576:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
