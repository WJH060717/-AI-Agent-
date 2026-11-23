"""Verify the frozen local CICIoT2023 development capture sets."""

import argparse
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi.testclient import TestClient
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource

from apps.api.main import create_app
from packages.config import Settings
from packages.detection.common import DOS_DDOS_FAMILY, merged_dos_subtype
from packages.detection.fragmentation import ACTIVE_FRAGMENT_RULES, FRAGMENT_RULES
from packages.detection.gre_bursts import GRE_BURST_FREEZE, GRE_BURST_RULE
from packages.detection.http_packets import HTTP_PACKET_FREEZE, HTTP_PACKET_RULES
from packages.detection.os_fingerprint import OS_FINGERPRINT_FREEZE, OS_FINGERPRINT_RULE
from packages.detection.packet_bursts import BURST_FREEZE, BURST_RULES
from packages.detection.packet_conflicts import (
    ARP_CONFLICT_FREEZE,
    ARP_CONFLICT_RULE,
    DNS_DIFFERENCE_FREEZE,
    DNS_DIFFERENCE_RULE,
)
from packages.detection.packet_recon import (
    HOST_DISCOVERY_FREEZE,
    HOST_DISCOVERY_RULE,
    PING_SWEEP_FREEZE,
    PING_SWEEP_RULE,
    PORT_SCAN_RULE,
)
from packages.storage.database import Database
from packages.storage.service import DataService, DomainError
from scripts.verify_pcap_packet import MANIFEST_SHA256

FIXED_MANIFEST_HASHES = {
    "v1": MANIFEST_SHA256,
    "v2": "a18dd3cd3305070d49ff7a2e6e0ac52ac4755818130842dec8ac376fd8ab81cb",
}
PACKET_COUNT_FIELDS = ("accepted", "duplicate", "skipped", "quarantined")
FRAGMENT_LABELS = {merged_dos_subtype(subtype) for _, subtype in FRAGMENT_RULES.values()}
BURST_LABELS = {merged_dos_subtype(subtype) for subtype in BURST_RULES.values()}
HTTP_LABELS = {merged_dos_subtype(subtype) for subtype in HTTP_PACKET_RULES.values()}
KNOWN_BEHAVIOR_LABELS = FRAGMENT_LABELS | BURST_LABELS | HTTP_LABELS
SLOWLORIS = merged_dos_subtype(HTTP_PACKET_RULES["R23"])
SOURCE_FILES = (
    "packages/agent/behavior_reporting.py",
    "packages/storage/reports.py",
    ".dockerignore",
    "PROJECT_SPEC.md",
    "pyproject.toml",
    "apps/api/main.py",
    "packages/detection/fragmentation.py",
    "packages/detection/packet_bursts.py",
    "packages/detection/packet_recon.py",
    "packages/detection/packet_conflicts.py",
    "packages/detection/os_fingerprint.py",
    "packages/detection/gre_bursts.py",
    "tests/contract/test_packet_recon.py",
    "tests/contract/test_gre_bursts.py",
    "tests/contract/test_flood_scope.py",
    "packages/detection/http_packets.py",
    "tests/contract/test_http_packet_rules.py",
    "tests/contract/test_packet_bursts.py",
    "packages/detection/registry.py",
    "packages/detection/aggregation.py",
    "packages/detection/common.py",
    "packages/storage/analysis.py",
    "packages/storage/incidents.py",
    "packages/storage/service.py",
    "packages/storage/reports.py",
    "packages/storage/replay.py",
    "packages/storage/worker.py",
    "packages/ingest/pcap_packet.py",
    "packages/ingest/dns_datagram.py",
    "packages/ingest/os_fingerprint.py",
    "tests/integration/test_packet_spoofing.py",
    "tests/contract/test_os_fingerprint_rule.py",
    "packages/contracts/models.py",
    "packages/contracts/evidence.py",
    "packages/contracts/api.py",
    "packages/agent/reporting.py",
    "packages/agent/executor.py",
    "scripts/verify_fragment_rules.py",
    "tests/contract/test_fixed_capture_acceptance.py",
    "tests/contract/test_fragment_rules.py",
    "tests/integration/test_pcap_packet.py",
)


class OfflineCaptureSettings(Settings):
    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (init_settings,)


def scored_subtype(scenario_label: str) -> str:
    subtype = merged_dos_subtype(scenario_label)
    if subtype not in KNOWN_BEHAVIOR_LABELS:
        raise ValueError("unknown fixed capture behavior")
    return subtype


def fixed_v2_gate(result: dict) -> bool:
    rows = result["samples"]
    return (
        len(rows) == result["samples_checked_without_errors"] == 12
        and result["samples_with_same_replayed_evidence"] == 12
        and result["samples_with_reconciled_records"] == 12
        and result["cross_class_candidates"] == 0
        and all(
            row["passed"]
            or (
                row["expected_subtype"] == SLOWLORIS
                and row["main_prediction"] == "unknown"
                and any(
                    item["rule"] == "R23" and item["verified"]
                    for item in row.get("unclassified_candidates", [])
                )
            )
            for row in rows
        )
        and result["all_samples_passed"] >= 11
    )


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_fixed_manifest(manifest: Path, fixed_set: str) -> tuple[str, list[dict]]:
    raw = manifest.read_bytes()
    digest = sha256_bytes(raw)
    if digest != FIXED_MANIFEST_HASHES.get(fixed_set):
        raise ValueError(f"fixed sample manifest changed for {fixed_set}")
    return digest, json.loads(raw)["samples"]


def body(response, expected_status: int) -> dict:
    if response.status_code != expected_status:
        raise AssertionError(f"HTTP {response.status_code}: {response.json().get('error', {})}")
    return response.json()


def capture_case(client, service, headers, dataset, capture_bytes: bytes, name: str) -> dict:
    session = dataset["default_session_id"]
    upload = body(
        client.post(
            "/api/v1/imports",
            headers={**headers, "Idempotency-Key": name},
            files={"file": (f"{name}.pcap", capture_bytes, "application/octet-stream")},
            data={
                "dataset_id": dataset["dataset_id"],
                "source_type": "pcap_packet",
                "sensor_id": "research-probe",
                "timezone": "UTC",
            },
        ),
        202,
    )
    service.process_one()
    batch = body(client.get(f"/api/v1/imports/{upload['batch_id']}", headers=headers), 200)
    incidents = body(
        client.get(
            "/api/v1/incidents",
            headers=headers,
            params={"dataset_id": dataset["dataset_id"], "session_id": session, "limit": 100},
        ),
        200,
    )
    if incidents["next_cursor"] is not None:
        raise ValueError("fixed capture acceptance exceeded the bounded incident page")
    candidates = [(item, item.get("attack_subtype")) for item in incidents["items"]]
    labels = sorted({label for _, label in candidates if label is not None})
    row = {
        "import_status": batch["status"],
        "import_error": batch["error_code"],
        "record_counts": {key: batch[key] for key in ("raw_records", *PACKET_COUNT_FIELDS)},
        "catalog_warnings": incidents.get("warnings", []),
        "candidate_subtypes": labels,
        "main_prediction": labels[0] if len(labels) == 1 else "unknown",
        "verified_candidates": [],
        "unclassified_candidates": [],
    }
    row["verification_failures"] = []
    for incident, label in candidates:
        try:
            verified = verify_candidate(
                client, service, headers, incident, label, capture_bytes, name
            )
        except (AssertionError, DomainError, IndexError, KeyError, ValueError) as exc:
            row["verification_failures"].append(
                {
                    "subtype": label,
                    "finding_id": incident["finding_id"],
                    "error": str(exc) or type(exc).__name__,
                }
            )
        else:
            destination = "verified_candidates" if label is not None else "unclassified_candidates"
            row[destination].append(verified)
    return row


def verify_candidate(client, service, headers, incident, label, capture_bytes, name):
    detail = body(client.get(f"/api/v1/incidents/{incident['id']}", headers=headers), 200)
    finding = detail["finding"]
    run_request = body(
        client.post(
            f"/api/v1/incidents/{incident['id']}/investigations",
            headers={**headers, "Idempotency-Key": f"{name}-{incident['id']}"},
            json={"mode": "deterministic"},
        ),
        202,
    )
    service.process_one()
    analysis = body(
        client.get(f"/api/v1/investigations/{run_request['run_id']}", headers=headers), 200
    )
    timeline = body(
        client.get(
            f"/api/v1/investigations/{run_request['run_id']}/timeline",
            headers=headers,
            params={"limit": 100},
        ),
        200,
    )
    exported = body(
        client.get(
            f"/api/v1/reports/{analysis['report_id']}/export",
            headers=headers,
            params={"format": "json"},
        ),
        200,
    )
    witness = {
        event["event_id"]: event
        for event in timeline["items"]
        if event["event_type"] == "network.packet"
    }
    observations = {}
    capture_sha256 = sha256_bytes(capture_bytes)
    for item in exported["evidence"]:
        [source] = item["fragments"]
        event = witness[item["event_id"]]
        [locator] = event["source_locators"]
        packet = source["pcap_record"]
        assert item["verified"] and item["redacted"]
        assert source["sha256"] == locator["raw_sha256"] == capture_sha256
        assert packet["byte_range"] == locator["pcap"]
        assert packet["record_number"] == locator["record_start"]
        observations[item["event_id"]] = {
            "event_id": item["event_id"],
            "packet": packet["record_number"],
            "byte_range": packet["byte_range"],
        }
    pairs = [
        {"initial": observations[a], "terminal": observations[b]}
        for a, b in finding.get("paired_evidence_ids", [])
    ]
    assert len({record["event_id"] for pair in pairs for record in pair.values()}) == 2 * len(pairs)
    assert finding.get("attack_subtype") == label
    if label is not None and label.startswith(f"{DOS_DDOS_FAMILY}-"):
        assert incident["title"].startswith(f"{DOS_DDOS_FAMILY} · ")
    flood = finding.get("flood_observation")
    if flood is not None:
        assert "来源分布未知" in incident["title"]
        if label is not None:
            assert flood["support"] == "flood_candidate"
            assert label == f"{DOS_DDOS_FAMILY}-{flood['behavior']}"
        assert incident.get("flood_observation") == flood
        contributing = [witness[event_id] for event_id in finding["contributing_evidence_ids"]]
        observed_ips = {event["src"]["ip"] for event in contributing}
        assert flood["observed_source_ip_count"] == len(observed_ips)
        assert flood["campaign_scope"] == "unknown"
    elif label is None:
        assert finding["kind"] in {
            "http_request_unclassified",
            "ethernet_arp_destination_spread",
            "ipv4_gre_burst_observation",
            "ethernet_arp_mapping_difference",
            "ipv4_dns_answer_difference",
        }
        assert "子类型未知" in incident["title"]
    rule_id = finding["rule_id"]
    if rule_id in HTTP_PACKET_RULES:
        config = finding["config"]
        connections = config["connections"]
        if rule_id == "R22":
            recurring = (
                flood["support"] == "flood_candidate"
                if flood is not None
                else config["version"] == "1.1.0" and label
            )
            count = 2 * connections if recurring else connections
            allowed_counts = range(count, count + 1)
        else:
            minimum = 3 if config["version"] in {"1.2.0", "1.3.0"} and label else 2
            allowed_counts = range(
                minimum * connections, config["maximum_segments"] * connections + 1
            )
        assert set(finding["contributing_evidence_ids"]) == set(witness)
    elif rule_id == GRE_BURST_RULE:
        config = finding["config"]
        count = config["window_records"]
        allowed_counts = range(count, count + 1)
        contributing = [witness[e] for e in finding["contributing_evidence_ids"]]
        assert len(contributing) >= config["minimum_matches"]
        assert {e["packet"]["gre_encapsulation"] for e in contributing} == {
            finding["gre_encapsulation"]
        }
    elif rule_id in {PING_SWEEP_RULE, HOST_DISCOVERY_RULE}:
        count = finding["config"]["minimum_destinations"]
        allowed_counts = range(count, count + 1)
        assert set(finding["contributing_evidence_ids"]) == set(witness)
        assert len({event["dst"]["ip"] for event in witness.values()}) == count
    elif rule_id in {ARP_CONFLICT_RULE, DNS_DIFFERENCE_RULE}:
        allowed_counts = (2,) if rule_id == ARP_CONFLICT_RULE else (3,)
        assert set(finding["contributing_evidence_ids"]) == set(witness)
    elif rule_id == OS_FINGERPRINT_RULE:
        allowed_counts = (4,)
        assert set(finding["contributing_evidence_ids"]) == set(witness)
        assert [
            [witness[event_id]["packet"]["os_probe"]["role"] for event_id in pair]
            for pair in finding["paired_evidence_ids"]
        ] == [["udp_request", "icmp_quote"], ["tcp_request", "tcp_response"]]
        for request_id, response_id in finding["paired_evidence_ids"]:
            request, response = witness[request_id], witness[response_id]
            assert request["src"]["ip"] == response["dst"]["ip"]
            assert request["dst"]["ip"] == response["src"]["ip"]
            assert request["packet"]["os_probe"]["correlation_sha256"] == (
                response["packet"]["os_probe"]["correlation_sha256"]
            )
            if request["packet"]["os_probe"]["role"] == "tcp_request":
                assert request["src"]["port"] == response["dst"]["port"]
                assert request["dst"]["port"] == response["src"]["port"]
            assert observations[request_id]["packet"] < observations[response_id]["packet"]
            assert datetime.fromisoformat(request["event_time"]) < datetime.fromisoformat(
                response["event_time"]
            )
        times = [datetime.fromisoformat(event["event_time"]) for event in witness.values()]
        assert max(times) - min(times) == timedelta(microseconds=finding["observation_span_us"])
        assert finding["observation_span_us"] <= finding["config"]["window_us"]
    elif rule_id == PORT_SCAN_RULE:
        count = finding["config"]["minimum_ports"]
        allowed_counts = range(count, count + 1)
        assert set(finding["contributing_evidence_ids"]) == set(witness)
    else:
        allowed_counts = range(64, 65)
    verification = {
        "subtype": label,
        **({"flood_observation": flood} if flood is not None else {}),
        **({"gre_encapsulation": finding["gre_encapsulation"]}
           if "gre_encapsulation" in finding else {}),
        "title": incident["title"],
        "rule": finding["rule_id"],
        "rule_version": finding["rule_version"],
        "finding_id": finding["id"],
        "start_time": finding["start_time"],
        "end_time": finding["end_time"],
        "window_span_us": finding["observation_span_us"],
        "evidence_count": len(witness),
        "window_records": sorted(observations.values(), key=lambda row: row["packet"]),
        "paired_fragments": pairs,
        "contributing_packets": [
            observations[event_id] for event_id in finding.get("contributing_evidence_ids", [])
        ],
        "reused_id_observed_pairs": finding.get("reused_id_observed_pairs", 0),
        "limitations": finding["limitations"],
        "source_sha256": capture_sha256,
        "run_state": analysis["state"],
        "report_validation": exported["report"]["validation"],
        "verified": exported["report"]["validation"] == "passed"
        and analysis["state"] == "completed"
        and set(observations) == set(finding["evidence_ids"]) == set(witness)
        and len(witness) in allowed_counts,
    }
    assessments = [
        assessment for assessment in exported["report"].get("behavior_assessments") or []
        if assessment["finding_id"] == finding["id"]
    ]
    if assessments:
        report_url = f"/api/v1/reports/{analysis['report_id']}"
        report = body(client.get(report_url, headers=headers), 200)
        html_export = client.get(report_url + "/export", headers=headers, params={"format": "html"})
        identities = set(finding.get("contributing_evidence_ids", finding["evidence_ids"]))
        verification["behavior_assessments"] = assessments
        verification["behavior_report_verified"] = (
            report["behavior_assessments"] == exported["report"]["behavior_assessments"]
            and html_export.status_code == 200
            and all(
                assessment["label"] in html_export.text
                and ("溯源成功" if assessment["trace_status"] == "successful" else "溯源未成功")
                in html_export.text
                and assessment["trace_scope"] in html_export.text
                and assessment["trace_reason"] in html_export.text
                and {ref["event_id"] for ref in assessment["evidence_refs"]} == identities
                and identities.issubset(observations)
                for assessment in assessments
            )
        )
    return verification


def repeat_and_replay(
    client, service, headers, dataset, payload: bytes, finding_id: str | None = None
) -> dict:
    origin = dataset["default_session_id"]

    def scoped_findings(session):
        page = body(
            client.get(
                "/api/v1/incidents",
                headers=headers,
                params={"dataset_id": dataset["dataset_id"], "session_id": session, "limit": 100},
            ),
            200,
        )
        assert page["next_cursor"] is None and not page["warnings"]
        entries = {}
        for incident in page["items"]:
            candidate = body(
                client.get(f"/api/v1/incidents/{incident['id']}", headers=headers), 200
            )["finding"]
            key = candidate["rule_id"], tuple(candidate["evidence_ids"])
            assert key not in entries
            entries[key] = candidate
        return entries

    original = scoped_findings(origin)
    if finding_id is not None:
        assert finding_id in {candidate["id"] for candidate in original.values()}
    duplicate = body(
        client.post(
            "/api/v1/imports",
            headers={**headers, "Idempotency-Key": "neutral-repeat-" + dataset["dataset_id"]},
            files={"file": ("renamed.pcap", payload, "application/octet-stream")},
            data={
                "dataset_id": dataset["dataset_id"],
                "source_type": "pcap_packet",
                "sensor_id": "research-probe",
                "timezone": "UTC",
            },
        ),
        202,
    )
    service.process_one()
    batch = body(client.get(f"/api/v1/imports/{duplicate['batch_id']}", headers=headers), 200)
    assert batch["status"] == "succeeded" and batch["accepted"] == 0 and batch["duplicate"] > 0
    assert scoped_findings(origin) == original, "reimport changed the original finding catalog"
    replay = body(
        client.post(
            f"/api/v1/datasets/{dataset['dataset_id']}/replays",
            headers={**headers, "Idempotency-Key": "isolated-replay"},
            json={"source_session_id": origin, "rate_eps": 1000},
        ),
        202,
    )
    service.process_one()
    job = body(client.get(f"/api/v1/replays/{replay['job_id']}", headers=headers), 200)
    assert job["state"] == "completed" and job["detection_status"] == "complete"
    assert job["published_events"] == batch["duplicate"]
    copied = scoped_findings(replay["session_id"])
    assert original.keys() == copied.keys()
    for key, candidate in original.items():
        replayed = copied[key]
        assert replayed["id"] != candidate["id"]
        for field in (
            "attack_subtype", "flood_observation", "paired_evidence_ids",
            "contributing_evidence_ids", "config", "gre_encapsulation",
        ):
            assert candidate.get(field) == replayed.get(field)
    return {
        "duplicates": batch["duplicate"],
        "replay_members": job["published_events"],
        "same_witness": True,
    }


def score(
    manifest: Path, *, bursts: bool = False, http: bool = False, fixed_set: str = "v1"
) -> dict:
    manifest_digest, samples = load_fixed_manifest(manifest, fixed_set)
    freeze = (ACTIVE_FRAGMENT_RULES / "ipv4-fragments-freeze.json").read_bytes()
    report = {
        "mode": "offline_isolated_sqlite_asgi",
        "fixed_set": fixed_set,
        "scoring_taxonomy": "merged_dos_ddos_exact_behavior@1.0.0",
        "manifest_sha256": manifest_digest,
        "rule_freeze_sha256": sha256_bytes(freeze),
        "gre_burst_freeze_sha256": sha256_bytes(GRE_BURST_FREEZE.read_bytes()),
        "host_discovery_freeze_sha256": sha256_bytes(HOST_DISCOVERY_FREEZE.read_bytes()),
        "ping_sweep_freeze_sha256": sha256_bytes(PING_SWEEP_FREEZE.read_bytes()),
        "arp_conflict_freeze_sha256": sha256_bytes(ARP_CONFLICT_FREEZE.read_bytes()),
        "dns_difference_freeze_sha256": sha256_bytes(DNS_DIFFERENCE_FREEZE.read_bytes()),
        "os_fingerprint_freeze_sha256": sha256_bytes(OS_FINGERPRINT_FREEZE.read_bytes()),
        "freeze_inputs": {
            path.name: sha256_bytes(path.read_bytes())
            for path in sorted(ACTIVE_FRAGMENT_RULES.glob("*.json"))
        },
        "source_sha256": {file: sha256_bytes(Path(file).read_bytes()) for file in SOURCE_FILES},
        "at_utc": datetime.now(UTC).isoformat(),
        "samples": [],
    }
    if bursts:
        report["burst_freeze_sha256"] = sha256_bytes(BURST_FREEZE.read_bytes())
    if http:
        report["http_freeze_sha256"] = sha256_bytes(HTTP_PACKET_FREEZE.read_bytes())
    replayed_burst = False
    replayed_http: set[str] = set()
    with TemporaryDirectory(prefix="trace-packet-verify-") as temporary:
        root = Path(temporary)
        settings = OfflineCaptureSettings(
            _env_file=None,
            app_env="test",
            model_provider="disabled",
            model_api_key=None,
            api_read_requests_per_minute=300,
            api_write_requests_per_minute=100,
            database_url=f"sqlite:///{(root / 'case.db').as_posix()}",
            staging_store=root / "staging",
            raw_store=root / "raw",
        )
        db = Database(settings)
        db.migrate()
        service = DataService(db, settings)
        try:
            workspace, tokens = service.init_workspace("isolated fragment rules verification")
            actor = service.system_actor(workspace)
            headers = {"Authorization": f"Bearer {tokens['admin']}"}
            app = create_app(settings)
            report["application_version"] = app.version
            with TestClient(app) as client:
                for index, sample in enumerate(samples, 1):
                    neutral = f"capture-{index:02}"
                    dataset = service.create_dataset(
                        actor, {"name": neutral, "provenance_type": "real_capture"}, neutral
                    )
                    payload = (manifest.parent / sample["sample_file"]).read_bytes()
                    actual_hash = sha256_bytes(payload)
                    if actual_hash != sample["sample_sha256"]:
                        raise ValueError(f"digest mismatch for {neutral}")
                    try:
                        result = capture_case(client, service, headers, dataset, payload, neutral)
                    except (AssertionError, DomainError, IndexError, KeyError, ValueError) as exc:
                        result = {
                            "main_prediction": "unknown",
                            "failure": str(exc) or type(exc).__name__,
                            "verified_candidates": [],
                            "candidate_subtypes": [],
                        }
                    else:
                        candidates = result["verified_candidates"]
                        if fixed_set == "v2":
                            candidates = candidates + result["unclassified_candidates"]
                        candidate = candidates[0] if candidates else None
                        replay_this_burst = bool(
                            bursts
                            and candidate
                            and candidate["rule"] in BURST_RULES
                            and not replayed_burst
                        )
                        replay_this_http = bool(
                            http
                            and candidate
                            and candidate["rule"] in HTTP_PACKET_RULES
                            and candidate["rule"] not in replayed_http
                        )
                        if candidate and (
                            fixed_set == "v2" or index == 1 or replay_this_burst or replay_this_http
                        ):
                            if replay_this_http:
                                replayed_http.add(candidate["rule"])
                            replayed_burst |= replay_this_burst
                            try:
                                replay = repeat_and_replay(
                                    client,
                                    service,
                                    headers,
                                    dataset,
                                    payload,
                                    candidate["finding_id"],
                                )
                                accepted = result["record_counts"]["accepted"]
                                assert replay["replay_members"] == accepted
                                result["repeat_and_replay"] = replay
                            except (
                                AssertionError,
                                DomainError,
                                IndexError,
                                KeyError,
                                ValueError,
                            ) as exc:
                                result["repeat_and_replay_failure"] = str(exc) or type(exc).__name__
                    expected = scored_subtype(sample["scenario_label"])
                    result["scenario_label"] = sample["scenario_label"]
                    result["expected_subtype"] = expected
                    result["sample_sha256"] = actual_hash
                    counts = result.get("record_counts")
                    result["expected_records"] = sample["packet_records"]
                    result["records_reconciled"] = (
                        counts is not None
                        and counts["raw_records"]
                        == sample["packet_records"]
                        == sum(counts[key] for key in PACKET_COUNT_FIELDS)
                        and counts["duplicate"] == 0
                    )
                    result["passed"] = (
                        expected == result["main_prediction"]
                        and result.get("import_status") == "succeeded"
                        and result.get("import_error") is None
                        and result["records_reconciled"]
                        and (
                            fixed_set == "v1"
                            or result.get("repeat_and_replay", {}).get("same_witness") is True
                        )
                        and not result.get("catalog_warnings")
                        and not result.get("verification_failures")
                        and "repeat_and_replay_failure" not in result
                        and bool(result["verified_candidates"])
                        and all(
                            item["verified"]
                            for key in ("verified_candidates", "unclassified_candidates")
                            for item in result.get(key, [])
                        )
                    )
                    report["samples"].append(result)
                    print(expected, result["main_prediction"], result["passed"], flush=True)
        finally:
            db.engine.dispose()
    rows = report["samples"]
    report["fragment_samples_passed"] = sum(
        row["passed"] for row in rows if row["expected_subtype"] in FRAGMENT_LABELS
    )
    report["fragment_samples_total"] = sum(
        row["expected_subtype"] in FRAGMENT_LABELS for row in rows
    )
    report["all_samples_passed"] = sum(row["passed"] for row in rows)
    report["all_samples_total"] = len(rows)
    report["samples_with_reconciled_records"] = sum(row["records_reconciled"] for row in rows)
    report["samples_with_same_replayed_evidence"] = sum(
        row.get("repeat_and_replay", {}).get("same_witness") is True for row in rows
    )
    report["non_fragment_samples_with_fragment_candidate"] = sum(
        any(label in FRAGMENT_LABELS for label in row["candidate_subtypes"])
        for row in rows
        if row["expected_subtype"] not in FRAGMENT_LABELS
    )
    report["samples_checked_without_errors"] = sum(
        row.get("import_status") == "succeeded"
        and not row.get("catalog_warnings")
        and not row.get("verification_failures")
        and not row.get("failure")
        and not row.get("repeat_and_replay_failure")
        and all(
            item["verified"]
            for key in ("verified_candidates", "unclassified_candidates")
            for item in row.get(key, [])
        )
        for row in rows
    )
    report["burst_samples_passed"] = sum(
        row["passed"] for row in rows if row["expected_subtype"] in BURST_LABELS
    )
    report["burst_samples_total"] = sum(row["expected_subtype"] in BURST_LABELS for row in rows)
    if http:
        report["http_samples_passed"] = sum(
            row["passed"] for row in rows if row["expected_subtype"] in HTTP_LABELS
        )
        report["http_samples_total"] = sum(row["expected_subtype"] in HTTP_LABELS for row in rows)
    report["samples_with_unclassified_http_observations"] = sum(
        any(item["rule"] in HTTP_PACKET_RULES for item in row.get("unclassified_candidates", []))
        for row in rows
    )
    report["samples_with_unknown_flood_scope"] = sum(
        any(
            item.get("flood_observation", {}).get("campaign_scope") == "unknown"
            for key in ("verified_candidates", "unclassified_candidates")
            for item in row.get(key, [])
        )
        for row in rows
    )
    report["cross_class_candidates"] = sum(
        any(label != row["expected_subtype"] for label in row["candidate_subtypes"]) for row in rows
    )
    if fixed_set == "v2":
        report["strict_gate_passed"] = fixed_v2_gate(report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--fixed-set", choices=FIXED_MANIFEST_HASHES, default="v1")
    parser.add_argument("--bursts", action="store_true")
    parser.add_argument("--http", action="store_true")
    options = parser.parse_args()
    if options.result.exists():
        parser.error("result path already exists")
    http = options.http or options.fixed_set == "v2"
    bursts = options.bursts or http
    result = score(options.manifest, bursts=bursts, http=http, fixed_set=options.fixed_set)
    options.result.parent.mkdir(parents=True, exist_ok=True)
    with options.result.open("x", encoding="utf-8") as output:
        json.dump(result, output, ensure_ascii=False, indent=2)
        output.write("\n")
    if options.fixed_set == "v2":
        if not result["strict_gate_passed"]:
            raise SystemExit(1)
        return
    if (
        result["fragment_samples_passed"] != 3
        or result["samples_checked_without_errors"] != result["all_samples_total"]
        or (
            (
                result["burst_samples_passed"] != 7
                or result["cross_class_candidates"]
                or not any(
                    row.get("repeat_and_replay", {}).get("same_witness")
                    and row["main_prediction"] in BURST_LABELS
                    for row in result["samples"]
                )
            )
            if bursts
            else result["non_fragment_samples_with_fragment_candidate"]
        )
        or not any(
            row.get("repeat_and_replay", {}).get("same_witness") for row in result["samples"]
        )
        or (
            http
            and (
                result["all_samples_passed"] != 12
                or result["http_samples_passed"] != 2
                or not all(
                    any(
                        row.get("repeat_and_replay", {}).get("same_witness")
                        and row["main_prediction"] == subtype
                        for row in result["samples"]
                    )
                    for subtype in HTTP_LABELS
                )
            )
        )
    ):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
