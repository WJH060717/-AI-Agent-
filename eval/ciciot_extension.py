"""Verify the available Section 13.7 inputs offline against the current source."""

import argparse
import json
from collections import Counter
from collections.abc import Iterable
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Annotated, Literal

from fastapi.testclient import TestClient
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from apps.api.main import create_app
from packages.contracts.models import ArpSenderObservation, PacketObservation
from packages.detection.os_fingerprint import OS_FINGERPRINT_RULE
from packages.detection.packet_conflicts import ARP_CONFLICT_RULE, DNS_DIFFERENCE_RULE
from packages.ingest.pcap_packet import (
    InvalidFrame,
    UnsupportedFrame,
    capture_header,
    observation,
    record_at_cursor,
)
from packages.storage.database import Database
from packages.storage.service import DataService, DomainError
from scripts.verify_fragment_rules import (
    PACKET_COUNT_FIELDS,
    SOURCE_FILES,
    OfflineCaptureSettings,
    capture_case,
    repeat_and_replay,
    sha256_bytes,
)

ROOT = Path(__file__).resolve().parents[1]
FEATURE_INVENTORY = Path("artifacts/ciciot2023-remaining21-01/manifest.json")
FEATURE_INVENTORY_SHA256 = "41f1a9bf1b125b102a25216389ba4f9fb955838a11f6a7cbe817724869464b72"
EXTENSION_MANIFEST_SHA256 = "0ca3522b27aecd46e6cd1be225f98f150c2efdc523cbf0bd81e2b0f57c15fc27"
EXTENSION_MANIFESTS = {
    "ciciot-extension@1.0.0": EXTENSION_MANIFEST_SHA256,
    "ciciot-extension@1.1.0": "34d074c625cf9bb46de53916dabc3c654accca57d624f72eb22485ff64a661b3",
}
CONTROL_MANIFEST = Path("artifacts/ciciot2023-http-normal-02/manifest.json")
CONTROL_MANIFEST_SHA256 = "15862a2e47dfd0cc1777e99cc2a25fc401e9ebe6c32c36365da890b433d51158"
MAX_CAPTURE_BYTES = 20 * 1024 * 1024
Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
CaseStatus = Literal["exact_pass", "unknown", "cross_class", "failed"]


class Artifact(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    path: str
    sha256: Sha256


class Capture(Artifact):
    records: int = Field(ge=1, le=100_000)
    provenance_type: Literal["real_capture", "derived"] = "derived"
    provenance: Artifact


class Scenario(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    subtype: str
    missing_evidence: str = Field(min_length=1)
    fixed: Capture | None = None
    collection_failure: Artifact | None = None
    supplements: list[Capture] = Field(default_factory=list, max_length=10)

    @model_validator(mode="after")
    def validate_fixed_input(self) -> "Scenario":
        if self.fixed is not None and self.collection_failure is not None:
            raise ValueError("fixed input and its collection failure are mutually exclusive")
        return self


class Manifest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    version: Literal["ciciot-extension@1.0.0", "ciciot-extension@1.1.0"]
    scenarios: list[Scenario] = Field(min_length=17, max_length=17)


def load_manifest(path: Path) -> tuple[str, Manifest]:
    raw = path.read_bytes()
    digest = sha256_bytes(raw)
    if digest not in EXTENSION_MANIFESTS.values():
        raise ValueError("extension manifest digest does not match a frozen version")
    manifest = Manifest.model_validate_json(raw)
    if digest != EXTENSION_MANIFESTS[manifest.version]:
        raise ValueError("extension manifest digest does not match the declared version")
    return digest, manifest


def validate_coverage(labels: Iterable[str], expected: set[str]) -> None:
    declared = list(labels)
    if len(declared) != len(expected) or set(declared) != expected:
        raise ValueError("extension coverage requires each frozen subtype exactly once")


def read_artifact(artifact: Artifact, suffix: str, max_bytes: int) -> bytes:
    relative = Path(artifact.path)
    base = (ROOT / "artifacts").resolve(strict=True)
    path = (ROOT / relative).resolve(strict=True)
    if relative.is_absolute() or not path.is_relative_to(base) or path.suffix.lower() != suffix:
        raise ValueError("invalid local artifact path")
    with path.open("rb") as file:
        payload = file.read(max_bytes + 1)
    if len(payload) > max_bytes or sha256_bytes(payload) != artifact.sha256:
        raise ValueError("local artifact exceeds its limit or has a different digest")
    return payload


def classify_case(subtype: str, records: int, data: dict) -> CaseStatus:
    counts = data.get("record_counts", {})
    replay = data.get("repeat_and_replay", {})
    verified = data.get("verified_candidates", [])
    observed = set(data.get("candidate_subtypes", []))
    if (
        data.get("import_status") != "succeeded"
        or data.get("import_error") is not None
        or data.get("catalog_warnings")
        or data.get("verification_failures")
        or counts.get("raw_records") != records
        or counts.get("duplicate") != 0
        or sum(counts.get(key, 0) for key in PACKET_COUNT_FIELDS) != records
        or replay.get("same_witness") is not True
        or not replay.get("duplicates") == replay.get("replay_members") == counts.get("accepted")
        or any(not item["verified"] for item in verified + data.get("unclassified_candidates", []))
        or {item["subtype"] for item in verified} != observed
    ):
        return "failed"
    if observed == {subtype}:
        return "exact_pass"
    if not observed or (subtype == "Mirai-udpplain" and observed == {"DoS/DDoS-UDP_Flood"}):
        return "unknown"
    return "cross_class"


def run_capture(
    client: TestClient,
    service: DataService,
    headers: dict[str, str],
    workspace: str,
    name: str,
    subtype: str,
    capture: Capture,
) -> dict:
    result: dict = {}
    try:
        read_artifact(capture.provenance, ".json", 5_000_000)
        payload = read_artifact(capture, ".pcap", MAX_CAPTURE_BYTES)
        dataset = service.create_dataset(
            service.system_actor(workspace),
            {"name": name, "provenance_type": capture.provenance_type},
            name,
        )
        result = capture_case(client, service, headers, dataset, payload, name)
        if result["import_status"] == "succeeded":
            result["repeat_and_replay"] = repeat_and_replay(
                client, service, headers, dataset, payload
            )
    except (AssertionError, DomainError, IndexError, KeyError, OSError, ValueError) as exc:
        result["failure"] = str(exc) or type(exc).__name__
    return {
        "input": capture.model_dump(),
        "status": classify_case(subtype, capture.records, result),
        **result,
    }


def conflict_control_coverage(data: bytes, records: int) -> dict[str, int]:
    source = BytesIO(data)
    header = capture_header(source, len(data))
    counts: Counter[str] = Counter()
    for number in range(1, records + 1):
        record = record_at_cursor(source, header, len(data), number)
        try:
            src, dst, packet, _ = observation(
                record, include_arp_request=True, include_arp_reply=True, include_dns_datagram=True,
                include_os_probe=True,
            )
        except (InvalidFrame, UnsupportedFrame):
            continue
        if isinstance(packet, ArpSenderObservation):
            counts["arp_request" if packet.arp_operation == 1 else "arp_reply"] += 1
        if isinstance(packet, PacketObservation) and packet.os_probe is not None:
            counts[f"fingerprint_{packet.os_probe.role}"] += 1
        if isinstance(packet, PacketObservation) and packet.protocol_number == 17:
            if 53 in (src.port, dst.port):
                counts["udp_port_53"] += 1
            if packet.dns_message is not None:
                counts[f"dns_{packet.dns_message.message_type}"] += 1
    if source.tell() != len(data):
        raise ValueError("normal control record count differs from manifest")
    return dict(counts)


def run_normal_controls(
    client: TestClient, service: DataService, headers: dict[str, str], workspace: str,
) -> dict:
    manifest = Artifact(path=CONTROL_MANIFEST.as_posix(), sha256=CONTROL_MANIFEST_SHA256)
    rows = json.loads(read_artifact(manifest, ".json", 1_000_000))["inputs"]
    entries = []
    coverage: Counter[str] = Counter()
    hits: Counter[str] = Counter(dict.fromkeys(
        (ARP_CONFLICT_RULE, DNS_DIFFERENCE_RULE, OS_FINGERPRINT_RULE), 0,
    ))
    for index, item in enumerate(rows, 1):
        sample = Capture(
            path=(CONTROL_MANIFEST.parent / item["sample_file"]).as_posix(),
            sha256=item["sample_sha256"], records=item["sample_records"], provenance=manifest,
        )
        result = run_capture(client, service, headers, workspace, f"control-{index:02}", "", sample)
        result["source_id"] = item["source_id"]
        if result["status"] != "failed":
            result["protocol_records"] = conflict_control_coverage(
                read_artifact(sample, ".pcap", MAX_CAPTURE_BYTES), sample.records,
            )
            coverage.update(result["protocol_records"])
            candidates = result["verified_candidates"] + result["unclassified_candidates"]
            hits.update({
                entry["rule"] for entry in candidates
                if entry["rule"] in hits
            })
        entries.append(result)
        print("control", item["source_id"], result["status"], flush=True)
    return {
        "manifest_sha256": manifest.sha256,
        "captures_expected": len(rows),
        "captures_run": sum(result["status"] != "failed" for result in entries),
        "protocols": sorted(coverage),
        "protocol_records": dict(coverage),
        "captures_with_observation_by_rule": dict(hits),
        "rows": entries,
    }


def run(manifest_path: Path, *, normal_controls: bool = False) -> dict:
    manifest_digest, manifest = load_manifest(manifest_path)
    feature_inventory = read_artifact(
        Artifact(path=FEATURE_INVENTORY.as_posix(), sha256=FEATURE_INVENTORY_SHA256),
        ".json",
        1_000_000,
    )
    expected = {
        sample["scenario_label"] for sample in json.loads(feature_inventory)["feature_samples"]
        if sample["family"] != "DoS"
    }
    validate_coverage((scenario.subtype for scenario in manifest.scenarios), expected)
    case_inputs = [
        capture.sha256
        for scenario in manifest.scenarios
        for capture in ([scenario.fixed] if scenario.fixed else []) + scenario.supplements
    ]
    if len(case_inputs) != len(set(case_inputs)):
        raise ValueError("duplicate capture inputs")

    rows = []
    controls = {"captures_run": 0, "protocols": []}
    with TemporaryDirectory(prefix="trace-ciciot-extension-") as directory:
        root = Path(directory)
        settings = OfflineCaptureSettings(
            _env_file=None, app_env="test", model_provider="disabled", model_api_key=None,
            model_base_url=None, model_name=None, web_dist=None,
            database_url=f"sqlite:///{(root / 'case.db').as_posix()}",
            raw_store=root / "raw", staging_store=root / "staging",
            api_read_requests_per_minute=1000, api_write_requests_per_minute=150,
        )
        db = Database(settings)
        db.migrate()
        service = DataService(db, settings)
        app = create_app(settings)
        try:
            workspace, tokens = service.init_workspace("isolated extension acceptance")
            headers = {"Authorization": f"Bearer {tokens['admin']}"}
            with TestClient(app) as client:
                for index, scenario in enumerate(manifest.scenarios, 1):
                    name = f"capture-{index:02}"
                    fixed = {"status": "unverified"}
                    if scenario.fixed:
                        fixed = run_capture(
                            client, service, headers, workspace, f"{name}-00",
                            scenario.subtype, scenario.fixed,
                        )
                    elif scenario.collection_failure:
                        fixed = {"record": scenario.collection_failure.model_dump()}
                        try:
                            read_artifact(scenario.collection_failure, ".json", 5_000_000)
                        except (OSError, ValueError) as exc:
                            fixed.update(status="failed", failure=str(exc))
                        else:
                            fixed["status"] = "collection_failed"
                    supplements = [
                        run_capture(
                            client, service, headers, workspace, f"{name}-{number:02}",
                            scenario.subtype, capture,
                        )
                        for number, capture in enumerate(scenario.supplements, 1)
                    ]
                    rows.append({
                        "subtype": scenario.subtype, "fixed": fixed, "supplements": supplements,
                        "missing_evidence": scenario.missing_evidence,
                    })
                    print(scenario.subtype, fixed["status"], flush=True)
                if normal_controls:
                    controls = run_normal_controls(client, service, headers, workspace)
        finally:
            db.engine.dispose()

    statuses = Counter(row["fixed"]["status"] for row in rows)
    files = {*SOURCE_FILES, "eval/ciciot_extension.py", "packages/storage/database.py"}
    files.update(path.relative_to(ROOT).as_posix() for path in (ROOT / "rules").rglob("*.json"))
    return {
        "at_utc": datetime.now(UTC).isoformat(),
        "mode": "offline_development_acceptance_isolated_sqlite_asgi",
        "application_version": app.version,
        "manifest_sha256": manifest_digest,
        "feature_inventory_sha256": FEATURE_INVENTORY_SHA256,
        "source_sha256": {name: sha256_bytes((ROOT / name).read_bytes()) for name in sorted(files)},
        "total_subtypes": len(rows),
        "fixed_status_counts": dict(statuses),
        "normal_controls": controls,
        "subtypes_with_exact_supplement": sum(
            any(sample["status"] == "exact_pass" for sample in row["supplements"]) for row in rows
        ),
        "strict_gate_passed": statuses["exact_pass"] == len(rows) and (
            not normal_controls or controls["captures_run"] == controls["captures_expected"]
        ),
        "rows": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--result", required=True, type=Path)
    parser.add_argument("--normal-controls", action="store_true")
    args = parser.parse_args()
    if args.result.exists():
        parser.error("result path already exists")
    result = run(args.manifest, normal_controls=args.normal_controls)
    args.result.parent.mkdir(parents=True, exist_ok=True)
    with args.result.open("x", encoding="utf-8") as output:
        json.dump(result, output, ensure_ascii=False, indent=2)
        output.write("\n")
    return 0 if result["strict_gate_passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
