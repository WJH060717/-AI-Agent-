import json
from hashlib import sha256
from pathlib import Path
from unittest.mock import Mock

import pytest

from eval import ciciot_extension
from eval.ciciot_extension import Artifact, classify_case, read_artifact, validate_coverage
from scripts.verify_fragment_rules import repeat_and_replay


def result(*subtypes: str) -> dict:
    return {
        "import_status": "succeeded",
        "record_counts": {
            "raw_records": 8, "accepted": 8, "duplicate": 0, "skipped": 0, "quarantined": 0,
        },
        "candidate_subtypes": list(subtypes),
        "verified_candidates": [{"subtype": subtype, "verified": True} for subtype in subtypes],
        "unclassified_candidates": [],
        "repeat_and_replay": {"same_witness": True, "duplicates": 8, "replay_members": 8},
    }


def test_exact_match_requires_verified_unique_subtype_and_replay() -> None:
    label = "Recon-PingSweep"
    data = result(label)
    assert classify_case(label, 8, data) == "exact_pass"
    assert classify_case(label, 9, data) == "failed"
    data["repeat_and_replay"] = {"same_witness": False}
    assert classify_case(label, 8, data) == "failed"
    data = result(label, "Recon-PortScan")
    assert classify_case(label, 8, data) == "cross_class"
    data = result(label)
    data["verified_candidates"][0]["verified"] = False
    assert classify_case(label, 8, data) == "failed"
    data = result(label)
    data["repeat_and_replay"]["replay_members"] = 7
    assert classify_case(label, 8, data) == "failed"


def test_generic_udp_observation_does_not_classify_mirai() -> None:
    label = "Mirai-udpplain"
    assert classify_case(label, 8, result("DoS/DDoS-UDP_Flood")) == "unknown"
    assert classify_case(label, 8, result("DoS/DDoS-TCP_Flood")) == "cross_class"
    assert classify_case(label, 8, result()) == "unknown"


@pytest.mark.parametrize("labels", [("a",), ("a", "a"), ("a", "b", "extra")])
def test_manifest_requires_each_frozen_subtype_once(labels: tuple[str, ...]) -> None:
    with pytest.raises(ValueError, match="coverage"):
        validate_coverage(labels, {"a", "b"})
    validate_coverage(("a", "b"), {"a", "b"})


def test_artifact_requires_local_path_hash_and_size(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ciciot_extension, "ROOT", tmp_path)
    local = tmp_path / "artifacts"
    local.mkdir()
    sample = b"capture"
    sample_hash = sha256(sample).hexdigest()
    (local / "capture.pcap").write_bytes(sample)
    (tmp_path / "outside.pcap").write_bytes(sample)
    artifact = Artifact(path="artifacts/capture.pcap", sha256=sample_hash)
    assert read_artifact(artifact, ".pcap", len(sample)) == sample
    with pytest.raises(ValueError, match="limit"):
        read_artifact(artifact, ".pcap", len(sample) - 1)
    with pytest.raises(ValueError, match="path"):
        read_artifact(Artifact(path="outside.pcap", sha256=sample_hash), ".pcap", len(sample))
    (local / "capture.pcap").write_bytes(b"changed")
    with pytest.raises(ValueError, match="digest"):
        read_artifact(artifact, ".pcap", len(sample))


def test_reimport_cannot_add_a_candidate_that_replay_reproduces() -> None:
    added = False
    client = Mock()

    def response(data: dict, status: int = 200) -> Mock:
        return Mock(status_code=status, json=Mock(return_value=data))

    def post(url: str, **kwargs: object) -> Mock:
        nonlocal added
        if url == "/api/v1/imports":
            added = True
            return response({"batch_id": "duplicate"}, 202)
        return response({"job_id": "replay", "session_id": "replayed"}, 202)

    def get(url: str, **kwargs: object) -> Mock:
        if url == "/api/v1/incidents":
            return response({"items": [{"id": "candidate"}] if added else [],
                             "next_cursor": None, "warnings": []})
        if url == "/api/v1/incidents/candidate":
            params = client.get.call_args_list[-2].kwargs["params"]
            return response({"finding": {
                "id": params["session_id"], "rule_id": "R24", "evidence_ids": ["packet"],
            }})
        if url == "/api/v1/imports/duplicate":
            return response({"status": "succeeded", "accepted": 0, "duplicate": 1})
        return response({"state": "completed", "detection_status": "complete",
                         "published_events": 1, "session_id": "replayed"})

    client.get.side_effect = get
    client.post.side_effect = post
    with pytest.raises(AssertionError, match="reimport changed"):
        repeat_and_replay(
            client, Mock(), {}, {"dataset_id": "case", "default_session_id": "original"}, b"pcap"
        )


def test_manifest_cannot_promote_a_supplement_to_fixed(tmp_path: Path) -> None:
    from eval.ciciot_extension import load_manifest

    source = ciciot_extension.ROOT / "eval/configs/ciciot-extension-01.json"
    _, manifest = load_manifest(source)
    assert len(manifest.scenarios) == 17
    raw = json.loads(source.read_bytes())
    case = raw["scenarios"][0]
    case["fixed"], case["supplements"][0] = case["supplements"][0], case["fixed"]
    modified = tmp_path / "relabelled.json"
    modified.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="manifest digest"):
        load_manifest(modified)


def test_offline_verifier_settings_ignore_process_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scripts.verify_fragment_rules import OfflineCaptureSettings

    monkeypatch.setenv("REPLAY_EVENT_LIMIT", "1")
    monkeypatch.setenv("MODEL_PROVIDER", "compatible")
    settings = OfflineCaptureSettings()
    assert settings.replay_event_limit == 100_000
    assert settings.model_provider == "disabled"
