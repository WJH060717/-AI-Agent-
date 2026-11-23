"""Frozen development capture sets bind manifests to their requested version."""

import hashlib

import pytest

from scripts import verify_fragment_rules as verifier


@pytest.fixture
def versions(tmp_path, monkeypatch):
    manifests = {"v1": b'{"samples": []}', "v2": b'{"samples": [{"packet_records": 8192}]}'}
    for version, content in manifests.items():
        (tmp_path / f"{version}.json").write_bytes(content)
    monkeypatch.setattr(
        verifier,
        "FIXED_MANIFEST_HASHES",
        {version: hashlib.sha256(content).hexdigest() for version, content in manifests.items()},
    )
    return tmp_path


def test_requested_frozen_manifest_passes(versions):
    digest, samples = verifier.load_fixed_manifest(versions / "v2.json", "v2")
    assert digest == verifier.FIXED_MANIFEST_HASHES["v2"]
    assert samples == [{"packet_records": 8192}]


@pytest.mark.parametrize("selected,requested", [("v1", "v2"), ("v2", "v1")])
def test_frozen_manifests_cannot_be_swapped(versions, selected, requested):
    with pytest.raises(ValueError, match="fixed sample manifest changed"):
        verifier.load_fixed_manifest(versions / f"{selected}.json", requested)


def test_modified_sample_manifest_fails_even_when_decoded_data_is_identical(versions):
    manifest = versions / "v2.json"
    manifest.write_bytes(manifest.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="fixed sample manifest changed"):
        verifier.load_fixed_manifest(manifest, "v2")


@pytest.mark.parametrize("prefix", ["DoS", "DDoS"])
def test_merged_taxonomy_preserves_behavior(prefix):
    assert verifier.scored_subtype(f"{prefix}-TCP_Flood") == "DoS/DDoS-TCP_Flood"
    assert verifier.scored_subtype(f"{prefix}-SYN_Flood") != "DoS/DDoS-TCP_Flood"
    with pytest.raises(ValueError, match="unknown fixed capture behavior"):
        verifier.scored_subtype(f"{prefix}-Unexpected")


def test_fixed_gate_accepts_only_verified_slowloris_unknown():
    unknown = {
        "expected_subtype": "DoS/DDoS-SlowLoris",
        "main_prediction": "unknown",
        "unclassified_candidates": [{"rule": "R23", "verified": True}],
        "passed": False,
    }
    result = {
        "samples": [{"passed": True} for _ in range(11)] + [unknown],
        "samples_checked_without_errors": 12,
        "samples_with_same_replayed_evidence": 12,
        "samples_with_reconciled_records": 12,
        "cross_class_candidates": 0,
        "all_samples_passed": 11,
    }
    assert verifier.fixed_v2_gate(result)
    unknown["expected_subtype"] = "DoS/DDoS-HTTP_Flood"
    assert not verifier.fixed_v2_gate(result)
    unknown["expected_subtype"] = "DoS/DDoS-SlowLoris"
    unknown["unclassified_candidates"][0]["verified"] = False
    assert not verifier.fixed_v2_gate(result)
