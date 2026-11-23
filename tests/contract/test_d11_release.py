import hashlib
import json

import pytest

from tests.contract.test_d10_release import source  # noqa: F401


@pytest.mark.parametrize("day", [11, 12])
def test_d11_candidate_has_own_acceptance_config_and_install_guide(source, tmp_path, day):  # noqa: F811
    from scripts.release_manifest import build_candidate, build_manifest, verify_manifest

    (source / "pyproject.toml").write_text(f'[project]\nversion="0.1.0.dev{day}"\n')
    (source / "packages/contracts/generated/openapi.json").write_text(
        json.dumps({"info": {"version": f"0.1.0.dev{day}"}})
    )
    for name in ("runbook.md", "limitations.md", "acceptance.json", "defects.json"):
        (source / f"docs/d{day}-{name}").write_text(f"D{day}" if name.endswith("md") else "{}")
    if day == 12:
        (source / "eval/d12-inputs.json").write_text("{}")
        for name in ("acceptance.json", "defects.json"):
            (source / f"docs/d11-{name}").write_text("{}")
    path = source / "data/fixtures/approved.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('{"synthetic":true}\n')
    reviewed = json.loads((source / "infra/release-inputs.json").read_bytes())
    reviewed["files"]["data/fixtures/approved.jsonl"] = hashlib.sha256(
        path.read_bytes()
    ).hexdigest()
    (source / "infra/release-inputs.json").write_text(json.dumps(reviewed))
    (source / "eval/configs").mkdir()
    (source / "eval/configs/d11-engineering.json").write_text(
        json.dumps(
            {
                "version": "d11-evaluation@1.0.0",
                "profile": "engineering",
                "model_mode": "protocol_stub",
                "runs": [
                    {
                        "run_id": "unit",
                        "scenario_id": "S1",
                        "sources": [
                            {
                                "source_type": "zeek",
                                "sensor_id": "s",
                                "object": {
                                    "path": "data/fixtures/approved.jsonl",
                                    "sha256": reviewed["files"]["data/fixtures/approved.jsonl"],
                                },
                            }
                        ],
                    }
                ],
            }
        )
    )
    frozen = build_manifest(source, f"d{day}-unit")
    assert frozen["version"] == f"d{day}-freeze@1.0.0"
    assert "eval/configs/d11-engineering.json" in frozen["files"]
    if day == 12:
        assert {"docs/d11-acceptance.json", "docs/d11-defects.json"} <= frozen["files"].keys()
    candidate = tmp_path / "candidate"
    build_candidate(source, frozen, candidate)
    assert (candidate / "README-install.md").read_text() == f"D{day}"
    verify_manifest(candidate, frozen)
