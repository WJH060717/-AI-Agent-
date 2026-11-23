import json
import tomllib
from pathlib import Path

import pytest

from scripts.p1_acceptance import model_readiness, readiness_report, write_report


def configured() -> dict:
    return {
        "model_provider": "compatible",
        "model_base_url": "https://approved.invalid/v1",
        "model_name": "approved-model",
        "model_api_key": "private-canary-never-in-report",
        "model_input_usd_per_million": "1.25",
        "model_output_usd_per_million": "2.50",
        "model_price_version": "owner-supplied-price-version",
        "agent_max_cost_microusd": 100000,
    }


def test_missing_configuration_does_not_inherit_shell_secrets(monkeypatch):
    for name, value in configured().items():
        monkeypatch.setenv(name.upper(), str(value))
    result = model_readiness(None)
    assert result.status == "missing"
    assert not result.connectivity_verified and not result.real_llm_accepted
    assert "private-canary" not in result.model_dump_json()


def test_valid_private_configuration_is_only_configuration_ready(tmp_path, monkeypatch):
    monkeypatch.setenv("MODEL_TEST_STUB", "true")
    path = tmp_path / "private.json"
    path.write_text(json.dumps(configured()), encoding="utf-8")
    result = model_readiness(path)
    assert result.status == "configuration_ready"
    assert result.per_run_budget_microusd == 100000
    assert not result.connectivity_verified and not result.real_llm_accepted
    assert "private-canary" not in result.model_dump_json()
    assert "approved.invalid" not in result.model_dump_json()


@pytest.mark.parametrize(
    "change",
    [
        {"model_api_key": ""},
        {"model_price_version": "unconfigured"},
        {"model_input_usd_per_million": None},
        {"agent_max_cost_microusd": 0},
        {"model_provider": "disabled"},
        {"model_base_url": "http://outside.invalid/v1"},
        {"model_base_url": "https://secret-in-url:password@approved.invalid/v1"},
        {"model_test_stub": True},
        {"unknown_secret_field": "private-canary"},
    ],
)
def test_invalid_or_incomplete_configuration_never_leaks_values(tmp_path, change):
    path = tmp_path / "private.json"
    path.write_text(json.dumps(configured() | change), encoding="utf-8")
    result = model_readiness(path)
    assert result.status == "incomplete" and result.errors
    assert not result.real_llm_accepted
    assert not any(
        s in result.model_dump_json() for s in ["private-canary", "password", "secret-in-url"]
    )


@pytest.mark.parametrize(
    "content",
    [
        '{"model_provider":"compatible","model_provider":"disabled"}',
        "not json private-canary",
        "x" * 32769,
        "[]",
    ],
)
def test_bad_private_file_is_rejected_without_dumping_content(tmp_path, content):
    path = tmp_path / "private.json"
    path.write_text(content, encoding="utf-8")
    result = model_readiness(path)
    assert result.status == "incomplete" and result.errors
    assert "private-canary" not in result.model_dump_json()


def test_missing_file_and_output_overwrite_are_safe(tmp_path):
    assert model_readiness(tmp_path / "absent").status == "incomplete"
    path = tmp_path / "report.json"
    write_report(path, {"safe": True})
    with pytest.raises(FileExistsError):
        write_report(path, {"safe": False})
    assert json.loads(path.read_bytes()) == {"safe": True}


def test_local_readiness_never_auto_closes_external_acceptance():
    root = Path(__file__).resolve().parents[2]
    result = readiness_report(root, None, probe=lambda *args: 0)
    assert result["deployment"]["compose_config_valid"]
    assert result["deployment"]["engine_available"]
    assert result["formal_data"]["planned"] == 33
    assert not result["formal_data"]["data_collection_complete"]
    assert result["open_p1"] == ["D10-001", "D10-002", "D10-003", "D10-005", "D10-006"]
    assert result["human_signatures"] == [] and not result["release_ready"]


def test_compose_images_match_current_application_version():
    root = Path(__file__).resolve().parents[2]
    version = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"][
        "version"
    ]
    compose = (root / "infra/compose.p1.yaml").read_text(encoding="utf-8")
    assert f"image: telemetry-trace:{version}" in compose
    assert f"image: telemetry-trace-web:{version}" in compose
