"""Guards around the authorized one-off operations script; no Docker/model calls."""

import importlib.util
import json
from pathlib import Path

import pytest


@pytest.fixture
def trial():
    path = Path(__file__).resolve().parents[2] / ".tools/p1-deepseek-01/trial.py"
    spec = importlib.util.spec_from_file_location("deepseek_trial", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def configuration():
    return {
        "model_provider": "compatible",
        "model_base_url": "https://api.deepseek.com",
        "model_name": "deepseek-flash",
        "model_api_key": "not-a-real-key-local-canary",
        "model_input_usd_per_million": 0.3,
        "model_output_usd_per_million": 1.2,
        "model_price_version": "test",
        "agent_max_cost_microusd": 100000,
    }


def test_valid_trial_config_adds_non_thinking_without_mutating_private_input(trial):
    value = configuration()
    result = trial.validate_configuration(value)
    assert result["model_thinking"] == "disabled"
    assert "model_thinking" not in value


@pytest.mark.parametrize(
    "changes",
    [
        {"model_base_url": "https://different.invalid"},
        {"agent_max_cost_microusd": 100001},
        {"model_api_key": "local-canary\nMODEL_PROVIDER=disabled"},
        {"model_name": "other-model"},
        {"model_test_stub": True},
        {"model_output_tokens_per_call": 3000},
    ],
)
def test_trial_rejects_scope_or_secret_format_changes_without_leaking(trial, changes):
    with pytest.raises(ValueError) as caught:
        trial.validate_configuration(configuration() | changes)
    assert "canary" not in str(caught.value)


def test_exclusive_marker_blocks_a_second_trial_and_preserves_first(trial, tmp_path):
    path = tmp_path / "trial-started.json"
    trial.write_new(path, {"idempotency_key": "first"})
    with pytest.raises(FileExistsError):
        trial.write_new(path, {"idempotency_key": "second"})
    assert json.loads(path.read_bytes()) == {"idempotency_key": "first"}


def test_container_api_keeps_token_in_stdin_and_returns_response(trial, monkeypatch):
    def transport(args, **kwargs):
        assert "private-local-token" not in " ".join(args)
        payload = json.loads(kwargs["data"])
        assert payload["token"] == "private-local-token"
        assert payload["path"] == "/health/live"
        return b'{"ok":true,"value":{"status":"ok"}}'

    monkeypatch.setattr(trial, "checked", transport)
    assert trial.container_api("private-local-token", "/health/live") == {"status": "ok"}


def test_resume_uncreated_retains_original_idempotency_and_refuses_created(
    trial, tmp_path, monkeypatch
):
    monkeypatch.setattr(trial, "TASK", tmp_path)
    monkeypatch.setattr(
        trial, "source_counts", lambda: {"events": 37, "reports": 1, "runs": 1, "active_jobs": 0}
    )
    original = {
        "idempotency_key": "original",
        "incident_id": trial.INCIDENT,
        "max_investigations": 1,
        "max_cost_microusd": 100000,
    }
    trial.write_new(tmp_path / "trial-started.json", original)
    assert trial.trial_marker(True) == original
    (tmp_path / "trial-created.json").write_text("{}", encoding="utf-8")
    with pytest.raises(RuntimeError):
        trial.trial_marker(True)


def test_resume_uncreated_rejects_an_existing_database_run(trial, tmp_path, monkeypatch):
    monkeypatch.setattr(trial, "TASK", tmp_path)
    monkeypatch.setattr(
        trial, "source_counts", lambda: {"events": 37, "reports": 1, "runs": 2, "active_jobs": 0}
    )
    trial.write_new(tmp_path / "trial-started.json", {"idempotency_key": "original"})
    with pytest.raises(RuntimeError):
        trial.trial_marker(True)
