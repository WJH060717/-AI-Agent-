from pathlib import Path

import pytest

from eval.contracts import EvaluationConfig
from eval.runner import collect, import_run
from packages.agent.runtime import AgentRuntime
from tests.contract.test_d11_evaluation import engineering_config
from tests.integration.d6_helpers import ModelStub


@pytest.mark.parametrize("group", ["B2", "B3"])
def test_failed_investigation_keeps_persistent_reservation_and_timing(context, monkeypatch, group):
    settings, db, service, workspace, _ = context
    with ModelStub() as stub:
        stub.configure(settings)
        config = EvaluationConfig.model_validate(
            engineering_config() | {"model_mode": "protocol_stub"}
        )
        actor = service.system_actor(workspace)
        dataset = import_run(service, actor, config.runs[0], Path(__file__).resolve().parents[2])

        def failed_after_reservation(runtime):
            runtime.reserve(
                "model", "draft", {"phase": "draft"}, input_tokens=10, output_tokens=10, wait_ms=1
            )
            raise ValueError("injected failure after durable reservation")

        monkeypatch.setattr(AgentRuntime, "run", failed_after_reservation)
        row = collect(service, actor, dataset, config.runs[0], config, group, 0)
        assert row["status"] == "failed"
        assert row["investigations"], "failed attempt disappeared"
        assert row["usage"]["model_calls"] >= 1 and row["usage"]["input_tokens"] >= 10
        item = row["investigations"][0]
        assert item["status"] == "failed" and item["elapsed_ms"] > 0
        assert item["terminal_observed"] is True


def test_retry_wait_and_abandoned_reservation_stay_in_investigation(context, monkeypatch):
    settings, _, service, workspace, _ = context
    with ModelStub() as stub:
        stub.configure(settings)
        config = EvaluationConfig.model_validate(
            engineering_config() | {"model_mode": "protocol_stub"}
        )
        actor = service.system_actor(workspace)
        dataset = import_run(service, actor, config.runs[0], Path(__file__).resolve().parents[2])
        original = AgentRuntime.run
        calls = 0

        def once_transient(runtime):
            nonlocal calls
            calls += 1
            if calls == 1:
                runtime.reserve(
                    "model",
                    "draft",
                    {"phase": "draft"},
                    input_tokens=10,
                    output_tokens=10,
                    wait_ms=1,
                )
                raise OSError("injected transient interruption")
            return original(runtime)

        monkeypatch.setattr(AgentRuntime, "run", once_transient)
        row = collect(service, actor, dataset, config.runs[0], config, "B3", 0)
        item = row["investigations"][0]
        assert item["attempts"] == 2 and item["terminal_observed"] is True
        assert item["elapsed_ms"] >= 2000
        assert "OSError" in item["attempt_errors"]
        assert item["usage"]["model_calls"] > 1 and item["usage"]["input_tokens"] >= 10
