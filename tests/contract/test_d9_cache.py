from copy import deepcopy

import pytest

from packages.agent.cache import report_cache_key
from packages.config import Settings


@pytest.mark.parametrize(
    "changed",
    ["workspace_id", "id", "scope", "event_ids", "event", "finding", "budget", "model", "pipeline"],
)
def test_cache_identity_changes_when_any_bound_input_changes(monkeypatch, changed):
    snapshot = {
        "workspace_id": "w",
        "id": "s",
        "incident_id": "i",
        "scope": {"session_id": "session"},
        "event_ids": ["e"],
    }
    events, findings, budget = (
        [{"event_id": "e", "value": 1}],
        [{"rule": "R01", "version": "1"}],
        {"max_model_calls": 4},
    )
    settings = Settings(_env_file=None)
    original = report_cache_key(settings, snapshot, events, findings, budget)
    snapshot = deepcopy(snapshot)
    if changed in snapshot:
        snapshot[changed] = "different"
    elif changed == "event":
        events[0]["value"] = 2
    elif changed == "finding":
        findings[0]["version"] = "2"
    elif changed == "budget":
        budget["max_model_calls"] = 3
    elif changed == "model":
        settings.model_name = "changed"
    else:
        monkeypatch.setattr("packages.agent.cache.pipeline_version", lambda: "changed")
    assert original != report_cache_key(settings, snapshot, events, findings, budget)
