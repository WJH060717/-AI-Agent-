import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from apps.api.main import create_app
from packages.storage.analysis import AnalysisService


def test_detection_limit_preserves_ingest_and_exposes_incomplete_coverage(context):
    settings, _, service, workspace, tokens = context
    settings.detection_event_limit = 2
    actor = service.system_actor(workspace)
    dataset = service.create_dataset(
        actor, {"name": "bounded", "provenance_type": "synthetic"}, "d"
    )
    line = json.loads(Path("data/fixtures/d1/zeek.jsonl").read_bytes().splitlines()[0])
    for index, count in enumerate([2, 1]):
        content = b"".join(
            (json.dumps(line | {"uid": f"d11-{index}-{i}"}) + "\n").encode() for i in range(count)
        )
        batch = service.stage_bytes(
            actor, dataset["dataset_id"], "zeek", "s", "UTC", content, str(index)
        )
        assert service.process_one()
        status = service.get_batch(actor, batch["batch_id"])
        assert status["accepted"] == count
        assert status["status"] == ("succeeded" if index == 0 else "partial")
    assert status["error_code"] == "RULE_SCOPE_TOO_LARGE"
    scope = {"dataset_id": dataset["dataset_id"], "session_id": dataset["default_session_id"]}
    # Raising the limit after a partial publication is not a completed re-detection.
    settings.detection_event_limit = 10000
    with TestClient(create_app(settings)) as client:
        client.headers["Authorization"] = f"Bearer {tokens['admin']}"
        overview = client.get("/api/v1/overview", params=scope).json()
        assert overview["event_count"] == 3
        assert overview["detection_status"] == "partial"
        assert overview["warnings"] == ["RULE_SCOPE_TOO_LARGE"]
        page = client.get("/api/v1/events", params=scope).json()
        assert len(page["items"]) == 3
        assert client.get("/api/v1/incidents", params=scope).json()["warnings"] == [
            "RULE_SCOPE_TOO_LARGE"
        ]
    for event in page["items"]:
        service.verify_evidence(actor, event["event_id"])
    other = service.create_dataset(
        actor, {"name": "other", "provenance_type": "synthetic"}, "other"
    )
    assert (
        service.overview(actor, other["dataset_id"], other["default_session_id"])["warnings"] == []
    )


def test_unexpected_detection_errors_still_fail_closed(context, monkeypatch):
    _, _, service, workspace, _ = context
    actor = service.system_actor(workspace)
    dataset = service.create_dataset(actor, {"name": "error", "provenance_type": "synthetic"}, "d")
    service.stage_bytes(
        actor,
        dataset["dataset_id"],
        "zeek",
        "s",
        "UTC",
        Path("data/fixtures/d1/zeek.jsonl").read_bytes(),
        "u",
    )

    def fail(*_):
        raise RuntimeError("unexpected detection failure")

    monkeypatch.setattr(AnalysisService, "detect", fail)
    with pytest.raises(RuntimeError, match="unexpected detection failure"):
        service.process_one()
    assert (
        service.overview(actor, dataset["dataset_id"], dataset["default_session_id"])["event_count"]
        == 0
    )
