import json

import pytest

from packages.agent.executor import ToolExecutor
from packages.storage.analysis import AnalysisService
from packages.storage.service import DomainError
from tests.unit.test_cc_round2 import TOKEN
from tests.unit.test_http_dns import record


@pytest.mark.parametrize("multi_host", [False, True])
def test_callbacks_import_report_tools_and_foreign_scope(context, multi_host):
    settings, _, service, workspace, _ = context
    assert settings.model_provider == "disabled"
    actor = service.system_actor(workspace)
    dataset = service.create_dataset(
        actor, {"name": "callbacks", "provenance_type": "synthetic"}, "d"
    )
    for source in ("zeek", "zeek_http"):
        rows = []
        for i in range(3):
            rows.append(
                record(
                    ts=1000 + 60 * i,
                    uid=f"CC{i}",
                    proto="tcp",
                    duration=5,
                    user_agent="Client/1",
                    uri=f"/check?device={TOKEN}",
                    response_body_len=64,
                    **{"id.orig_p": 42000 + i},
                )
            )
        if source == "zeek":
            rows = [
                {
                    key: value
                    for key, value in row.items()
                    if key
                    in {
                        "ts",
                        "uid",
                        "proto",
                        "duration",
                        "id.orig_h",
                        "id.orig_p",
                        "id.resp_h",
                        "id.resp_p",
                    }
                }
                for row in rows
            ]
        if multi_host and source == "zeek_http":
            for index, row in enumerate(rows):
                row["host"] = "config.example" if index == 0 else "ping.example"
                row["status_code"] = 200 if index == 0 else 404
        raw = b"".join(json.dumps(row).encode() + b"\n" for row in rows)
        for repeat in range(2):
            batch = service.stage_bytes(
                actor, dataset["dataset_id"], source, "s", "UTC", raw, source + str(repeat)
            )
            assert service.process_one()
            status = service.get_batch(actor, batch["batch_id"])
            assert status["status"] == "succeeded" and status["quarantined"] == 0
            assert status["accepted"] == (0 if repeat else 3)
            assert status["duplicate"] == (3 if repeat else 0)
    analysis = AnalysisService(service)
    incidents = analysis.list_incidents(actor, dataset["dataset_id"], dataset["default_session_id"])
    assert len(incidents) == 1 and ("R09" if multi_host else "R08") in incidents[0]["title"]
    run_id = analysis.create_run(actor, incidents[0]["id"], "r")["run_id"]
    assert service.process_one()
    run = analysis.get_run(actor, run_id)
    assert run["state"] == "completed" and run["budget_used"]["model_calls"] == 0, run
    report = analysis.get_report(actor, run["report_id"])
    assert report["mode"] == "deterministic_fallback" and report["validation"] == "passed"
    assert "正常更新" in json.dumps(report, ensure_ascii=False)
    assert TOKEN not in json.dumps(report)
    tools = ToolExecutor(service, actor, run_id)
    found = tools.call("search_events", {"types": ["network.http"]})
    assert len(found.evidence_ids) == 3
    assert TOKEN not in found.model_dump_json() and "Client/1" not in found.model_dump_json()
    for event_id in found.evidence_ids:
        evidence = analysis.evidence(actor, event_id, run["snapshot_id"])
        assert evidence["verified"] and "client_shape" in json.dumps(evidence)
        assert TOKEN not in json.dumps(evidence)
    foreign, _ = service.init_workspace("other")
    with pytest.raises(DomainError):
        analysis.evidence(service.system_actor(foreign), found.evidence_ids[0], run["snapshot_id"])
