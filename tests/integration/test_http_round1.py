import json
from uuid import uuid4

import pytest
from sqlalchemy import select

from packages.agent.executor import ToolExecutor
from packages.contracts.context import DatasetContext
from packages.storage import schema_v4 as t
from packages.storage.analysis import AnalysisService
from packages.storage.context import ContextService
from packages.storage.service import DomainError
from tests.unit.test_http_dns import record


def setup(context):
    settings, _, service, workspace, _ = context
    assert settings.model_provider == "disabled"
    actor = service.system_actor(workspace)
    dataset = service.create_dataset(actor, {"name": "http", "provenance_type": "synthetic"}, "d")
    for source, value in [
        ("zeek", record(ts=990, proto="tcp", duration=20)),
        (
            "zeek_dns",
            record(
                ts=980,
                proto="udp",
                query="example.com",
                qtype=1,
                rcode=0,
                rejected=False,
                answers=["198.51.100.2", "SECRET txt"],
            ),
        ),
        ("zeek_http", record()),
    ]:
        raw = json.dumps(value).encode() + b"\n"
        for repeat in range(2):
            batch = service.stage_bytes(
                actor, dataset["dataset_id"], source, "sensor", "UTC", raw, source + str(repeat)
            )
            assert service.process_one()
            status = service.get_batch(actor, batch["batch_id"])
            assert status["status"] == "succeeded"
            assert status["accepted"] == 1 - repeat and status["duplicate"] == repeat
    return actor, dataset


def test_complete_report_safe_tools_evidence_and_scope(context):
    _, _, service, _, _ = context
    actor, dataset = setup(context)
    analysis = AnalysisService(service)
    incidents = analysis.list_incidents(actor, dataset["dataset_id"], dataset["default_session_id"])
    assert len(incidents) == 1
    created = analysis.create_run(actor, incidents[0]["id"], "r")
    assert service.process_one()
    run = analysis.get_run(actor, created["run_id"])
    assert run["state"] == "completed", run
    assert run["budget_used"]["model_calls"] == 0
    report = analysis.get_report(actor, run["report_id"])
    assert report["mode"] == "deterministic_fallback" and report["validation"] == "passed"
    assert "DNS" in json.dumps(report, ensure_ascii=False)
    assert "内容、完成下载、执行及恶意性未知" in json.dumps(report, ensure_ascii=False)
    assert "SECRET" not in json.dumps(report)
    tools = ToolExecutor(service, actor, created["run_id"])
    result = tools.call("search_events", {"limit": 10})
    assert "SECRET" not in result.model_dump_json()
    assert {"http", "dns"}.issubset({k for item in result.data["items"] for k in item})
    http_only = tools.call("search_events", {"types": ["network.http"]})
    assert len(http_only.evidence_ids) == 1
    for event_id in report["timeline"]:
        evidence = analysis.evidence(actor, event_id, run["snapshot_id"])
        assert evidence["verified"] and "SECRET" not in json.dumps(evidence)
    other_workspace, _ = service.init_workspace("foreign")
    with pytest.raises(DomainError):
        analysis.evidence(
            service.system_actor(other_workspace), report["timeline"][0], run["snapshot_id"]
        )
    with pytest.raises(DomainError):
        analysis.evidence(actor, "f" * 64, run["snapshot_id"])
    with service.db.engine.connect() as conn:
        event = service.get_event(actor, report["timeline"][0])
        obj = (
            conn.execute(
                select(t.objects).where(t.objects.c.id == event["source_locators"][0]["object_id"])
            )
            .mappings()
            .one()
        )
    path = service.settings.raw_store / obj["storage_key"]
    path.write_bytes(path.read_bytes() + b"\n")  # Only this disposable test archive.
    with pytest.raises(DomainError, match="ARCHIVE_INTEGRITY_FAILED"):
        analysis.evidence(actor, report["timeline"][0], run["snapshot_id"])


def test_source_family_and_quarantine(context):
    _, _, service, workspace, _ = context
    actor = service.system_actor(workspace)
    dataset = service.create_dataset(
        actor, {"name": "context", "provenance_type": "synthetic"}, "d"
    )
    ContextService(service).configure(
        actor,
        dataset["dataset_id"],
        DatasetContext.model_validate(
            {
                "sensors": [
                    {
                        "sensor_id": "z",
                        "source_type": "zeek",
                        "instance_id": "i",
                        "observation_domain": "lab",
                        "clock_basis": "fixture",
                    }
                ]
            }
        ),
        "c",
    )
    raw = json.dumps(record()).encode() + b'\n{"ts":true}\n'
    batch = service.stage_bytes(actor, dataset["dataset_id"], "zeek_http", "z", "UTC", raw, "u")
    service.process_one()
    status = service.get_batch(actor, batch["batch_id"])
    assert status["accepted"] == status["quarantined"] == 1
    with pytest.raises(DomainError, match="SENSOR_CONTEXT_MISMATCH"):
        service.stage_bytes(actor, dataset["dataset_id"], "zeek_dns", str(uuid4()), "UTC", raw, "x")
