import base64
import json

import pytest

from packages.agent.executor import ToolExecutor
from packages.storage.analysis import AnalysisService
from packages.storage.service import DomainError
from tests.unit.test_http_dns import record


def test_nontext_import_dedup_report_and_safe_evidence(context):
    settings, _, service, workspace, _ = context
    assert settings.model_provider == "disabled"
    actor = service.system_actor(workspace)
    dataset = service.create_dataset(
        actor, {"name": "nontext", "provenance_type": "synthetic"}, "d"
    )
    secret = base64.b64encode(b"/q?" + b"SECRET" * 8 + bytes([255]) + b"%Q").decode()
    for source in ("zeek", "zeek_http"):
        records = []
        for i in range(2):
            row = record(
                ts=1000 + i * 10,
                uid=f"B{i}",
                proto="tcp",
                duration=5,
                status_code=404,
                response_body_len=0,
                **{"id.orig_p": 45000 + i},
            )
            row.pop("uri", None)
            if source == "zeek_http":
                row["uri_b64"] = secret
            else:
                row = {
                    k: v
                    for k, v in row.items()
                    if k
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
            records.append(row)
        raw = b"".join(json.dumps(row).encode() + b"\n" for row in records)
        for repeat in range(2):
            batch = service.stage_bytes(
                actor, dataset["dataset_id"], source, "s", "UTC", raw, source + str(repeat)
            )
            assert service.process_one()
            status = service.get_batch(actor, batch["batch_id"])
            assert status["status"] == "succeeded" and status["quarantined"] == 0
            assert status["accepted"] == (0 if repeat else 2)
            assert status["duplicate"] == (2 if repeat else 0)
    analysis = AnalysisService(service)
    incidents = analysis.list_incidents(actor, dataset["dataset_id"], dataset["default_session_id"])
    assert len(incidents) == 1 and "R10" in incidents[0]["title"]
    run_id = analysis.create_run(actor, incidents[0]["id"], "r")["run_id"]
    assert service.process_one()
    run = analysis.get_run(actor, run_id)
    assert run["state"] == "completed" and run["budget_used"]["model_calls"] == 0
    report = analysis.get_report(actor, run["report_id"])
    assert report["mode"] == "deterministic_fallback" and report["validation"] == "passed"
    assert "失败响应" in json.dumps(report, ensure_ascii=False)
    assert secret not in json.dumps(report)
    tool = ToolExecutor(service, actor, run_id).call("search_events", {"types": ["network.http"]})
    assert len(tool.evidence_ids) == 2
    for event_id in tool.evidence_ids:
        evidence = analysis.evidence(actor, event_id, run["snapshot_id"])
        text = json.dumps(evidence)
        assert evidence["verified"] and "query_shape" in text
        assert "uri_b64" not in text and secret not in text and "SECRET" not in text
    foreign, _ = service.init_workspace("other")
    with pytest.raises(DomainError):
        analysis.evidence(service.system_actor(foreign), tool.evidence_ids[0], run["snapshot_id"])
