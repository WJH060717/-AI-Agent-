import json

from packages.storage.analysis import AnalysisService
from packages.storage.reports import ReportService
from tests.integration.d6_helpers import pending


def test_live_status_then_report_and_exports_share_saved_progress(context):
    _, _, service, _, _ = context
    actor, _, run = pending(context, mode="deterministic")
    analysis = AnalysisService(service)
    queued = analysis.get_run(actor, run["run_id"])
    assert [s["status"] for s in queued["pipeline_progress"]["stages"]][:3] == ["available"] * 3
    service.process_one()
    final = analysis.get_run(actor, run["run_id"])
    report = analysis.get_report(actor, final["report_id"])
    assert final["pipeline_progress"] == report["pipeline_progress"]
    assert report["pipeline_progress"]["stages"][4]["status"] == "not_run"
    assert report["pipeline_progress"]["stages"][5]["status"] == "completed"
    exports = ReportService(service)
    bundle = json.loads(exports.export(actor, final["report_id"], "json"))
    assert bundle["report"]["pipeline_progress"] == report["pipeline_progress"]
    html = exports.export(actor, final["report_id"], "html").decode()
    assert "六阶段执行状态" in html and "情报归因 · 未执行" in html
    assert analysis.get_run(actor, run["run_id"])["pipeline_progress"] == final["pipeline_progress"]


def test_legacy_report_stays_legacy_without_recomputing_progress(context):
    from sqlalchemy import update

    from packages.storage import schema_v5 as t

    actor, _, run = pending(context, mode="deterministic")
    _, db, service, _, _ = context
    analysis = AnalysisService(service)
    service.process_one()
    final = analysis.get_run(actor, run["run_id"])
    report = analysis.get_report(actor, final["report_id"])
    report.pop("pipeline_progress")
    # Simulate a report written before this field existed in an isolated test database.
    with db.engine.begin() as conn:
        conn.execute(
            update(t.reports).where(t.reports.c.id == final["report_id"]).values(payload=report)
        )
    assert "pipeline_progress" not in analysis.get_run(actor, run["run_id"])
    assert "pipeline_progress" not in analysis.get_report(actor, final["report_id"])
    assert "pipeline_progress" not in json.dumps(report)


def test_queue_cancel_before_execution_keeps_trace_not_run(context):
    from packages.storage.queue import Queue

    settings, db, service, _, _ = context
    actor, _, run = pending(context, mode="deterministic")
    Queue(db, settings).cancel(actor, run["job_id"])
    stages = AnalysisService(service).get_run(actor, run["run_id"])["pipeline_progress"]["stages"]
    assert [s["status"] for s in stages[:3]] == ["available"] * 3
    assert stages[3]["status"] == "not_run"


def test_prepared_crop_and_cancelled_draft_preserve_proven_execution(context, monkeypatch):
    import pytest

    import packages.storage.analysis as module
    from packages.agent.runtime import AgentRuntime
    from packages.storage.queue import LeaseLost, Queue

    settings, db, service, _, _ = context
    actor, _, run = pending(context, mode="deterministic")
    analysis = AnalysisService(service)
    graph = module.evidence_graph
    monkeypatch.setattr(
        module, "evidence_graph", lambda events, scope: graph(events, scope) | {"truncated": True}
    )
    queue = Queue(db, settings)
    lease = queue.claim("pipeline-cancel")

    def cancel_draft(runtime):
        runtime.step()
        runtime.step()
        stages = analysis.get_run(actor, run["run_id"])["pipeline_progress"]["stages"]
        assert stages[3]["status"] == "partial"
        queue.cancel(actor, run["job_id"])
        runtime.guard()

    monkeypatch.setattr(AgentRuntime, "run", cancel_draft)
    with pytest.raises(LeaseLost):
        analysis.process(lease, queue)
    stages = analysis.get_run(actor, run["run_id"])["pipeline_progress"]["stages"]
    assert [s["status"] for s in stages[:3]] == ["completed"] * 3
    assert stages[3]["status"] == "partial"
    assert stages[5]["status"] == "cancelled"
