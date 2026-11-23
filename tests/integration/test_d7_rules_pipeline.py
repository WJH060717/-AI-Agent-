from packages.storage.analysis import AnalysisService
from tests.integration.d7_helpers import import_d7


def test_r05_r06_real_import_snapshot_and_report_are_reproducible(context):
    actor, dataset, _ = import_d7(context)
    analysis = AnalysisService(context[2])
    incidents = analysis.list_incidents(actor, dataset["dataset_id"], dataset["default_session_id"])
    assert len(incidents) == 1
    detail = analysis.get_incident(actor, incidents[0]["id"])
    assert {f["rule_id"] for f in detail["findings"]} == {"R05", "R06"}
    assert (
        next(f for f in detail["findings"] if f["rule_id"] == "R06")["kind"]
        == "outbound_volume_anomaly"
    )
    run = analysis.create_run(actor, incidents[0]["id"], "deterministic", mode="deterministic")
    context[2].process_one()
    state = analysis.get_run(actor, run["run_id"])
    assert state["state"] == "completed"
    report = analysis.get_report(actor, state["report_id"])
    assert report["investigation_analysis"]["stop_reason"] == "DETERMINISTIC_MODE"
    assert "R05" in report["summary"] and "R06" in report["summary"]


def test_monitoring_still_matches_periodicity_but_normal_backup_baseline_is_not_volume_anomaly(
    context,
):
    actor, dataset, _ = import_d7(context, "normal")
    analysis = AnalysisService(context[2])
    incidents = analysis.list_incidents(actor, dataset["dataset_id"], dataset["default_session_id"])
    findings = [f for i in incidents for f in analysis.get_incident(actor, i["id"])["findings"]]
    assert {f["rule_id"] for f in findings} == {"R05"}


def test_irregular_small_connections_do_not_trigger_r05_r06(context):
    actor, dataset, _ = import_d7(context, "irregular")
    assert (
        AnalysisService(context[2]).list_incidents(
            actor, dataset["dataset_id"], dataset["default_session_id"]
        )
        == []
    )
