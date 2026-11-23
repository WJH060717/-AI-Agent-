from pathlib import Path

from packages.contracts.context import DatasetContext
from packages.storage.analysis import AnalysisService
from packages.storage.context import ContextService
from scripts.build_d6_fixture import build


def import_case(context, normal=False):
    settings, _, service, workspace, _ = context
    actor = service.system_actor(workspace)
    folder = Path(settings.staging_store) / "d6-rules-fixture"
    build(folder)
    dataset = service.create_dataset(
        actor, {"name": "four-rules", "provenance_type": "synthetic"}, "rules"
    )
    ContextService(service).configure(
        actor,
        dataset["dataset_id"],
        DatasetContext.model_validate_json((folder / "context.json").read_bytes()),
        "ctx",
    )
    for name, source, sensor in (
        ("network", "zeek", "net-a"),
        ("auth_a", "linux_auth", "auth-a"),
        ("audit", "linux_audit", "audit-a"),
    ):
        filename = ("normal_" if normal else "") + name
        service.stage_bytes(
            actor,
            dataset["dataset_id"],
            source,
            sensor,
            "UTC",
            (folder / f"{filename}.jsonl").read_bytes(),
            name,
        )
        service.process_one()
    return actor, dataset, folder


def test_r03_r04_actual_import_attempt_then_success_candidates_and_reproducible_report(context):
    _, _, service, _, _ = context
    actor, dataset, folder = import_case(context)
    analysis = AnalysisService(service)
    before = analysis.list_incidents(actor, dataset["dataset_id"], dataset["default_session_id"])
    old = analysis.get_incident(actor, before[0]["id"])
    assert any(f["kind"] == "remote_access_attempt" for f in old["findings"])
    service.stage_bytes(
        actor,
        dataset["dataset_id"],
        "linux_auth",
        "auth-b",
        "UTC",
        (folder / "auth_b.jsonl").read_bytes(),
        "target-auth",
    )
    service.process_one()
    incidents = analysis.list_incidents(actor, dataset["dataset_id"], dataset["default_session_id"])
    assert len(incidents) == 1
    current = analysis.get_incident(actor, incidents[0]["id"])
    assert {f["rule_id"] for f in current["findings"]} == {"R01", "R02", "R03", "R04"}
    assert not any(f["kind"] == "remote_access_attempt" for f in current["findings"])
    run = analysis.create_run(actor, incidents[0]["id"], "four-rules")
    service.process_one()
    state = analysis.get_run(actor, run["run_id"])
    assert state["state"] == "completed"
    report = analysis.get_report(actor, state["report_id"])
    assert "R03" in report["summary"] and "R04" in report["summary"]
    assert report["mode"] == "deterministic_fallback"


def test_authorized_normal_host_management_without_suspicious_seed_does_not_trigger(context):
    _, _, service, _, _ = context
    actor, dataset, folder = import_case(context, normal=True)
    service.stage_bytes(
        actor,
        dataset["dataset_id"],
        "linux_auth",
        "auth-b",
        "UTC",
        (folder / "auth_b.jsonl").read_bytes(),
        "target-auth",
    )
    service.process_one()
    assert (
        AnalysisService(service).list_incidents(
            actor, dataset["dataset_id"], dataset["default_session_id"]
        )
        == []
    )
