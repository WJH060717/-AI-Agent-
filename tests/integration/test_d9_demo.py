import json

from packages.contracts.context import DatasetContext
from packages.storage.analysis import AnalysisService
from packages.storage.context import ContextService


def test_s1_demo_includes_three_evidence_classes_and_keeps_socket_gaps(context, tmp_path):
    from scripts.build_d9_fixture import build

    _, _, service, workspace, _ = context
    build(tmp_path / "demo")
    root = tmp_path / "demo" / "S1"
    manifest = json.loads((root / "manifest.json").read_bytes())
    assert manifest["provenance_type"] == "synthetic"
    assert manifest["independent_evaluation_run"] is False
    actor = service.system_actor(workspace)
    dataset = service.create_dataset(actor, {"name": "d9", "provenance_type": "synthetic"}, "d9")
    ContextService(service).configure(
        actor,
        dataset["dataset_id"],
        DatasetContext.model_validate_json((root / "context.json").read_bytes()),
        "context",
    )
    for filename, source, sensor in [
        ("network", "zeek", "net-a"),
        ("auth_a", "linux_auth", "auth-a"),
        ("audit", "linux_audit", "audit-a"),
        ("auth_b", "linux_auth", "auth-b"),
        ("alerts", "suricata", "alert-a"),
    ]:
        service.stage_bytes(
            actor,
            dataset["dataset_id"],
            source,
            sensor,
            "UTC",
            (root / f"{filename}.jsonl").read_bytes(),
            filename,
        )
        service.process_one()
    analysis = AnalysisService(service)
    incidents = analysis.list_incidents(actor, dataset["dataset_id"], dataset["default_session_id"])
    assert any("R06" in item["title"] for item in incidents)
    incident = incidents[0]
    run = analysis.create_run(actor, incident["id"], "run", mode="deterministic")
    service.process_one()
    report = analysis.get_report(actor, analysis.get_run(actor, run["run_id"])["report_id"])
    # The later egress finding has a non-overlapping window: keep a separate candidate.
    assert "R06" not in report["provenance"]["rule_version"]
    assert len(report["timeline"]) == 37
    assert "socket" in json.dumps(report, ensure_ascii=False).lower()
    events = analysis.timeline_page(actor, run["run_id"], limit=100)["items"]
    assert {e["event_type"] for e in events} == {
        "network.connection",
        "auth.login",
        "host.process",
        "security.alert",
    }
