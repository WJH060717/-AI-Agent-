import struct

import pytest

from packages.storage.analysis import AnalysisService
from tests.integration.d6_helpers import ModelStub, pending
from tests.integration.d7_helpers import pending_d7
from tests.integration.test_pcap_packet import ipv4_frame, one_dataset, pcap, upload


def packet_connection_draft(kind: str, context: dict) -> dict:
    if kind == "plan":
        return {"action": "draft", "reason_summary": "no useful further query"}
    packets = [event for event in context["facts"] if event["event_type"] == "network.packet"]
    return {
        "claims": [
            {
                "kind": "observed",
                "statement": "all packets establish a connection",
                "fact_predicate": {
                    "name": "connection_seen",
                    "values": {
                        "src_ip": packets[0]["src"]["ip"],
                        "dst_ip": packets[0]["dst"]["ip"],
                        "transport": "tcp",
                    },
                },
                "evidence_ids": [packet["event_id"] for packet in packets[:2]],
            }
        ],
    }


@pytest.mark.parametrize("contradiction", [False, True])
def test_packet_only_model_draft_checks_fields_and_preserves_connection_unknown(
    context, contradiction
):
    settings, _, service, workspace, _ = context
    actor = service.system_actor(workspace)
    dataset = one_dataset(service, actor)
    frames = [
        ipv4_frame(6, struct.pack("!HHIIBBHHH", 12345, port, 1, 0, 0x50, 2, 0, 0, 0))
        for port in range(20, 40)
    ]
    upload(service, actor, dataset, pcap(*[(frame, len(frame)) for frame in frames]))
    service.process_one()
    analysis = AnalysisService(service)
    [incident] = analysis.list_incidents(
        actor, dataset["dataset_id"], dataset["default_session_id"]
    )

    def draft(kind: str, model_context: dict) -> dict:
        reply = packet_connection_draft(kind, model_context)
        if contradiction and kind == "draft":
            reply["claims"][0]["fact_predicate"]["values"]["transport"] = "udp"
        return reply

    with ModelStub(draft) as stub:
        stub.configure(settings)
        run = analysis.create_run(actor, incident["id"], "packet-only-draft", mode="live")
        service.process_one()
    state = analysis.get_run(actor, run["run_id"])
    report = analysis.get_report(actor, state["report_id"])
    if contradiction:
        assert state["state"] == "partial"
        assert report["claim_validation"]["rejected_codes"] == [
            "DRAFT_CONNECTION_EVIDENCE_MISMATCH",
            "DRAFT_CONNECTION_EVIDENCE_MISMATCH",
        ]
        assert stub.requests[-1]["untrusted_context"]["validation_errors"] == [
            "DRAFT_CONNECTION_EVIDENCE_MISMATCH"
        ]
        return
    assert state["state"] == "completed"
    assert report["mode"] == "live"
    assert report["provenance"]["model_execution"] == "protocol_test_stub"
    [claim] = [claim for claim in report["claims"] if claim["claim_id"] == "agent-note-0"]
    assert claim["kind"] == "unknown" and claim.get("fact_predicate") is None
    assert all(ref["fragments"][0]["pcap"] for ref in claim["evidence_refs"])
    assert len(claim["evidence_refs"]) == 2
    assert "all packets establish" not in claim["statement"]
    assert report["claim_validation"]["validated_observed"] >= 1
    assert report["claim_validation"]["stop_reason"] is None
    assert report["claim_validation"]["repair_attempts"] == 0
    assert [req["phase"] for req in stub.requests] == ["plan", "draft"]


@pytest.mark.parametrize(
    "behavior,terminal,rejections,repairs",
    [
        ("wrong_fact", "partial", 2, 1),
        ("repair", "completed", 1, 1),
        ("fake_reference", "partial", 2, 1),
        ("scope_injection", "partial", 0, 0),
    ],
)
def test_rejections_and_repair_are_visible_without_relaxing_budget(
    context, behavior, terminal, rejections, repairs
):
    settings, _, service, _, _ = context
    with ModelStub(behavior) as stub:
        stub.configure(settings)
        actor, _, run = pending(context)
        service.process_one()
    analysis = AnalysisService(service)
    state = analysis.get_run(actor, run["run_id"])
    assert state["state"] == terminal
    report = analysis.get_report(actor, state["report_id"])
    audit = report["claim_validation"]
    assert len(audit["rejected_codes"]) == rejections
    assert audit["repair_attempts"] == repairs
    assert state["budget_used"]["model_calls"] <= 4
    assert state["budget_used"]["tool_calls"] <= 2
    if rejections:
        assert all(code.startswith("DRAFT_") for code in audit["rejected_codes"])
    if terminal == "partial":
        assert report["mode"] == "deterministic_fallback" and audit["stop_reason"]
    else:
        assert report["mode"] == "live" and any(
            c["kind"] == "observed" and "failure" in c["statement"] for c in report["claims"]
        )
    assert "PRIVATE-INJECTION" not in str(report)


def test_periodic_volume_report_explains_heartbeat_and_backup_not_scanning(context):
    actor, _, run, _ = pending_d7(context)
    context[2].process_one()
    analysis = AnalysisService(context[2])
    state = analysis.get_run(actor, run["run_id"])
    report = analysis.get_report(actor, state["report_id"])
    narrative = " ".join(report["alternatives"] + report["recommendations"])
    assert "扫描" not in narrative
    assert "心跳" in narrative and "备份" in narrative
    assert report["claim_validation"]["integrity"] == "verified"
    assert report["claim_validation"]["validated_observed"] >= 2


def test_read_time_integrity_failure_preserves_original_validation_record(context):
    from sqlalchemy import select

    from packages.storage import schema_v5 as t
    from tests.integration.test_d3_safety import prepare

    _, _, service, _, _ = context
    actor, _, incident, analysis = prepare(context)
    run = analysis.create_run(actor, incident["id"], "integrity", mode="deterministic")
    service.process_one()
    report_id = analysis.get_run(actor, run["run_id"])["report_id"]
    original = analysis.get_report(actor, report_id)
    path = next(service.settings.raw_store.rglob("*.jsonl"))
    content = path.read_bytes()
    path.write_bytes(b"corrupted synthetic test input\n")
    try:
        current = analysis.get_report(actor, report_id)
        assert current["validation"] == "partial"
        assert current["claim_validation"] == original["claim_validation"]
        assert analysis.get_run(actor, run["run_id"])["state"] == "completed"
        with service.db.engine.connect() as conn:
            stored = conn.execute(
                select(t.reports.c.payload).where(t.reports.c.id == report_id)
            ).scalar_one()
        assert stored == original
    finally:
        path.write_bytes(content)
    assert analysis.get_report(actor, report_id) == original
