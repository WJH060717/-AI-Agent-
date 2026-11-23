import asyncio
import json

import httpx
from sqlalchemy import select

from apps.api.main import create_app
from packages.contracts.context import DatasetContext
from packages.storage import schema_v5 as t
from packages.storage.analysis import AnalysisService
from packages.storage.context import ContextService
from scripts.build_d7_fixture import build
from tests.integration.d4_helpers import context_payload
from tests.integration.d6_helpers import ModelStub
from tests.integration.d7_helpers import import_d7, pending_d7


def test_empty_baseline_keeps_legacy_context_canonical_bytes(context):
    _, db, service, workspace, _ = context
    actor = service.system_actor(workspace)
    dataset = service.create_dataset(
        actor, {"name": "legacy", "provenance_type": "synthetic"}, "legacy"
    )
    payload = DatasetContext.model_validate(context_payload())
    ContextService(service).configure(actor, dataset["dataset_id"], payload, "ctx")
    with db.engine.connect() as conn:
        stored = conn.execute(
            select(t.contexts.c.payload).where(t.contexts.c.id == dataset["dataset_id"])
        ).scalar_one()
    assert "egress_baselines" not in stored
    assert json.dumps(stored, sort_keys=True) == json.dumps(
        payload.model_dump(mode="json", exclude={"egress_baselines"}), sort_keys=True
    )


def test_viewer_can_read_typed_comparison_but_other_workspace_cannot(context):
    settings, _, service, _, tokens = context
    with ModelStub("d7") as stub:
        stub.configure(settings)
        _, _, run, _ = pending_d7(context)
        service.process_one()

    async def scenario():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_app(settings)), base_url="http://test"
        ) as client:
            headers = {"Authorization": f"Bearer {tokens['viewer']}"}
            state = (
                await client.get(f"/api/v1/investigations/{run['run_id']}", headers=headers)
            ).json()
            assert state["query_stop_reason"] == "ACTIONABLE_GAPS_RESOLVED"
            url = f"/api/v1/reports/{state['report_id']}"
            response = await client.get(url, headers=headers)
            assert response.status_code == 200
            data = response.json()["investigation_analysis"]
            assert len(data["changes"]) == 2 and data["config_hash"]
            for change in data["changes"]:
                ref = change["evidence_refs"][0]
                evidence = await client.get(
                    f"/api/v1/evidence/{ref['event_id']}",
                    headers=headers,
                    params={"snapshot_id": run["snapshot_id"]},
                )
                assert evidence.status_code == 200
            _, other = service.init_workspace("other")
            assert (
                await client.get(url, headers={"Authorization": f"Bearer {other['viewer']}"})
            ).status_code == 404

    asyncio.run(scenario())


def test_countercontext_evidence_shows_safe_process_fields_and_hides_commands_accounts_extensions(
    context,
):
    root = context[0].staging_store / "projected-d7"
    build(root)
    records = [json.loads(line) for line in (root / "audit.jsonl").read_bytes().splitlines()]
    for record in records:
        record["extensions"] = {"sensitive": "PRIVATE-EXTENSION"}
        if record["record_type"] == "SYSCALL":
            record["user"]["name"] = "PRIVATE-ACCOUNT"
            record["process"]["command_line"] = "PRIVATE-COMMAND"
            record["process"]["arbitrary"] = {"value": "PRIVATE-EXTRA"}
    actor, dataset, _ = import_d7(context, audit_records=records)
    service = context[2]
    analysis = AnalysisService(service)
    incident = analysis.list_incidents(actor, dataset["dataset_id"], dataset["default_session_id"])[
        0
    ]
    run = analysis.create_run(actor, incident["id"], "projection")
    service.process_one()
    events = service.list_events(actor, dataset["dataset_id"], dataset["default_session_id"], 100)[
        "items"
    ]
    event = next(
        e
        for e in events
        if e.get("process") and e["process"]["executable"] == "/usr/bin/node_exporter"
    )
    result = analysis.evidence(actor, event["event_id"], run["snapshot_id"])
    serialized = json.dumps(result)
    projected = [
        json.loads(line["text"]) for fragment in result["fragments"] for line in fragment["lines"]
    ]
    syscall = next(row for row in projected if row["record_type"] == "SYSCALL")
    assert syscall["process"]["executable"] == "/usr/bin/node_exporter"
    assert syscall["process"]["start_ticks"] == 8000 and syscall["process"]["pid"] == 80
    assert syscall["process"]["identity_basis"] == "lifecycle_record"
    assert "PRIVATE-" not in serialized
    assert all("process" not in row for row in projected if row["record_type"] == "EOE")
