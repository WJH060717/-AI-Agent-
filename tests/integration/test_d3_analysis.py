import asyncio
import json
from datetime import UTC, datetime
from uuid import uuid4

import httpx

from apps.api.main import create_app
from packages.contracts.models import NormalizedEvent
from packages.detection.r01 import detect_scans
from packages.storage.analysis import AnalysisService


def scan_bytes(count=24, step=1, target="10.10.0.20"):
    start = datetime(2026, 11, 14, 1, tzinfo=UTC).timestamp()
    return b"".join(
        (
            json.dumps(
                {
                    "ts": start + i * step,
                    "uid": f"s{i}",
                    "id.orig_h": "192.0.2.10",
                    "id.orig_p": 42000 + i,
                    "id.resp_h": target,
                    "id.resp_p": i + 1,
                    "proto": "tcp",
                    "synthetic": True,
                }
            )
            + "\n"
        ).encode()
        for i in range(count)
    )


def test_first_rule_graph_report_and_snapshot_are_real_and_scoped(context):
    settings, _, service, workspace, tokens = context
    actor = service.system_actor(workspace)
    dataset = service.create_dataset(actor, {"name": "scan", "provenance_type": "synthetic"}, "d")
    service.stage_bytes(actor, dataset["dataset_id"], "zeek", "s", "UTC", scan_bytes(), "u")
    service.process_one()
    analysis = AnalysisService(service)
    incidents = analysis.list_incidents(actor, dataset["dataset_id"], dataset["default_session_id"])
    assert len(incidents) == 1
    incident = incidents[0]
    # Identical import does not multiply findings/incidents.
    service.stage_bytes(actor, dataset["dataset_id"], "zeek", "s", "UTC", scan_bytes(), "u2")
    service.process_one()
    assert (
        len(analysis.list_incidents(actor, dataset["dataset_id"], dataset["default_session_id"]))
        == 1
    )

    async def scenario():
        headers = {"Authorization": f"Bearer {tokens['analyst']}"}
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_app(settings)), base_url="http://test"
        ) as client:
            created = await client.post(
                f"/api/v1/incidents/{incident['id']}/investigations",
                headers=headers | {"Idempotency-Key": "run-1"},
                json={"mode": "auto"},
            )
            assert created.status_code == 202, created.text
            run = created.json()
            assert (
                await client.post(
                    f"/api/v1/incidents/{incident['id']}/investigations",
                    headers=headers | {"Idempotency-Key": "run-1"},
                    json={"mode": "auto"},
                )
            ).json() == run
            service.process_one()
            state = (
                await client.get(f"/api/v1/investigations/{run['run_id']}", headers=headers)
            ).json()
            assert state["state"] == "completed"
            report = (
                await client.get(f"/api/v1/reports/{state['report_id']}", headers=headers)
            ).json()
            assert report["mode"] == "deterministic_fallback"
            assert report["validation"] == "passed"
            assert len(report["timeline"]) == 24
            graph = (
                await client.get(f"/api/v1/investigations/{run['run_id']}/graph", headers=headers)
            ).json()
            assert len(graph["edges"]) == 24
            ref = report["claims"][0]["evidence_refs"][0]
            evidence = await client.get(
                f"/api/v1/evidence/{ref['event_id']}",
                headers=headers,
                params={"snapshot_id": run["snapshot_id"]},
            )
            assert evidence.status_code == 200, evidence.text
            assert evidence.json()["verified"] is True
            assert evidence.json()["fragments"][0]["lines"][0]["line"] >= 1
            _, other_tokens = service.init_workspace("other")
            assert (
                await client.get(
                    f"/api/v1/reports/{state['report_id']}",
                    headers={"Authorization": f"Bearer {other_tokens['admin']}"},
                )
            ).status_code == 404
            # New data cannot change the frozen timeline/report.
            service.stage_bytes(
                actor, dataset["dataset_id"], "zeek", "other", "UTC", scan_bytes(1), "later"
            )
            service.process_one()
            again = (
                await client.get(f"/api/v1/reports/{state['report_id']}", headers=headers)
            ).json()
            assert again == report
            newer = await client.post(
                f"/api/v1/incidents/{incident['id']}/investigations",
                headers=headers | {"Idempotency-Key": "run-2"},
                json={"mode": "auto"},
            )
            assert newer.status_code == 202
            service.process_one()
            newer_state = (
                await client.get(
                    f"/api/v1/investigations/{newer.json()['run_id']}", headers=headers
                )
            ).json()
            assert newer_state["state"] == "completed"
            new_report = (
                await client.get(f"/api/v1/reports/{newer_state['report_id']}", headers=headers)
            ).json()
            assert len(new_report["timeline"]) == 25

    asyncio.run(scenario())


def test_r01_threshold_and_normal_counterexamples(context):
    _, _, service, workspace, _ = context
    actor = service.system_actor(workspace)
    dataset = service.create_dataset(
        actor, {"name": "negative", "provenance_type": "synthetic"}, "d"
    )
    service.stage_bytes(actor, dataset["dataset_id"], "zeek", "s", "UTC", scan_bytes(19), "u")
    service.process_one()
    analysis = AnalysisService(service)
    assert (
        analysis.list_incidents(actor, dataset["dataset_id"], dataset["default_session_id"]) == []
    )
    events = [
        NormalizedEvent.model_validate(e)
        for e in service.list_events(
            actor, dataset["dataset_id"], dataset["default_session_id"], 100
        )["items"]
    ]
    assert detect_scans(events, str(uuid4())) == []
