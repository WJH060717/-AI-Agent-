import asyncio

import httpx
import pytest

from apps.api.main import create_app
from packages.storage.analysis import AnalysisService
from packages.storage.service import DomainError
from tests.integration.d4_helpers import audit_record, raw_lines
from tests.integration.test_d5_paging import add_auth, grouped_setup


def investigated(context):
    _, _, service, _, _ = context
    actor, dataset = grouped_setup(context)
    add_auth(service, actor, dataset)
    records = []
    for pid, ppid, ticks, parent_ticks, second in ((10, 1, 50, 1, 30), (42, 10, 100, 50, 40)):
        call = audit_record("SYSCALL", str(pid), timestamp=f"2026-11-14T01:00:{second}Z")
        call["process"].update(
            pid=pid, ppid=ppid, start_ticks=ticks, parent_start_ticks=parent_ticks, action="create"
        )
        records += [call, audit_record("EOE", str(pid), timestamp=call["timestamp"])]
    service.stage_bytes(
        actor, dataset["dataset_id"], "linux_audit", "audit-a", "UTC", raw_lines(records), "audit"
    )
    service.process_one()
    analysis = AnalysisService(service)
    incident = analysis.list_incidents(actor, dataset["dataset_id"], dataset["default_session_id"])[
        0
    ]
    run = analysis.create_run(actor, incident["id"], "investigate")
    service.process_one()
    return actor, dataset, run


def test_aggregate_investigation_reproduces_all_findings_and_freezes_paths(context):
    _, _, service, _, _ = context
    actor, dataset, run = investigated(context)
    analysis = AnalysisService(service)
    state = analysis.get_run(actor, run["run_id"])
    assert state["state"] == "completed"
    report = analysis.get_report(actor, state["report_id"])
    assert len(report["provenance"]["finding_ids"].split(",")) == 2
    assert {
        c["fact_predicate"]["values"]["rule_id"]
        for c in report["claims"]
        if (c.get("fact_predicate") or {}).get("name") == "rule_triggered"
    } == {"R01", "R02"}
    paths = analysis.get_paths(actor, run["run_id"])
    assert paths == report["path_analysis"] and paths["paths"]
    assert len(paths["paths"][0]["edge_ids"]) == 3
    [assessment] = report["behavior_assessments"]
    assert assessment["behavior"] == "brute_force_suspected"
    assert assessment["trace_status"] == "successful"
    assert "发起侧溯源未成功" in assessment["trace_reason"]
    assert len(assessment["trace_evidence_refs"]) == 3
    before = report
    service.stage_bytes(
        actor,
        dataset["dataset_id"],
        "linux_auth",
        "auth-a",
        "UTC",
        raw_lines([{"bad": "record"}]),
        "bad",
    )
    service.process_one()
    assert analysis.get_report(actor, state["report_id"]) == before
    from sqlalchemy import select

    from packages.storage import schema_v4 as t

    object_id = service.get_event(actor, report["timeline"][0])["source_locators"][0]["object_id"]
    with service.db.engine.connect() as conn:
        obj = (
            conn.execute(
                select(t.objects).where(
                    t.objects.c.workspace_id == actor.workspace_id, t.objects.c.id == object_id
                )
            )
            .mappings()
            .first()
        )
    path = service.settings.raw_store / obj["storage_key"]
    path.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(DomainError, match="EVIDENCE_UNVERIFIABLE"):
        analysis.get_paths(actor, run["run_id"])
    assert analysis.get_report(actor, state["report_id"])["validation"] == "partial"
    with service.db.engine.connect() as conn:
        stored = conn.execute(
            select(t.reports.c.payload).where(
                t.reports.c.workspace_id == actor.workspace_id, t.reports.c.id == state["report_id"]
            )
        ).scalar_one()
    assert stored == before


def test_snapshot_timeline_graph_focus_pages_and_paths_are_scoped(context):
    settings, _, service, _, tokens = context
    actor, dataset, run = investigated(context)
    analysis = AnalysisService(service)

    async def scenario():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_app(settings)), base_url="http://test"
        ) as client:
            headers = {"Authorization": f"Bearer {tokens['viewer']}"}
            base = f"/api/v1/investigations/{run['run_id']}"
            timeline = []
            cursor = None
            while True:
                response = await client.get(
                    base + "/timeline",
                    headers=headers,
                    params={"limit": 7, **({"cursor": cursor} if cursor else {})},
                )
                assert response.status_code == 200, response.text
                page = response.json()
                timeline += page["items"]
                cursor = page["next_cursor"]
                if not cursor:
                    break
            assert len(timeline) == 32 and len({e["event_id"] for e in timeline}) == 32
            assert [(e["event_time"], e["event_id"]) for e in timeline] == sorted(
                (e["event_time"], e["event_id"]) for e in timeline
            )
            full = analysis.get_graph(actor, run["run_id"])
            first = (await client.get(base + "/graph", headers=headers, params={"limit": 5})).json()
            edges = first["edges"][:]
            cursor = first["next_cursor"]
            while cursor:
                page = (
                    await client.get(
                        base + "/graph", headers=headers, params={"limit": 5, "cursor": cursor}
                    )
                ).json()
                edges += page["edges"]
                cursor = page["next_cursor"]
            assert {e["edge_id"] for e in edges} == {e["edge_id"] for e in full["edges"]}
            assert len(edges) == len(full["edges"])
            focus = full["edges"][0]["source"]
            page = (
                await client.get(base + "/graph", headers=headers, params={"focus_entity": focus})
            ).json()
            assert all(focus in (e["source"], e["target"]) for e in page["edges"])
            assert (
                await client.get(
                    base + "/timeline", headers=headers, params={"cursor": first["next_cursor"]}
                )
            ).status_code == 422
            assert (
                await client.get(
                    base + "/graph", headers=headers, params={"focus_entity": "missing"}
                )
            ).status_code == 404
            assert (await client.get(base + "/paths", headers=headers)).json()["paths"]
            _, other = service.init_workspace("other")
            for suffix in ("/paths", "/timeline", "/graph"):
                assert (
                    await client.get(
                        base + suffix, headers={"Authorization": f"Bearer {other['admin']}"}
                    )
                ).status_code == 404
            assert (
                await client.get(
                    "/api/v1/incidents",
                    headers=headers,
                    params={
                        "dataset_id": dataset["dataset_id"],
                        "session_id": dataset["default_session_id"],
                        "limit": 101,
                    },
                )
            ).status_code == 422

    asyncio.run(scenario())
