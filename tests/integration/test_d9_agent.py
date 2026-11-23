import asyncio
from decimal import Decimal

import httpx
from sqlalchemy import select

from apps.api.main import create_app
from packages.agent.runtime import AgentRuntime
from packages.storage import schema_v5 as t
from packages.storage.analysis import AnalysisService
from packages.storage.queue import Queue
from tests.integration.d6_helpers import ModelStub, pending


def test_resumed_run_rejects_pipeline_drift_and_does_not_publish_fresh_cache(context, monkeypatch):
    from packages.agent import cache

    settings, db, service, _, _ = context
    with ModelStub() as stub:
        stub.configure(settings)
        actor, _, run = pending(context)
        queue = Queue(db, settings)
        lease = queue.claim("before-pipeline-change")
        runtime = AgentRuntime(service, queue, lease)
        runtime.step()
        runtime.step()
        monkeypatch.setattr(cache, "pipeline_version", lambda: "f" * 64)
        analysis = AnalysisService(service)
        analysis.process(lease, queue)
        state = analysis.get_run(actor, run["run_id"])
        assert state["stop_reason"] == "MODEL_CONFIGURATION_CHANGED"
        assert state["state"] == "partial" and not stub.requests
        report = analysis.get_report(actor, state["report_id"])
        assert "cache_key" not in report["provenance"]


def test_cost_budget_refuses_call_before_transport(context):
    settings, _, service, _, _ = context
    # Explicit test prices exercise the accounting; these are not provider quotes.
    with ModelStub() as stub:
        stub.configure(settings)
        settings.model_input_usd_per_million = Decimal("1")
        settings.model_output_usd_per_million = Decimal("2")
        settings.agent_max_cost_microusd = 1
        actor, _, run = pending(context)
        service.process_one()
        state = AnalysisService(service).get_run(actor, run["run_id"])
        assert state["stop_reason"] == "MODEL_COST_BUDGET_EXHAUSTED"
        assert state["state"] == "partial" and not stub.requests
        assert state["budget_used"]["cost_microusd"] == 0


def test_failed_call_and_resumed_reservation_keep_cost(context):
    settings, db, service, _, _ = context
    with ModelStub("invalid") as stub:
        stub.configure(settings)
        settings.model_input_usd_per_million = Decimal("1")
        settings.model_output_usd_per_million = Decimal("2")
        settings.agent_max_cost_microusd = 100000
        actor, _, run = pending(context)
        queue = Queue(db, settings)
        lease = queue.claim("d9-budget")
        runtime = AgentRuntime(service, queue, lease)
        runtime.step()
        runtime.step()
        runtime.step()
        charged = runtime.payload["used"]["cost_microusd"]
        assert charged > 0 and runtime.payload["used"]["actual_cost_microusd"] == 0
        outcome = AgentRuntime(service, queue, lease).run()
        assert outcome["used"]["cost_microusd"] == charged
        with db.engine.connect() as conn:
            action = conn.execute(
                select(t.agent_actions.c.usage).where(
                    t.agent_actions.c.run_id == run["run_id"], t.agent_actions.c.kind == "model"
                )
            ).scalar_one()
        assert action["cost_microusd"] == charged


def test_cached_view_requires_version_match_preserves_source_and_never_calls_model(context):
    settings, db, service, _, tokens = context
    actor, _, run = pending(context, mode="deterministic")
    service.process_one()
    analysis = AnalysisService(service)
    report_id = analysis.get_run(actor, run["run_id"])["report_id"]
    report = analysis.get_report(actor, report_id)

    async def scenario():
        app = create_app(settings)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            h = {"Authorization": f"Bearer {tokens['viewer']}"}
            cached = await client.get(f"/api/v1/reports/{report_id}?mode=cached", headers=h)
            assert cached.status_code == 200, cached.text
            value = cached.json()
            assert value["mode"] == "cached" and value["generated_at"] == report["generated_at"]
            assert value["provenance"]["source_mode"] == "deterministic_fallback"
            assert len(value["provenance"]["cache_key"]) == 64
            settings.model_name = "version-drift"
            stale = await client.get(f"/api/v1/reports/{report_id}?mode=cached", headers=h)
            assert (
                stale.status_code == 409 and stale.json()["error"]["code"] == "REPORT_CACHE_STALE"
            )
            original = await client.get(f"/api/v1/reports/{report_id}", headers=h)
            assert original.json() == report

    asyncio.run(scenario())
    with db.engine.connect() as conn:
        assert service._get(conn, t.reports, actor, report_id)["payload"] == report
        assert (
            conn.execute(
                select(t.agent_actions).where(t.agent_actions.c.run_id == run["run_id"])
            ).first()
            is None
        )
