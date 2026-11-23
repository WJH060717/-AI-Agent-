import asyncio

import httpx

from apps.api.main import create_app
from tests.integration.d6_helpers import ModelStub, pending


def test_agent_api_status_actions_transitions_roles_and_budget_schema(context):
    settings, _, service, _, tokens = context
    with ModelStub() as stub:
        stub.configure(settings)
        actor, _, run = pending(context)
        service.process_one()

    async def scenario():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_app(settings)), base_url="http://test"
        ) as client:
            analyst = {"Authorization": f"Bearer {tokens['analyst']}"}
            viewer = {"Authorization": f"Bearer {tokens['viewer']}"}
            base = f"/api/v1/investigations/{run['run_id']}"
            state = (await client.get(base, headers=viewer)).json()
            assert state["phase"] == "completed" and state["budget_used"]["tool_calls"] == 2
            first = await client.get(base + "/tool-calls", headers=analyst, params={"limit": 1})
            assert first.status_code == 200, first.text
            page = first.json()
            assert page["next_cursor"] and page["items"][0]["seq"] == 1
            next_page = (
                await client.get(
                    base + "/tool-calls",
                    headers=analyst,
                    params={"cursor": page["next_cursor"], "limit": 1},
                )
            ).json()
            assert next_page["items"][0]["seq"] == 2
            assert (await client.get(base + "/tool-calls", headers=viewer)).status_code == 403
            history = (await client.get(base + "/transitions", headers=viewer)).json()
            assert {item["phase"] for item in history["items"]}.issuperset(
                {
                    "queued",
                    "preparing",
                    "planning",
                    "querying",
                    "checking",
                    "drafting",
                    "validating",
                    "completed",
                }
            )
            _, other = service.init_workspace("other")
            assert (
                await client.get(
                    base + "/tool-calls", headers={"Authorization": f"Bearer {other['admin']}"}
                )
            ).status_code == 404
            from packages.storage.analysis import AnalysisService

            incident_id = AnalysisService(service).get_incident(
                actor,
                AnalysisService(service).get_report(actor, state["report_id"])["provenance"][
                    "incident_id"
                ],
            )["id"]
            response = await client.post(
                f"/api/v1/incidents/{incident_id}/investigations",
                headers=analyst | {"Idempotency-Key": "oversize"},
                json={"mode": "live", "budget": {"max_tool_calls": 7}},
            )
            assert response.status_code == 422

    asyncio.run(scenario())
