import asyncio

import httpx

from apps.api.main import create_app


def test_runtime_config_is_admin_only_and_never_exports_credentials_or_paths(context):
    settings, _, _, _, tokens = context

    async def scenario():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_app(settings)), base_url="http://test"
        ) as client:
            for role, code in [("viewer", 403), ("analyst", 403), ("admin", 200)]:
                result = await client.get(
                    "/api/v1/runtime-config", headers={"Authorization": f"Bearer {tokens[role]}"}
                )
                assert result.status_code == code
                if code == 200:
                    assert result.json()["currency"] == "USD"
                    assert result.json()["model_provider"] == "disabled"
                    assert result.json()["agent_max_cost_microusd"] == 0
                    for private in [
                        "database_url",
                        "model_api_key",
                        "model_base_url",
                        "raw_store",
                        "staging_store",
                        tokens["admin"],
                    ]:
                        assert private not in result.text

    asyncio.run(scenario())
