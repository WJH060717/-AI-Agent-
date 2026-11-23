import asyncio

import httpx
import pytest
from pydantic import ValidationError

from apps.api.main import app
from packages.config import Settings


def test_liveness_is_minimal_and_business_routes_require_authentication():
    async def check():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/api/v1/health/live")
            assert response.status_code == 200
            assert response.json() == {"status": "ok", "stage": "d12"}
            assert (await client.get("/api/v1/events")).status_code == 401

    asyncio.run(check())


def test_enabled_model_requires_explicit_credentials():
    with pytest.raises(ValidationError):
        Settings(_env_file=None, model_provider="compatible", model_name="test")


def test_secrets_are_not_in_configuration_repr():
    settings = Settings(_env_file=None, model_api_key="do-not-print-me")
    assert "do-not-print-me" not in repr(settings)
