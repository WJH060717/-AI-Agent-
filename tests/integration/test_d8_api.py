import asyncio
from concurrent.futures import ThreadPoolExecutor

import httpx

from apps.api.main import create_app


def test_rate_limits_isolate_roles_methods_and_workspaces_and_do_not_write(context):
    settings, _, service, _, tokens = context
    settings.api_read_requests_per_minute = 2
    settings.api_write_requests_per_minute = 1
    _, other = service.init_workspace("other")

    async def scenario():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_app(settings)), base_url="http://test"
        ) as client:
            admin = {"Authorization": f"Bearer {tokens['admin']}"}
            viewer = {"Authorization": f"Bearer {tokens['viewer']}"}
            responses = await asyncio.gather(
                *[client.get("/api/v1/datasets", headers=admin) for _ in range(6)]
            )
            assert sorted(r.status_code for r in responses) == [200, 200, 429, 429, 429, 429]
            rejected = next(r for r in responses if r.status_code == 429)
            assert 1 <= int(rejected.headers["Retry-After"]) <= 60
            assert rejected.json()["error"]["code"] == "RATE_LIMITED"
            assert rejected.headers["X-Request-ID"] == rejected.json()["error"]["request_id"]
            assert (await client.get("/api/v1/datasets", headers=viewer)).status_code == 200
            assert (
                await client.get(
                    "/api/v1/datasets", headers={"Authorization": f"Bearer {other['admin']}"}
                )
            ).status_code == 200
            for index, expected in enumerate([201, 429]):
                response = await client.post(
                    "/api/v1/datasets",
                    headers=admin | {"Idempotency-Key": f"rate-{index}"},
                    json={"name": f"rate-{index}", "provenance_type": "synthetic"},
                )
                assert response.status_code == expected
            listing = (await client.get("/api/v1/datasets", headers=viewer)).json()["items"]
            assert len(listing) == 1 and listing[0]["name"] == "rate-0"
            assert (await client.get("/api/v1/health/live")).status_code == 200

    asyncio.run(scenario())


def test_limit_window_expires_and_does_not_evict_active_quota():
    from apps.api.limits import RequestLimiter

    limiter = RequestLimiter(read_limit=2, write_limit=1, max_identities=2)
    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(lambda _: limiter.check("actor-a", "read", at=1), range(8)))
    assert outcomes.count(0) == 2 and outcomes.count(60) == 6
    assert limiter.check("actor-b", "read", at=1) == 0
    assert limiter.check("actor-c", "read", at=2) == 59
    assert limiter.check("actor-a", "read", at=2) == 59
    assert limiter.check("actor-c", "read", at=61) == 0
    assert limiter.check("actor-a", "read", at=61) == 0


def test_errors_have_safe_body_and_matching_request_header(context):
    settings, _, _, _, tokens = context
    app = create_app(settings)

    @app.get("/private-failure")
    def explode():
        raise RuntimeError("PRIVATE_PATH_AND_KEY")

    async def scenario():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
            base_url="http://test",
        ) as client:
            cases = [
                await client.get("/api/v1/datasets"),
                await client.get("/missing"),
                await client.get(
                    "/api/v1/events", headers={"Authorization": f"Bearer {tokens['viewer']}"}
                ),
                await client.get("/api/v1/health/live", headers={"Content-Length": "999999999"}),
                await client.get("/private-failure"),
                await client.get("/api/v1/health/live", headers={"Content-Length": "9" * 5000}),
            ]
            assert [r.status_code for r in cases] == [401, 404, 422, 413, 500, 413]
            for response in cases:
                value = response.json()["error"]
                assert set(value) == {"code", "message", "request_id", "details"}
                assert value["request_id"] == response.headers["X-Request-ID"]
                assert value["request_id"] != "unavailable"
                assert "PRIVATE" not in response.text

    asyncio.run(scenario())
