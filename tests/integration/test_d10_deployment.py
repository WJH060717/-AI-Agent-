import asyncio
from pathlib import Path

import httpx
import pytest

from apps.api.main import create_app
from packages.config import Settings


def web_files(folder: Path) -> Path:
    dist = folder / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text('<html><script src="/assets/app.js"></script></html>')
    (dist / "assets/app.js").write_text("window.demoLoaded = true;")
    (dist / ".env").write_text("PRIVATE_SECRET=must-not-be-served")
    (folder / "private.txt").write_text("private-bytes")
    return dist


def test_production_web_serves_only_entry_and_assets_with_api_auth_preserved(context, tmp_path):
    settings, _, _, _, _ = context
    settings.web_dist = web_files(tmp_path)

    async def scenario():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_app(settings)), base_url="http://test"
        ) as client:
            entry = await client.get("/")
            assert entry.status_code == 200 and "/assets/app.js" in entry.text
            assert entry.headers["x-content-type-options"] == "nosniff"
            assert (await client.get("/assets/app.js")).status_code == 200
            for path in (
                "/.env",
                "/private.txt",
                "/assets/%2e%2e/private.txt",
                "/packages/config.py",
            ):
                response = await client.get(path)
                assert response.status_code == 404 and "private-bytes" not in response.text
            assert (await client.get("/api/v1/datasets")).status_code == 401
            assert (await client.get("/api/v1/no-such-route")).status_code == 404
            assert (await client.get("/api/v1/health/live")).json()["stage"] == "d12"

    asyncio.run(scenario())


def test_missing_web_build_rejects_startup(tmp_path):
    settings = Settings(_env_file=None, web_dist=tmp_path / "absent")
    with pytest.raises(ValueError, match="WEB_BUILD_UNAVAILABLE"):
        create_app(settings)


def test_preflight_is_read_only_and_redacts_configuration(context, tmp_path):
    from scripts.preflight import preflight

    settings, db, _, _, _ = context
    settings.web_dist = web_files(tmp_path)
    settings.raw_store.mkdir()
    settings.staging_store.mkdir()
    with db.engine.connect() as conn:
        before = set(conn.exec_driver_sql("SELECT id FROM workspaces").scalars())
    result = preflight(settings)
    assert result["ready"] is True and result["migration_head"] == "0006_d9"
    assert result["model_status"] == "disabled"
    assert result["worker_status"] == "not_verified"
    assert str(settings.raw_store) not in str(result)
    assert settings.database_url.get_secret_value() not in str(result)
    assert list(settings.raw_store.iterdir()) == []
    with db.engine.connect() as conn:
        assert set(conn.exec_driver_sql("SELECT id FROM workspaces").scalars()) == before


def test_preflight_missing_database_does_not_create_it(tmp_path):
    from scripts.preflight import preflight

    path = tmp_path / "absent.db"
    settings = Settings(_env_file=None, database_url=f"sqlite:///{path}")
    result = preflight(settings)
    assert result["ready"] is False and "DATABASE_UNAVAILABLE" in result["errors"]
    assert not path.exists()
