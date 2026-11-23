import asyncio
from pathlib import Path

import httpx
import pytest
from sqlalchemy import inspect, select

from apps.api.main import create_app
from packages.storage import schema_v1 as t
from packages.storage.service import DomainError


def test_migration_repeat_and_no_plaintext_tokens(context):
    _, db, _, _, tokens = context
    db.migrate()
    assert "events" in inspect(db.engine).get_table_names()
    with db.engine.connect() as conn:
        stored = conn.execute(select(t.tokens.c.digest)).scalars().all()
    assert all(token not in stored for token in tokens.values())
    assert all(len(value) == 64 for value in stored)


def test_signed_pagination_and_scope(context):
    _, _, service, workspace, _ = context
    actor = service.system_actor(workspace)
    a = service.create_dataset(actor, {"name": "a", "provenance_type": "synthetic"}, "a")
    b = service.create_dataset(actor, {"name": "b", "provenance_type": "synthetic"}, "b")
    service.stage_bytes(
        actor,
        a["dataset_id"],
        "zeek",
        "s",
        "UTC",
        Path("data/fixtures/d1/zeek.jsonl").read_bytes(),
        "upload",
    )
    service.process_one()
    first = service.list_events(actor, a["dataset_id"], a["default_session_id"], 3)
    second = service.list_events(
        actor, a["dataset_id"], a["default_session_id"], 100, first["next_cursor"]
    )
    assert len(first["items"]) == 3 and len(second["items"]) == 5
    assert len({e["event_id"] for e in first["items"] + second["items"]}) == 8
    with pytest.raises(DomainError):
        service.list_events(actor, a["dataset_id"], b["default_session_id"], 10)
    with pytest.raises(DomainError):
        service.list_events(actor, a["dataset_id"], a["default_session_id"], 10, "invalid")
    with pytest.raises(DomainError):
        service.list_events(
            actor, b["dataset_id"], b["default_session_id"], 10, first["next_cursor"]
        )


def test_actual_chunked_upload_size_limit(context):
    settings, _, _, _, tokens = context
    settings.max_upload_mb = 1

    async def scenario():
        async def chunks():
            yield (
                b'--test\r\nContent-Disposition: form-data; name="file"; filename="x.jsonl"\r\n'
                b"Content-Type: application/octet-stream\r\n\r\n"
            )
            for _ in range(20):
                yield b"x" * 65536
            yield b"\r\n--test--\r\n"

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_app(settings)), base_url="http://test"
        ) as client:
            response = await client.post(
                "/api/v1/imports",
                content=chunks(),
                headers={
                    "Authorization": f"Bearer {tokens['admin']}",
                    "Content-Type": "multipart/form-data; boundary=test",
                },
            )
            assert response.status_code == 413

    asyncio.run(scenario())
