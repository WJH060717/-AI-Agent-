import asyncio
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import select

from apps.api.main import create_app
from packages.storage import schema_v6 as t
from packages.storage.queue import LeaseLost, Queue
from packages.storage.service import DomainError
from tests.integration.test_d5_paging import add_auth, grouped_setup


def setup_replay(context, rate=1000):
    from packages.contracts.replay import ReplayCreate
    from packages.storage.replay import ReplayService

    _, _, service, _, _ = context
    actor, dataset = grouped_setup(context)
    replay = ReplayService(service)
    request = ReplayCreate(source_session_id=dataset["default_session_id"], rate_eps=rate)
    created = replay.create(actor, dataset["dataset_id"], request, "replay")
    return actor, dataset, replay, request, created


def test_replay_rate_fixed_highwater_resume_and_immutable_events(context):
    from packages.storage.analysis import AnalysisService
    from packages.storage.replay import ReplayRunner

    settings, db, service, _, _ = context
    actor, dataset, api, request, created = setup_replay(context, rate=10)
    incidents = AnalysisService(service)
    assert (
        "REPLAY_DETECTION_PENDING"
        in incidents.incident_page(actor, dataset["dataset_id"], created["session_id"])["warnings"]
    )
    with db.engine.connect() as conn:
        before = list(
            conn.execute(select(t.events).where(t.events.c.workspace_id == actor.workspace_id))
        )
    assert api.create(actor, dataset["dataset_id"], request, "replay") == created
    assert len(service.dataset_page(actor)["items"]) == 1
    queue = Queue(db, settings)
    first = queue.claim("first")
    clock = [datetime.now(UTC)]
    runner = ReplayRunner(service, queue, clock=lambda: clock[0])
    assert runner.step(first) > 0
    clock[0] += timedelta(seconds=0.5)
    assert runner.step(first) == 0
    state = api.status(actor, created["job_id"])
    assert state["published_events"] == 5 and state["detection_status"] == "pending"
    assert (
        "REPLAY_DETECTION_PENDING"
        in incidents.incident_page(actor, dataset["dataset_id"], created["session_id"])["warnings"]
    )
    assert (
        service.overview(actor, dataset["dataset_id"], created["session_id"])["detection_status"]
        == "pending"
    )
    # Separate later publication must not enter the frozen replay source.
    add_auth(service, actor, dataset)
    service.process_one()
    page = service.list_events(actor, dataset["dataset_id"], created["session_id"], 2)
    with db.engine.begin() as conn:
        conn.execute(
            t.jobs.update()
            .where(t.jobs.c.id == first.job_id)
            .values(lease_until="2000-01-01T00:00:00+00:00")
        )
    second = queue.claim("recovered")
    with pytest.raises(LeaseLost):
        runner.step(first)
    clock[0] += timedelta(seconds=10)
    while runner.step(second) is not None:
        pass
    state = api.status(actor, created["job_id"])
    assert state["state"] == "completed"
    assert (
        "REPLAY_DETECTION_PENDING"
        not in incidents.incident_page(actor, dataset["dataset_id"], created["session_id"])[
            "warnings"
        ]
    )
    assert state["published_events"] == state["total_events"] == len(before)
    seen = page["items"]
    while page["next_cursor"]:
        page = service.list_events(
            actor, dataset["dataset_id"], created["session_id"], 2, page["next_cursor"]
        )
        seen += page["items"]
    assert len(seen) == 5  # paginator retains its own earlier target watermark
    with db.engine.connect() as conn:
        after = list(
            conn.execute(
                select(t.events).where(
                    t.events.c.workspace_id == actor.workspace_id,
                    t.events.c.event_id.in_([r.event_id for r in before]),
                )
            )
        )
    assert sorted(before) == sorted(after)
    assert (
        service.overview(actor, dataset["dataset_id"], created["session_id"])["input_mode"]
        == "replay"
    )


def test_replay_partial_detection_and_cancel_fences(context):
    from packages.storage.replay import ReplayRunner

    settings, db, service, _, _ = context
    actor, dataset, api, request, created = setup_replay(context)
    settings.detection_event_limit = 1
    queue = Queue(db, settings)
    lease = queue.claim("partial")
    moment = [datetime.now(UTC)]
    runner = ReplayRunner(service, queue, clock=lambda: moment[0])
    runner.step(lease)
    moment[0] += timedelta(seconds=10)
    assert runner.step(lease) is None
    status = api.status(actor, created["job_id"])
    assert status["state"] == "partial" and status["detection_status"] == "partial"
    assert status["warnings"] == ["RULE_SCOPE_TOO_LARGE"]
    another = api.create(actor, dataset["dataset_id"], request, "cancel")
    lease = queue.claim("cancel")
    queue.cancel(actor, another["job_id"])
    with pytest.raises(LeaseLost):
        runner.step(lease)
    assert api.status(actor, another["job_id"])["state"] == "cancelled"
    assert (
        service.overview(actor, dataset["dataset_id"], another["session_id"])["detection_status"]
        == "partial"
    )


def test_replay_invalid_scope_limit_and_idempotency(context):
    from packages.contracts.replay import ReplayCreate

    settings, _, service, _, tokens = context
    actor, dataset, api, request, created = setup_replay(context)
    with pytest.raises(DomainError, match="IDEMPOTENCY"):
        api.create(
            actor, dataset["dataset_id"], request.model_copy(update={"rate_eps": 1}), "replay"
        )
    with pytest.raises(DomainError, match="FORBIDDEN"):
        api.create(service.authenticate(tokens["viewer"]), dataset["dataset_id"], request, "viewer")
    other, _ = service.init_workspace("other")
    with pytest.raises(DomainError, match="NOT_FOUND"):
        api.status(service.system_actor(other), created["job_id"])
    with pytest.raises(DomainError, match="REPLAY_SOURCE_MODE"):
        api.create(
            actor,
            dataset["dataset_id"],
            ReplayCreate(source_session_id=created["session_id"]),
            "nested",
        )
    settings.replay_event_limit = 1
    with pytest.raises(DomainError, match="REPLAY_SCOPE_TOO_LARGE"):
        api.create(actor, dataset["dataset_id"], request, "large")


def test_replay_http_contract_and_analyst_ownership(context):
    from packages.contracts.replay import ReplayStatus

    settings, _, service, _, tokens = context
    actor, dataset = grouped_setup(context)
    app = create_app(settings)

    async def exercise():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            route = f"/api/v1/datasets/{dataset['dataset_id']}/replays"
            body = {"source_session_id": dataset["default_session_id"], "rate_eps": 1000}
            headers = {"Authorization": f"Bearer {tokens['analyst']}", "Idempotency-Key": "http"}
            result = await client.post(route, json=body, headers=headers)
            assert result.status_code == 202, result.text
            value = ReplayStatus.model_validate(result.json())
            assert value.input_mode == "replay"
            bad = await client.post(route, json=body | {"rate_eps": True}, headers=headers)
            assert bad.status_code == 422
            bad = await client.post(
                route, json=body, headers=headers | {"Authorization": f"Bearer {tokens['viewer']}"}
            )
            assert bad.status_code == 403
            read = await client.get(f"/api/v1/replays/{value.job_id}", headers=headers)
            assert read.status_code == 200
            cancelled = await client.post(f"/api/v1/jobs/{value.job_id}/cancel", headers=headers)
            assert cancelled.status_code == 202
            # The same analyst cannot cancel an admin-created replay.
            admin = await client.post(
                route,
                json=body,
                headers=headers
                | {"Authorization": f"Bearer {tokens['admin']}", "Idempotency-Key": "admin"},
            )
            denied = await client.post(
                f"/api/v1/jobs/{admin.json()['job_id']}/cancel", headers=headers
            )
            assert denied.status_code == 403
            missing = await client.get(f"/api/v1/replays/{uuid4()}", headers=headers)
            assert missing.status_code == 404

    asyncio.run(exercise())
