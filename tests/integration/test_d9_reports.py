import asyncio

import httpx
import pytest
from sqlalchemy import select

from apps.api.main import create_app
from packages.storage import schema_v5 as t
from packages.storage.analysis import AnalysisService
from tests.integration.d6_helpers import pending


@pytest.fixture
def published(context):
    settings, db, service, _, tokens = context
    actor, dataset, run = pending(context, mode="deterministic")
    service.process_one()
    report = AnalysisService(service).get_report(
        actor, AnalysisService(service).get_run(actor, run["run_id"])["report_id"]
    )
    return settings, db, service, actor, tokens, report


def test_review_is_append_only_idempotent_scoped_and_exported_safely(published):
    settings, db, service, actor, tokens, report = published
    _, foreign = service.init_workspace("other")

    async def scenario():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_app(settings)), base_url="http://test"
        ) as client:
            base = f"/api/v1/reports/{report['report_id']}"
            headers = {
                "Authorization": f"Bearer {tokens['analyst']}",
                "Idempotency-Key": "review-1",
            }
            body = {
                "claim_id": report["claims"][0]["claim_id"],
                "decision": "needs_more_evidence",
                "comment": '<img src=x onerror="alert(1)">',
            }
            response = await client.post(base + "/reviews", headers=headers, json=body)
            assert response.status_code == 201, response.text
            first = response.json()
            assert first["actor_id"] and first["created_at"]
            assert (
                await client.post(base + "/reviews", headers=headers, json=body)
            ).json() == first
            assert (
                await client.post(
                    base + "/reviews", headers=headers, json=body | {"decision": "accepted"}
                )
            ).status_code == 409
            assert (
                await client.post(
                    base + "/reviews",
                    headers=headers | {"Idempotency-Key": "bad"},
                    json=body | {"claim_id": "not-a-claim"},
                )
            ).status_code == 422
            for token, expected in [(tokens["viewer"], 403), (foreign["analyst"], 404)]:
                h = {"Authorization": f"Bearer {token}", "Idempotency-Key": "forbidden"}
                assert (
                    await client.post(base + "/reviews", headers=h, json=body)
                ).status_code == expected
                assert (
                    await client.get(base + "/export?format=json", headers=h)
                ).status_code == expected
            listing = await client.get(base + "/reviews", headers=headers)
            assert listing.status_code == 200
            assert listing.json()["items"] == [first]
            exported = await client.get(base + "/export?format=json", headers=headers)
            assert exported.status_code == 200, exported.text
            bundle = exported.json()
            from packages.contracts.reports import ReportExport

            ReportExport.model_validate(bundle)
            assert bundle["report"] == report and bundle["reviews"] == [first]
            assert {e["event_id"] for e in bundle["evidence"]} == set(report["timeline"])
            assert all(
                e["verified"] and e["redacted"] and not e["next_cursor"] for e in bundle["evidence"]
            )
            assert "attachment" in exported.headers["content-disposition"]
            html = await client.get(base + "/export?format=html", headers=headers)
            assert html.status_code == 200 and "&lt;img" in html.text
            assert "<img src=x" not in html.text and "<script" not in html.text
            assert "default-src 'none'" in html.headers["content-security-policy"]
            assert report["generated_at"] in html.text
            assert (
                await client.get(base + "/export?format=pdf", headers=headers)
            ).status_code == 422
            assert (await client.get(base, headers=headers)).json() == report

    asyncio.run(scenario())
    with db.engine.connect() as conn:
        assert service._get(conn, t.reports, actor, report["report_id"])["payload"] == report
        actions = (
            conn.execute(
                select(t.audit.c.action).where(t.audit.c.workspace_id == actor.workspace_id)
            )
            .scalars()
            .all()
        )
    assert actions.count("report.review") == 1
    assert actions.count("report.export") == 2
    assert "report.export.denied" in actions


def test_raw_download_checks_role_workspace_path_and_integrity(published):
    settings, db, service, actor, tokens, report = published
    ref = report["claims"][0]["evidence_refs"][0]["fragments"][0]
    with db.engine.connect() as conn:
        obj = service._get(conn, t.objects, actor, ref["object_id"])
    path = settings.raw_store / obj["storage_key"]
    raw = path.read_bytes()
    _, foreign = service.init_workspace("other")

    async def scenario():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_app(settings)), base_url="http://test"
        ) as client:
            url = f"/api/v1/raw-objects/{ref['object_id']}/download"
            for token, expected in [
                (tokens["viewer"], 403),
                (foreign["analyst"], 404),
                (tokens["analyst"], 200),
            ]:
                response = await client.get(url, headers={"Authorization": f"Bearer {token}"})
                assert response.status_code == expected, response.text
                if expected == 200:
                    assert response.content == raw
            path.write_bytes(raw + b"corrupt")
            try:
                h = {"Authorization": f"Bearer {tokens['admin']}"}
                assert (await client.get(url, headers=h)).status_code == 409
                assert (
                    await client.get(
                        f"/api/v1/reports/{report['report_id']}/export?format=json", headers=h
                    )
                ).status_code == 409
            finally:
                path.write_bytes(raw)

    asyncio.run(scenario())
    with db.engine.connect() as conn:
        actions = (
            conn.execute(
                select(t.audit.c.action).where(t.audit.c.workspace_id == actor.workspace_id)
            )
            .scalars()
            .all()
        )
    assert "raw.download" in actions and "raw.download.denied" in actions


def test_review_and_report_pages_keep_watermark_and_actor_binding(published):
    settings, _, service, actor, tokens, report = published

    async def scenario():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_app(settings)), base_url="http://test"
        ) as client:
            h = {"Authorization": f"Bearer {tokens['analyst']}"}
            base = f"/api/v1/reports/{report['report_id']}/reviews"
            for index in range(2):
                r = await client.post(
                    base,
                    headers=h | {"Idempotency-Key": str(index)},
                    json={
                        "claim_id": "identity-unknown",
                        "decision": "rejected",
                        "comment": str(index),
                    },
                )
                assert r.status_code == 201
            page = (await client.get(base + "?limit=1", headers=h)).json()
            await client.post(
                base,
                headers=h | {"Idempotency-Key": "later"},
                json={"claim_id": "identity-unknown", "decision": "accepted", "comment": "later"},
            )
            next_page = await client.get(
                base, params={"cursor": page["next_cursor"], "limit": 1}, headers=h
            )
            assert next_page.status_code == 200 and next_page.json()["next_cursor"] is None
            assert next_page.json()["items"][0]["comment"] == "1"
            assert (
                await client.get(
                    base,
                    params={"cursor": page["next_cursor"]},
                    headers={"Authorization": f"Bearer {tokens['admin']}"},
                )
            ).status_code == 422
            incident = report["provenance"]["incident_id"]
            history = await client.get(f"/api/v1/incidents/{incident}/reports", headers=h)
            assert (
                history.status_code == 200
                and history.json()["items"][0]["report_id"] == report["report_id"]
            )

    asyncio.run(scenario())


def test_concurrent_review_retries_publish_once(published):
    from concurrent.futures import ThreadPoolExecutor

    from packages.contracts.reports import ReviewCreate
    from packages.storage.reports import ReportService

    _, _, service, actor, _, report = published
    payload = ReviewCreate(
        claim_id="identity-unknown", decision="needs_more_evidence", comment="still unknown"
    )
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(
            pool.map(
                lambda _: ReportService(service).review(
                    actor, report["report_id"], payload, "concurrent"
                ),
                range(4),
            )
        )
    assert len({r["review_id"] for r in results}) == 1
    assert len(ReportService(service).reviews(actor, report["report_id"])["items"]) == 1


def test_export_limits_and_raw_storage_path_cannot_escape(published, tmp_path):
    from packages.storage.reports import ReportService
    from packages.storage.service import DomainError

    settings, db, service, actor, _, report = published
    settings.report_export_max_lines = 1
    with pytest.raises(DomainError, match="EXPORT_EVIDENCE_LIMIT_EXCEEDED"):
        ReportService(service).export(actor, report["report_id"], "json")
    # The app DB role cannot mutate raw objects on PG; use the disposable SQLite fixture only.
    if db.engine.dialect.name != "sqlite":
        return
    outside = tmp_path / "outside.jsonl"
    outside.write_text("private", encoding="utf-8")
    object_id = report["claims"][0]["evidence_refs"][0]["fragments"][0]["object_id"]
    with db.engine.begin() as conn:
        conn.execute(
            t.objects.update()
            .where(t.objects.c.workspace_id == actor.workspace_id, t.objects.c.id == object_id)
            .values(storage_key=str(outside))
        )
    with pytest.raises(DomainError, match="EVIDENCE_UNAVAILABLE"):
        ReportService(service).raw_download(actor, object_id)


@pytest.mark.parametrize("mapping", ["absolute", "parent", "symlink"])
@pytest.mark.parametrize("operation", ["cached", "export", "evidence"])
def test_shared_evidence_reads_reject_outside_archive_even_with_matching_hash(
    published, tmp_path, monkeypatch, mapping, operation
):
    import os

    from packages.storage.reports import ReportService
    from packages.storage.service import DomainError

    settings, db, service, actor, _, report = published
    ref = report["claims"][0]["evidence_refs"][0]
    object_id = ref["fragments"][0]["object_id"]
    with db.engine.connect() as conn:
        obj = service._get(conn, t.objects, actor, object_id)
    outside = tmp_path / "outside.jsonl"
    outside.write_bytes((settings.raw_store / obj["storage_key"]).read_bytes())
    storage_key = str(outside)
    if mapping == "parent":
        storage_key = os.path.relpath(outside, settings.raw_store)
    elif mapping == "symlink":
        link = settings.raw_store / "outside-link.jsonl"
        try:
            link.symlink_to(outside)
        except OSError:
            if os.name != "nt":
                raise
            # Windows directory junctions test resolution without symlink privileges.
            import subprocess

            directory_link = settings.raw_store / "outside-junction"
            subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(directory_link), str(outside.parent)],
                check=True,
                capture_output=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            storage_key = str(directory_link.relative_to(settings.raw_store) / outside.name)
        else:
            storage_key = link.name
    original_get = service._get

    def mapped_get(conn, table, identity, item_id):
        row = original_get(conn, table, identity, item_id)
        return (
            dict(row) | {"storage_key": storage_key}
            if table.name == "raw_objects" and item_id == object_id
            else row
        )

    monkeypatch.setattr(service, "_get", mapped_get)
    with pytest.raises(DomainError, match="EVIDENCE_UNAVAILABLE"):
        if operation == "cached":
            ReportService(service).cached(actor, report["report_id"])
        elif operation == "export":
            ReportService(service).export(actor, report["report_id"], "json")
        else:
            AnalysisService(service).evidence(actor, ref["event_id"], report["snapshot_id"])


def test_history_existing_frozen_cursor_survives_new_report_above_initial_limit(published):
    from uuid import uuid4

    from packages.storage.reports import ReportService

    _, db, service, actor, _, report = published
    initial_ids = {report["report_id"]}

    def add(version):
        report_id = str(uuid4())
        with db.engine.begin() as conn:
            conn.execute(
                t.reports.insert().values(
                    workspace_id=actor.workspace_id,
                    id=report_id,
                    run_id=report["run_id"],
                    version=version,
                    payload=report | {"report_id": report_id},
                )
            )
        return report_id

    for version in range(2, 51):
        initial_ids.add(add(version))
    reports = ReportService(service)
    first = reports.history(actor, report["provenance"]["incident_id"], limit=1)
    added = add(51)
    rest = reports.history(
        actor, report["provenance"]["incident_id"], limit=100, cursor=first["next_cursor"]
    )
    actual = {r["report_id"] for r in first["items"] + rest["items"]}
    assert actual == initial_ids and added not in actual and rest["next_cursor"] is None
