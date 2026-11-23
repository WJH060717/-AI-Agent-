from datetime import UTC, datetime
from uuid import UUID, uuid4, uuid5

import pytest
from sqlalchemy import select

from packages.config import Settings
from packages.contracts.models import InvestigationScope, Report
from packages.detection.r01 import detect_scans
from packages.ingest.parsers import ParseContext, parse_record
from packages.storage import schema_v3 as old
from packages.storage import schema_v4 as new
from packages.storage.analysis import AnalysisService
from packages.storage.database import Database
from packages.storage.service import DataService, DomainError, digest
from tests.integration.test_d3_analysis import scan_bytes


def test_upgrade_d4_keeps_real_events_report_snapshot_and_identity_key(tmp_path):
    settings = Settings(
        _env_file=None,
        app_env="test",
        database_url=f"sqlite:///{tmp_path / 'old.db'}",
        raw_store=tmp_path / "raw",
        staging_store=tmp_path / "staging",
    )
    db = Database(settings)
    db.migrate("0003_d4")
    workspace, dataset, session, obj, snap, run, job, report_id = [str(uuid4()) for _ in range(8)]
    content = scan_bytes()
    stamp = datetime.now(UTC).isoformat()
    ctx = ParseContext(workspace, dataset, obj, digest(content), "s", "zeek", "UTC")
    events = [parse_record(raw, i + 1, ctx) for i, raw in enumerate(content.splitlines())]
    finding = detect_scans(events, session)[0]
    incident = str(uuid5(UUID(workspace), finding["id"]))
    scope = InvestigationScope(
        workspace_id=workspace,
        dataset_id=dataset,
        session_id=session,
        snapshot_id=snap,
        start="2026-11-14T00:55:00Z",
        end="2026-11-14T01:05:00Z",
    )
    report = Report(
        report_id=report_id,
        run_id=run,
        snapshot_id=snap,
        mode="deterministic_fallback",
        generated_at=stamp,
        summary="Legacy migration fixture",
        claims=[],
        timeline=[e.event_id for e in events],
        provenance={"template_version": "1.1.0"},
        validation="passed",
    ).model_dump(mode="json", exclude={"path_analysis"})
    settings.raw_store.mkdir()
    (settings.raw_store / "legacy.jsonl").write_bytes(content)
    with db.engine.begin() as conn:
        conn.execute(old.workspaces.insert().values(id=workspace, name="legacy"))
        conn.execute(old.private_keys.insert().values(workspace_id=workspace, salt="b" * 64))
        conn.execute(
            old.datasets.insert().values(
                workspace_id=workspace,
                id=dataset,
                name="legacy",
                provenance_type="synthetic",
                created_at=stamp,
            )
        )
        conn.execute(
            old.sessions.insert().values(
                workspace_id=workspace, id=session, dataset_id=dataset, mode="import"
            )
        )
        conn.execute(
            old.objects.insert().values(
                workspace_id=workspace,
                id=obj,
                sha256=digest(content),
                sensor_id="s",
                storage_key="legacy.jsonl",
                byte_size=len(content),
                sealed_at=stamp,
            )
        )
        for event in events:
            conn.execute(
                old.events.insert().values(
                    workspace_id=workspace,
                    dataset_id=dataset,
                    event_id=event.event_id,
                    event_time=event.event_time.isoformat(),
                    event_type=event.event_type,
                    payload=event.model_dump(mode="json"),
                )
            )
            conn.execute(
                old.members.insert().values(
                    workspace_id=workspace, session_id=session, event_id=event.event_id
                )
            )
        conn.execute(
            old.findings.insert().values(
                workspace_id=workspace,
                id=finding["id"],
                dataset_id=dataset,
                session_id=session,
                payload=finding,
            )
        )
        conn.execute(
            old.incidents.insert().values(
                workspace_id=workspace,
                id=incident,
                dataset_id=dataset,
                session_id=session,
                finding_id=finding["id"],
                title="R01 扫描候选",
                start_time=finding["start_time"],
                end_time=finding["end_time"],
                created_at=stamp,
            )
        )
        conn.execute(
            old.snapshots.insert().values(
                workspace_id=workspace,
                id=snap,
                incident_id=incident,
                scope=scope.model_dump(mode="json"),
                event_ids=[e.event_id for e in events],
                created_at=stamp,
            )
        )
        conn.execute(
            old.jobs.insert().values(
                workspace_id=workspace, id=job, kind="investigation", state="succeeded"
            )
        )
        conn.execute(
            old.runs.insert().values(
                workspace_id=workspace,
                id=run,
                incident_id=incident,
                snapshot_id=snap,
                job_id=job,
                state="completed",
                report_id=report_id,
                created_at=stamp,
            )
        )
        conn.execute(
            old.reports.insert().values(
                workspace_id=workspace, id=report_id, run_id=run, version=1, payload=report
            )
        )
    db.migrate()
    service = DataService(db, settings)
    actor = service.system_actor(workspace)
    analysis = AnalysisService(service)
    with db.engine.connect() as conn:
        assert conn.execute(select(new.private_keys.c.salt)).scalar_one() == "b" * 64
        assert conn.execute(select(new.reports.c.payload)).scalar_one() == report
    assert analysis.get_report(actor, report_id) == report
    assert analysis.incident_page(actor, dataset, session)["items"][0]["id"] == incident
    assert len(analysis.timeline_page(actor, run)["items"]) == 24
    with pytest.raises(DomainError, match="LEGACY_PATH"):
        analysis.get_paths(actor, run)
    db.engine.dispose()
