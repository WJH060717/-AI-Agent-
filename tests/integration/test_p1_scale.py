from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select

from packages.storage import schema_v6 as t
from packages.storage.queue import Queue
from scripts.benchmark_p1_replay import source_records
from tests.integration.test_p1_replay import setup_replay


def test_detection_streaming_is_confined_to_reads(context):
    from sqlalchemy import event

    from packages.storage.analysis import AnalysisService
    from tests.integration.test_d5_paging import grouped_setup

    _, db, service, _, _ = context
    actor, dataset = grouped_setup(context)
    invalid = []

    def observe(conn, cursor, statement, params, execution, many):
        if execution.execution_options.get("stream_results") and not statement.startswith("SELECT"):
            invalid.append(statement.split()[0])

    event.listen(db.engine, "before_cursor_execute", observe)
    try:
        with db.engine.begin() as conn:
            AnalysisService(service).detect(
                conn, actor, dataset["dataset_id"], dataset["default_session_id"]
            )
    finally:
        event.remove(db.engine, "before_cursor_execute", observe)
    assert invalid == [], "PostgreSQL cannot DECLARE a server cursor for DML/savepoint commands"


def test_import_more_than_ten_thousand_is_complete(context):
    _, _, service, workspace, _ = context
    actor = service.system_actor(workspace)
    dataset = service.create_dataset(actor, {"name": "scale", "provenance_type": "synthetic"}, "d")
    batch = service.stage_bytes(
        actor, dataset["dataset_id"], "zeek", "scale", "UTC", source_records(10001), "import"
    )
    service.process_one()
    assert service.get_batch(actor, batch["batch_id"])["status"] == "succeeded"
    view = service.overview(actor, dataset["dataset_id"], dataset["default_session_id"])
    assert view["event_count"] == 10001 and view["detection_status"] == "complete"


@pytest.mark.parametrize("kind", ["work", "bytes", "publication"])
def test_resource_limit_is_partial_and_publication_rolls_back(context, monkeypatch, kind):
    from packages.detection.limits import DetectionLimit
    from packages.storage.incidents import CatalogService
    from packages.storage.replay import ReplayRunner

    settings, db, service, _, _ = context
    actor, dataset, api, _, created = setup_replay(context)
    if kind == "work":
        settings.detection_work_limit = 1
    elif kind == "bytes":
        settings.detection_byte_limit = 1024
    else:
        original = CatalogService.publish

        def fail_after_publish(self, *args, **kwargs):
            original(self, *args, **kwargs)
            raise DetectionLimit("forced publication boundary")

        monkeypatch.setattr(CatalogService, "publish", fail_after_publish)
    queue = Queue(db, settings)
    lease = queue.claim("limited")
    clock = [datetime.now(UTC)]
    runner = ReplayRunner(service, queue, clock=lambda: clock[0])
    runner.step(lease)
    clock[0] += timedelta(seconds=10)
    assert runner.step(lease) is None
    result = api.status(actor, created["job_id"])
    assert result["state"] == "partial"
    assert result["warnings"] == ["RULE_RESOURCE_LIMIT"]
    assert result["published_events"] == result["total_events"]
    with db.engine.connect() as conn:
        for table in [t.findings, t.incidents, t.catalogs]:
            assert (
                conn.execute(
                    select(func.count())
                    .select_from(table)
                    .where(
                        table.c.workspace_id == actor.workspace_id,
                        table.c.session_id == created["session_id"],
                    )
                ).scalar_one()
                == 0
            )
        assert (
            conn.execute(
                select(t.heads.c.id).where(
                    t.heads.c.workspace_id == actor.workspace_id,
                    t.heads.c.id == created["session_id"],
                )
            ).first()
            is None
        )
