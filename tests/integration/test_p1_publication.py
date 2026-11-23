from sqlalchemy import event, func, select

from packages.storage import schema_v4 as t
from packages.storage.queue import Queue
from packages.storage.worker import ImportRunner
from scripts.benchmark_p1_replay import source_records


def test_large_batch_publication_is_atomic_bounded_and_duplicate_safe(context):
    settings, db, service, workspace, _ = context
    settings.detection_event_limit = 1
    actor = service.system_actor(workspace)
    dataset = service.create_dataset(
        actor, {"name": "publication", "provenance_type": "synthetic"}, "dataset"
    )
    raw = source_records(501)
    service.stage_bytes(actor, dataset["dataset_id"], "zeek", "p1", "UTC", raw, "first")
    queue = Queue(db, settings)
    runner = ImportRunner(service, queue)
    lease = queue.claim("publisher")
    assert not runner.step(lease)
    assert (
        service.overview(actor, dataset["dataset_id"], dataset["default_session_id"])["event_count"]
        == 0
    )
    statements = []

    def count_sql(conn, cursor, statement, parameters, context, executemany):
        if "session_events" in statement.lower():
            statements.append(statement)

    event.listen(db.engine, "before_cursor_execute", count_sql)
    try:
        assert runner.step(lease)
    finally:
        event.remove(db.engine, "before_cursor_execute", count_sql)
    assert len(statements) <= 10, f"publication caused {len(statements)} membership statements"
    service.stage_bytes(actor, dataset["dataset_id"], "zeek", "p1", "UTC", raw, "duplicate")
    service.process_one()
    with db.engine.connect() as conn:
        count, waters = conn.execute(
            select(func.count(), func.count(func.distinct(t.members.c.publication))).where(
                t.members.c.workspace_id == workspace,
                t.members.c.session_id == dataset["default_session_id"],
            )
        ).one()
    assert count == 501 and waters == 1
