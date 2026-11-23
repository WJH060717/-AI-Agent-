from sqlalchemy import event

from scripts.benchmark_d11 import records
from tests.integration.conftest import context  # noqa: F401


def test_event_page_does_not_scan_and_sort_the_whole_session(context):  # noqa: F811
    settings, db, service, workspace, _ = context
    settings.detection_event_limit = 1
    actor = service.system_actor(workspace)
    dataset = service.create_dataset(
        actor, {"name": "query-work", "provenance_type": "synthetic"}, "d"
    )
    for i in range(4):
        service.stage_bytes(
            actor, dataset["dataset_id"], "zeek", "s", "UTC", records(i * 500, 500), str(i)
        )
        assert service.process_one()
    steps = 0

    def progress():
        nonlocal steps
        steps += 100
        return 0

    def checkout(connection, *_):
        connection.set_progress_handler(progress, 100)

    def checkin(connection, *_):
        connection.set_progress_handler(None, 0)

    event.listen(db.engine, "checkout", checkout)
    event.listen(db.engine, "checkin", checkin)
    try:
        page = service.list_events(actor, dataset["dataset_id"], dataset["default_session_id"], 5)
    finally:
        event.remove(db.engine, "checkout", checkout)
        event.remove(db.engine, "checkin", checkin)
    assert len(page["items"]) == 5 and page["next_cursor"]
    assert steps < 8000, f"A five-event page executed {steps} SQLite VM steps on 2000 events"
