import os
import time
from pathlib import Path
from uuid import uuid4

from apps.worker.cleanup import inventory


def test_orphan_inventory_is_read_only_and_protects_referenced_objects(context):
    settings, db, service, workspace, _ = context
    actor = service.system_actor(workspace)
    dataset = service.create_dataset(
        actor, {"name": "cleanup", "provenance_type": "synthetic"}, "d"
    )
    service.stage_bytes(
        actor,
        dataset["dataset_id"],
        "zeek",
        "s",
        "UTC",
        Path("data/fixtures/d1/zeek.jsonl").read_bytes(),
        "u",
    )
    service.process_one()
    referenced = next(settings.raw_store.rglob("*.jsonl"))
    orphan = referenced.parent / f"{uuid4()}.partial"
    orphan.write_bytes(b"partial")
    old = time.time() - 90000
    for path in (referenced, orphan):
        os.utime(path, (old, old))
    result = inventory(db, settings)
    assert [r["relative_path"] for r in result] == [
        orphan.relative_to(settings.raw_store).as_posix()
    ]
    assert orphan.read_bytes() == b"partial"
    assert referenced.exists()
