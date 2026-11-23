import hashlib
import json
from pathlib import Path

from packages.contracts.models import NormalizedEvent


def test_fixture_references_real_raw_bytes_without_truth_labels():
    root = Path("data/fixtures/d1")
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    objects = {item["object_id"]: item for item in manifest["raw_objects"]}
    events = [
        NormalizedEvent.model_validate_json(line)
        for line in (root / "events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert len(events) == 24
    assert len({e.event_id for e in events}) == 24
    assert {e.sensor.type for e in events} == {"zeek", "linux_auth", "linux_audit", "suricata"}
    for event in events:
        assert not event.extensions
        for ref in event.source_locators:
            obj = objects[str(ref.object_id)]
            raw = (root / obj["path"]).read_bytes()
            assert hashlib.sha256(raw).hexdigest() == ref.raw_sha256 == obj["sha256"]
            assert 1 <= ref.record_start <= ref.record_end <= len(raw.splitlines())
            if event.event_type == "auth.login":
                record = json.loads(raw.splitlines()[ref.record_start - 1])
                assert event.user.session_id == record.get("session_id")
                if event.auth.outcome == "failure":
                    assert event.user.session_id is None
