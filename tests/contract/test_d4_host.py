import json

import pytest

from packages.contracts.models import SourceLocator
from packages.ingest.linux import parse_audit_group
from packages.ingest.parsers import parse_record
from tests.integration.d4_helpers import audit_record, auth_record, parse_context, raw_lines


def test_auth_redacts_account_and_only_success_gets_session():
    raw = raw_lines([auth_record(), auth_record(5, "success")])
    ctx = parse_context("linux_auth", raw)
    a, b = [parse_record(row, i + 1, ctx) for i, row in enumerate(raw.splitlines())]
    assert a.asset_id == b.asset_id
    assert a.user.entity_id == b.user.entity_id and a.user.entity_id
    assert "alice" not in a.model_dump_json()
    assert a.user.session_id is None and b.user.session_id.startswith("session:")
    assert b.host.boot_id == "boot-a"


def test_naive_time_and_conflicting_hostname_are_rejected():
    for change in ({"timestamp": "2026-11-14T01:00:00"}, {"host": "wrong-host"}):
        raw = raw_lines([auth_record() | change])
        with pytest.raises(ValueError):
            parse_record(raw, 1, parse_context("linux_auth", raw))


def test_audit_interleaved_fragments_and_exec_birth_separation():
    records = [
        audit_record("SYSCALL"),
        audit_record("SYSCALL", "2"),
        audit_record("EXECVE"),
        audit_record("EOE"),
    ]
    raw = raw_lines(records)
    ctx = parse_context("linux_audit", raw)
    parts = [
        (
            row,
            SourceLocator(
                object_id=ctx.object_id, raw_sha256=ctx.sha256, record_start=i + 1, record_end=i + 1
            ),
        )
        for i, row in enumerate(raw.splitlines())
        if i != 1
    ]
    event = parse_audit_group(parts, ctx)
    assert [ref.record_start for ref in event.source_locators] == [1, 3, 4]
    assert event.process.action == "exec" and event.process.start_time is None
    assert event.process.start_ticks == 100 and event.process.entity_id
    weak = records[0] | {"process": {"pid": 42, "ppid": 10, "action": "exec"}}
    parts[0] = (json.dumps(weak).encode(), parts[0][1])
    event = parse_audit_group(parts, ctx)
    assert event.process.entity_id is None and event.process.parent_entity_id is None
    assert "identity_weak" in event.quality_flags
