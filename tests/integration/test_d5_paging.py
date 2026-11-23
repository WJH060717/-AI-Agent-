import hashlib
import hmac
import json
from datetime import UTC, datetime

import pytest
from sqlalchemy import select

from packages.contracts.context import DatasetContext
from packages.storage.analysis import AnalysisService
from packages.storage.context import ContextService
from packages.storage.service import DomainError
from tests.integration.d4_helpers import auth_record, context_payload, raw_lines
from tests.integration.test_d3_analysis import scan_bytes


def grouped_setup(context):
    _, _, service, workspace, _ = context
    actor = service.system_actor(workspace)
    dataset = service.create_dataset(actor, {"name": "group", "provenance_type": "synthetic"}, "d")
    metadata = context_payload()
    metadata["sensors"].append(
        metadata["sensors"][0] | {"sensor_id": "net-a", "source_type": "zeek", "asset_id": None}
    )
    ContextService(service).configure(
        actor, dataset["dataset_id"], DatasetContext.model_validate(metadata), "ctx"
    )
    service.stage_bytes(actor, dataset["dataset_id"], "zeek", "net-a", "UTC", scan_bytes(), "net")
    service.process_one()
    return actor, dataset


def add_auth(service, actor, dataset):
    records = [auth_record(i) for i in range(5, 10)] + [auth_record(22, "success")]
    for record in records:
        record.update(dest_ip="10.10.0.20", dest_port=22)
    records[-1]["src_port"] = 42021
    service.stage_bytes(
        actor, dataset["dataset_id"], "linux_auth", "auth-a", "UTC", raw_lines(records), "auth"
    )
    service.process_one()


def test_aggregation_replaces_current_catalog_but_keeps_old_incident_and_cursor(context):
    from packages.storage import schema_v4 as t

    _, db, service, _, _ = context
    actor, dataset = grouped_setup(context)
    analysis = AnalysisService(service)
    before = analysis.incident_page(actor, dataset["dataset_id"], dataset["default_session_id"], 1)
    old_id = before["items"][0]["id"]
    add_auth(service, actor, dataset)
    page = analysis.incident_page(actor, dataset["dataset_id"], dataset["default_session_id"], 1)
    assert len(page["items"]) == 1 and page["items"][0]["id"] != old_id
    group = page["items"][0]
    assert len(group["finding_ids"]) == 2 and group["aggregation_reasons"]
    with db.engine.connect() as conn:
        assert conn.execute(select(t.incidents.c.id).where(t.incidents.c.id == old_id)).first()
    run = analysis.create_run(actor, old_id, "old")
    service.process_one()
    assert analysis.get_run(actor, run["run_id"])["state"] == "completed"


def test_event_pages_pin_publications_and_reject_scope_or_signature_change(context):
    _, _, service, workspace, _ = context
    actor = service.system_actor(workspace)
    dataset = service.create_dataset(actor, {"name": "page", "provenance_type": "synthetic"}, "d")
    records = [json.loads(line) for line in scan_bytes(6).splitlines()]
    for record in records:
        record["ts"] = datetime(2026, 11, 14, 1, tzinfo=UTC).timestamp()
    service.stage_bytes(actor, dataset["dataset_id"], "zeek", "s", "UTC", raw_lines(records), "u")
    service.process_one()
    expected = service.list_events(
        actor, dataset["dataset_id"], dataset["default_session_id"], 100
    )["items"]
    first = service.list_events(actor, dataset["dataset_id"], dataset["default_session_id"], 2)
    later = records[0] | {"uid": "late", "ts": records[0]["ts"] - 1}
    service.stage_bytes(
        actor,
        dataset["dataset_id"],
        "zeek",
        "s",
        "UTC",
        raw_lines([later, later | {"uid": "later", "ts": records[0]["ts"] + 1}]),
        "late",
    )
    service.process_one()
    found = first["items"][:]
    cursor = first["next_cursor"]
    while cursor:
        page = service.list_events(
            actor, dataset["dataset_id"], dataset["default_session_id"], 2, cursor
        )
        found.extend(page["items"])
        cursor = page["next_cursor"]
    assert found == expected
    assert [e["event_id"] for e in found] == sorted(e["event_id"] for e in found)
    with pytest.raises(DomainError, match="CURSOR"):
        service.list_events(
            actor,
            dataset["dataset_id"],
            dataset["default_session_id"],
            2,
            first["next_cursor"] + "x",
        )
    other = service.create_dataset(actor, {"name": "other", "provenance_type": "synthetic"}, "d2")
    with pytest.raises(DomainError, match="CURSOR"):
        service.list_events(
            actor, other["dataset_id"], other["default_session_id"], 2, first["next_cursor"]
        )


def test_incident_keyset_pages_are_frozen_across_catalog_change(context):
    _, _, service, workspace, _ = context
    actor = service.system_actor(workspace)
    dataset = service.create_dataset(actor, {"name": "many", "provenance_type": "synthetic"}, "d")
    records = []
    for i in range(3):
        records.extend(
            [
                json.loads(line) | {"id.orig_h": f"192.0.2.{10 + i}"}
                for line in scan_bytes().splitlines()
            ]
        )
    service.stage_bytes(actor, dataset["dataset_id"], "zeek", "s", "UTC", raw_lines(records), "u")
    service.process_one()
    analysis = AnalysisService(service)
    expected = analysis.incident_page(
        actor, dataset["dataset_id"], dataset["default_session_id"], 100
    )["items"]
    first = analysis.incident_page(actor, dataset["dataset_id"], dataset["default_session_id"], 1)
    more = [json.loads(line) | {"id.orig_h": "192.0.2.90"} for line in scan_bytes().splitlines()]
    service.stage_bytes(actor, dataset["dataset_id"], "zeek", "s", "UTC", raw_lines(more), "more")
    service.process_one()
    found = first["items"][:]
    cursor = first["next_cursor"]
    while cursor:
        page = analysis.incident_page(
            actor, dataset["dataset_id"], dataset["default_session_id"], 1, cursor
        )
        found += page["items"]
        cursor = page["next_cursor"]
    assert found == expected
    assert (
        len(
            analysis.incident_page(
                actor, dataset["dataset_id"], dataset["default_session_id"], 100
            )["items"]
        )
        == 4
    )
    with pytest.raises(DomainError, match="CURSOR"):
        analysis.incident_page(
            actor,
            dataset["dataset_id"],
            dataset["default_session_id"],
            1,
            first["next_cursor"] + "x",
        )


def test_cursor_cannot_be_resigned_using_known_bearer_token_hash(context):
    _, _, service, _, tokens = context
    actor = service.authenticate(tokens["admin"])
    dataset = service.create_dataset(
        actor, {"name": "private-signing", "provenance_type": "synthetic"}, "d"
    )
    service.stage_bytes(actor, dataset["dataset_id"], "zeek", "s", "UTC", scan_bytes(3), "u")
    service.process_one()
    cursor = service.list_events(actor, dataset["dataset_id"], dataset["default_session_id"], 1)[
        "next_cursor"
    ]
    encoded = cursor.split(".")[0]
    known_hash = hashlib.sha256(tokens["admin"].encode()).hexdigest()
    forged = encoded + "." + hmac.new(known_hash.encode(), encoded.encode(), "sha256").hexdigest()
    with pytest.raises(DomainError, match="CURSOR"):
        service.list_events(actor, dataset["dataset_id"], dataset["default_session_id"], 1, forged)


def test_dataset_pages_pin_creation_sequence_and_token_scope(context):
    _, _, service, workspace, tokens = context
    actor = service.system_actor(workspace)
    for i in range(3):
        service.create_dataset(actor, {"name": str(i), "provenance_type": "synthetic"}, str(i))
    expected = service.dataset_page(actor, 100)["items"]
    first = service.dataset_page(actor, 1)
    service.create_dataset(actor, {"name": "later", "provenance_type": "synthetic"}, "later")
    second = service.dataset_page(actor, 100, first["next_cursor"])
    assert first["items"] + second["items"] == expected
    other_role = service.authenticate(tokens["viewer"])
    with pytest.raises(DomainError, match="CURSOR"):
        service.dataset_page(other_role, 1, first["next_cursor"])
