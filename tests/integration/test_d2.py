import asyncio
import hashlib
import json
from pathlib import Path

import httpx
import pytest

from apps.api.main import create_app


def test_upload_worker_query_evidence_and_repeat(context):
    settings, db, service, workspace, tokens = context

    async def scenario():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_app(settings)), base_url="http://test"
        ) as client:
            headers = {"Authorization": f"Bearer {tokens['admin']}"}
            assert (await client.get("/api/v1/datasets")).status_code == 401
            response = await client.post(
                "/api/v1/datasets",
                headers=headers | {"Idempotency-Key": "dataset-1"},
                json={"name": "d2", "provenance_type": "synthetic"},
            )
            assert response.status_code == 201, response.text
            dataset = response.json()
            data = {
                "dataset_id": dataset["dataset_id"],
                "source_type": "zeek",
                "sensor_id": "lab-zeek",
                "timezone": "UTC",
            }
            raw = Path("data/fixtures/d1/zeek.jsonl").read_bytes() + b"{bad json}\n"
            upload_headers = headers | {"Idempotency-Key": "upload-1"}
            upload = await client.post(
                "/api/v1/imports",
                headers=upload_headers,
                data=data,
                files={"file": ("../../unsafe.jsonl", raw)},
            )
            assert upload.status_code == 202, upload.text
            batch = upload.json()
            assert (
                await client.get(f"/api/v1/imports/{batch['batch_id']}", headers=headers)
            ).json()["status"] == "queued"
            assert service.process_one() is True
            result = (
                await client.get(f"/api/v1/imports/{batch['batch_id']}", headers=headers)
            ).json()
            assert (result["accepted"], result["quarantined"], result["duplicate"]) == (8, 1, 0)
            response = await client.get(
                "/api/v1/events",
                headers=headers,
                params={
                    "dataset_id": dataset["dataset_id"],
                    "session_id": dataset["default_session_id"],
                },
            )
            assert response.status_code == 200, response.text
            events = response.json()["items"]
            assert len(events) == 8
            obj = events[0]["source_locators"][0]
            assert obj["raw_sha256"] == hashlib.sha256(raw).hexdigest()
            assert list(settings.raw_store.rglob("*.jsonl"))
            repeated = await client.post(
                "/api/v1/imports",
                headers=upload_headers,
                data=data,
                files={"file": ("safe.jsonl", raw)},
            )
            assert repeated.json()["batch_id"] == batch["batch_id"]
            changed = await client.post(
                "/api/v1/imports",
                headers=upload_headers,
                data=data,
                files={"file": ("x.jsonl", b"{}\n")},
            )
            assert changed.status_code == 409
            viewer = {"Authorization": f"Bearer {tokens['viewer']}"}
            denied = await client.post(
                "/api/v1/imports", headers=viewer, data=data, files={"file": ("x", raw)}
            )
            assert denied.status_code == 403
            # Same bytes, new request key: stable events, no double counting.
            again = await client.post(
                "/api/v1/imports",
                headers=headers | {"Idempotency-Key": "upload-2"},
                data=data,
                files={"file": ("x", raw)},
            )
            service.process_one()
            counts = (
                await client.get(f"/api/v1/imports/{again.json()['batch_id']}", headers=headers)
            ).json()
            assert (counts["accepted"], counts["duplicate"], counts["quarantined"]) == (0, 8, 1)
            _, other_tokens = service.init_workspace("other")
            other = {"Authorization": f"Bearer {other_tokens['admin']}"}
            assert (
                await client.get(f"/api/v1/events/{events[0]['event_id']}", headers=other)
            ).status_code == 404
            assert (
                await client.get(f"/api/v1/imports/{batch['batch_id']}", headers=other)
            ).status_code == 404

    asyncio.run(scenario())


def test_suricata_real_field_mapping_and_non_alert_is_quarantined(context):
    _, _, service, workspace, _ = context
    actor = service.system_actor(workspace)
    dataset = service.create_dataset(actor, {"name": "eve", "provenance_type": "synthetic"}, "ds")
    raw = {
        "timestamp": "2026-11-14T09:00:00+0800",
        "event_type": "alert",
        "src_ip": "192.0.2.10",
        "src_port": 42000,
        "dest_ip": "10.10.0.20",
        "dest_port": 22,
        "proto": "TCP",
        "flow_id": 9999999999999999999,
        "alert": {"signature_id": 42, "signature": "test", "severity": 2, "category": "lab"},
    }
    batch = service.stage_bytes(
        actor,
        dataset["dataset_id"],
        "suricata",
        "sensor-a",
        "UTC",
        (json.dumps(raw) + '\n{"event_type":"flow"}\n').encode(),
        "b1",
    )
    service.process_one()
    result = service.get_batch(actor, batch["batch_id"])
    assert (result["accepted"], result["quarantined"]) == (1, 1)
    events = service.list_events(actor, dataset["dataset_id"], dataset["default_session_id"], 50)
    assert events["items"][0]["alert"]["rule_id"] == "42"
    assert events["items"][0]["event_time"].startswith("2026-11-14T01:")


def test_archive_tampering_fails_closed(context):
    settings, _, service, workspace, _ = context
    actor = service.system_actor(workspace)
    dataset = service.create_dataset(actor, {"name": "x", "provenance_type": "synthetic"}, "x")
    service.stage_bytes(
        actor,
        dataset["dataset_id"],
        "zeek",
        "s",
        "UTC",
        Path("data/fixtures/d1/zeek.jsonl").read_bytes(),
        "x",
    )
    service.process_one()
    event = service.list_events(actor, dataset["dataset_id"], dataset["default_session_id"], 1)[
        "items"
    ][0]
    path = next(settings.raw_store.rglob("*.jsonl"))
    path.write_bytes(b"tampered\n")
    with pytest.raises(ValueError, match="INTEGRITY"):
        service.verify_evidence(actor, event["event_id"])


@pytest.mark.parametrize("bad_field", [{"alert": None}, {"alert": []}, {"proto": 42}])
def test_malformed_eve_payload_does_not_rollback_good_records(context, bad_field):
    _, _, service, workspace, _ = context
    actor = service.system_actor(workspace)
    dataset = service.create_dataset(
        actor, {"name": "malformed", "provenance_type": "synthetic"}, "ds"
    )
    raw = {
        "timestamp": "2026-11-14T01:00:00Z",
        "event_type": "alert",
        "src_ip": "192.0.2.10",
        "dest_ip": "10.10.0.20",
        "proto": "TCP",
        "alert": {"signature_id": 42},
    }
    content = (json.dumps(raw) + "\n" + json.dumps(raw | bad_field) + "\n").encode()
    batch = service.stage_bytes(actor, dataset["dataset_id"], "suricata", "s", "UTC", content, "u")
    service.process_one()
    result = service.get_batch(actor, batch["batch_id"])
    assert (result["accepted"], result["quarantined"]) == (1, 1)
