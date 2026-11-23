"""Automatic upload routing preserves real sensor identity and deduplication."""

import pytest
from fastapi.testclient import TestClient

from apps.api.main import create_app
from tests.integration.test_pcap_packet import events, ipv4_frame, one_dataset, pcap


@pytest.fixture
def case(context):
    settings, _, service, workspace, tokens = context
    actor = service.system_actor(workspace)
    dataset = one_dataset(service, actor)
    frame = ipv4_frame(1, bytes(8))
    raw = pcap((frame, len(frame)))
    with TestClient(create_app(settings)) as client:
        yield client, service, actor, dataset, raw, tokens["admin"]


def post(case, key, sensor=None, source="pcap_packet"):
    client, _, _, dataset, raw, token = case
    data = {"dataset_id": dataset["dataset_id"], "source_type": source}
    if sensor is not None:
        data["sensor_id"] = sensor
    return client.post(
        "/api/v1/imports",
        data=data,
        files={"file": ("neutral.pcap", raw, "application/octet-stream")},
        headers={"Authorization": f"Bearer {token}", "Idempotency-Key": key},
    )


def configure(case, *sensors):
    client, _, _, dataset, _, token = case
    response = client.post(
        f"/api/v1/datasets/{dataset['dataset_id']}/context",
        json={"sensors": [
            {"sensor_id": name, "source_type": family, "instance_id": name,
             "observation_domain": "lab-a", "clock_basis": "synchronized", "offset_ms": 20}
            for name, family in sensors
        ]},
        headers={"Authorization": f"Bearer {token}", "Idempotency-Key": "source-config"},
    )
    assert response.status_code == 200


def test_unconfigured_pcap_import_uses_existing_ui_default(case):
    _, service, actor, dataset, _, _ = case
    first = post(case, "first")
    assert first.status_code == 202
    assert service.process_one()
    [event] = events(service, actor, dataset)
    assert event["sensor"]["sensor_id"] == "lab-sensor-01"
    again = post(case, "again", sensor="lab-sensor-01")
    assert again.status_code == 202 and service.process_one()
    assert service.get_batch(actor, again.json()["batch_id"])["duplicate"] == 1


def test_pcap_reuses_the_only_existing_source_identity(case):
    _, service, actor, dataset, _, _ = case
    initial = post(case, "original", sensor="research-probe")
    assert initial.status_code == 202 and service.process_one()
    automatic = post(case, "automatic")
    assert automatic.status_code == 202 and service.process_one()
    assert service.get_batch(actor, automatic.json()["batch_id"])["duplicate"] == 1
    [event] = events(service, actor, dataset)
    assert event["sensor"]["sensor_id"] == "research-probe"


def test_configured_source_resolves_by_family_and_applies_clock_context(case):
    configure(case, ("capture", "pcap"), ("network", "zeek"))
    _, service, actor, dataset, _, _ = case
    result = post(case, "automatic")
    assert result.status_code == 202 and service.process_one()
    [event] = events(service, actor, dataset)
    assert event["sensor"]["sensor_id"] == "capture"
    assert event["time_quality"]["offset_ms"] == 20


def test_multiple_configured_sensors_require_explicit_selection(case):
    configure(case, ("capture-a", "pcap"), ("capture-b", "pcap"), ("network", "zeek"))
    _, service, _, _, _, _ = case
    result = post(case, "ambiguous")
    assert result.status_code == 422
    reason = result.json()["error"]
    assert reason["code"] == "SENSOR_SELECTION_REQUIRED"
    assert reason["details"] == {"sensor_ids": ["capture-a", "capture-b"]}
    assert not service.process_one()
    assert post(case, "selected", sensor="capture-b").status_code == 202


def test_accepted_automatic_request_retries_after_sensor_set_changes(case):
    first = post(case, "original")
    assert first.status_code == 202
    assert post(case, "second", sensor="research-probe").status_code == 202
    reissued = post(case, "original")
    assert reissued.status_code == 202 and reissued.json() == first.json()
    ambiguous = post(case, "ambiguous")
    assert ambiguous.status_code == 422
    assert ambiguous.json()["error"]["code"] == "SENSOR_SELECTION_REQUIRED"


def test_unconfigured_linux_does_not_invent_a_sensor_identity(case):
    response = post(case, "linux", source="linux_auth")
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "LINUX_CONTEXT_REQUIRED"
