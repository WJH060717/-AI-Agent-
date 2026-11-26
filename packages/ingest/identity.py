"""Identity/time constraints; raw values never establish host identity by themselves."""

import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid5

from packages.contracts.context import DatasetContext, SensorProfile, source_family
from packages.contracts.models import NormalizedEvent


def pseudonym(salt: str, *values: str) -> str:
    return hmac.new(
        bytes.fromhex(salt), json.dumps(values, separators=(",", ":")).encode(), hashlib.sha256
    ).hexdigest()


def bound_profile(context) -> SensorProfile | None:
    if context.metadata is None:
        return None
    metadata = DatasetContext.model_validate(context.metadata)
    profile = next((s for s in metadata.sensors if s.sensor_id == context.sensor_id), None)
    if profile is None or profile.source_type != source_family(context.source_type):
        raise ValueError("sensor/source context mismatch")
    return profile


def aware(value: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp must be a string")
    timestamp = datetime.fromisoformat(value)
    if timestamp.tzinfo is None:
        raise ValueError("timestamp must carry a timezone")
    return timestamp.astimezone(UTC)


def apply_context(event: NormalizedEvent, context) -> NormalizedEvent:
    profile = bound_profile(context)
    if profile is None:
        return event
    event.event_time += timedelta(milliseconds=profile.offset_ms)
    if event.process and event.process.start_time:
        event.process.start_time += timedelta(milliseconds=profile.offset_ms)
    if event.socket:
        event.socket.connected_at += timedelta(milliseconds=profile.offset_ms)
    event.time_quality.offset_ms = profile.offset_ms
    event.time_quality.uncertainty_ms = profile.uncertainty_ms
    event.time_quality.basis = profile.clock_basis
    event.sensor.instance_id = profile.instance_id
    event.sensor.observation_domain = profile.observation_domain
    event.parser_version += "+identity1.0"
    event.quality_flags = [f for f in event.quality_flags if f != "clock_uncertain"]
    if profile.uncertainty_ms:
        event.quality_flags.append("clock_uncertain")
    metadata = DatasetContext.model_validate(context.metadata)
    earliest = event.event_time - timedelta(milliseconds=profile.uncertainty_ms)
    latest = event.event_time + timedelta(milliseconds=profile.uncertainty_ms)
    for endpoint in (event.src, event.dst):
        if endpoint is None:
            continue
        possible = []
        for asset in metadata.assets:
            for address in asset.addresses:
                if (
                    address.ip == str(endpoint.ip)
                    and address.observation_domain == profile.observation_domain
                    and earliest < address.valid_to
                    and latest >= address.valid_from
                ):
                    possible.append((asset.asset_id, address))
        covering = {
            asset
            for asset, address in possible
            if address.valid_from <= earliest and latest < address.valid_to
        }
        if len({asset for asset, _ in possible}) == 1 and len(covering) == 1:
            endpoint.asset_id = next(iter(covering))
            endpoint.resolution_quality = "inventory_interval"
        elif possible:
            endpoint.asset_id = None
            endpoint.resolution_quality = "ambiguous"
            event.quality_flags.append("identity_ambiguous")
        else:
            endpoint.asset_id = None
            endpoint.resolution_quality = "unknown"
    if (
        event.host
        and event.dst
        and event.dst.asset_id
        and event.dst.asset_id != event.host.asset_id
    ):
        raise ValueError("collector host and destination address identity conflict")
    return event


def process_key(asset: UUID, boot: str, pid: int, birth) -> str:
    return "process:" + str(uuid5(asset, json.dumps([boot, pid, birth], separators=(",", ":"))))


def precedes(a: NormalizedEvent, b: NormalizedEvent, max_gap_seconds: int | None = None) -> bool:
    latest_a = a.event_time + timedelta(milliseconds=a.time_quality.uncertainty_ms)
    earliest_b = b.event_time - timedelta(milliseconds=b.time_quality.uncertainty_ms)
    if latest_a >= earliest_b:
        return False
    if max_gap_seconds is not None:
        earliest_a = a.event_time - timedelta(milliseconds=a.time_quality.uncertainty_ms)
        latest_b = b.event_time + timedelta(milliseconds=b.time_quality.uncertainty_ms)
        return (latest_b - earliest_a).total_seconds() <= max_gap_seconds
    return True
