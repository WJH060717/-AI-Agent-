"""Strict, line-local Zeek conn and Suricata EVE alert adapters."""

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from packages.contracts.models import NormalizedEvent, SourceLocator, stable_event_id


@dataclass(frozen=True)
class ParseContext:
    workspace_id: str
    dataset_id: str
    object_id: str
    sha256: str
    sensor_id: str
    source_type: str
    timezone: str
    metadata: dict | None = None
    identity_salt: str | None = None


def parse_record(raw: bytes, line: int, context: ParseContext) -> NormalizedEvent:
    if context.source_type == "linux_auth":
        from packages.ingest.linux import parse_auth

        return parse_auth(raw, line, context)
    record: dict[str, Any] = json.loads(raw.decode("utf-8"))
    if not isinstance(record, dict):
        raise ValueError("record must be a JSON object")
    if context.source_type == "pcap_http":
        from packages.ingest.http_wire import wire_record

        record = wire_record(record)
    if context.source_type == "pcap" and record.get("format") != "pcap-conn@1":
        raise ValueError("missing PCAP connection format")
    synthetic = record.get("synthetic") is True
    if context.source_type in {"zeek_http", "zeek_dns", "pcap_http"}:
        from packages.ingest.http_dns import protocol_payload

        value = record["ts"]
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("Zeek ts must be numeric epoch seconds")
        ts = datetime.fromtimestamp(value, UTC)
        original = str(value)
        payload = protocol_payload(
            record, "zeek_http" if context.source_type == "pcap_http" else context.source_type
        )
        if context.source_type == "pcap_http":
            from packages.contracts.protocols import HTTPQueryEncoding, HTTPResponseShape

            payload["schema_version"] = "1.5"
            payload["http"].query_encoding = HTTPQueryEncoding.model_validate(
                record["query_encoding"]
            )
            payload["http"].response_shape = HTTPResponseShape.model_validate(
                record["response_shape"]
            )
    elif context.source_type in {"zeek", "pcap"}:
        value = record["ts"]
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("Zeek ts must be numeric epoch seconds")
        ts = datetime.fromtimestamp(value, UTC)
        if "duration" in record and (
            isinstance(record["duration"], bool) or not isinstance(record["duration"], (int, float))
        ):
            raise ValueError("Zeek duration must be numeric seconds")
        src = {"ip": record["id.orig_h"], "port": record.get("id.orig_p")}
        dst = {"ip": record["id.resp_h"], "port": record.get("id.resp_p")}
        payload = {
            "event_type": "network.connection",
            "src": src,
            "dst": dst,
            "network": {
                "transport": record["proto"],
                "uid": record.get("uid"),
                "bytes_out": record.get("orig_bytes"),
                "bytes_in": record.get("resp_bytes"),
                "duration_ms": record["duration"] * 1000 if "duration" in record else None,
            },
        }
        original = str(value)
    elif context.source_type == "suricata":
        if record.get("event_type") != "alert":
            raise ValueError("D2 accepts EVE alert records only")
        original = record["timestamp"]
        ts = datetime.fromisoformat(original)
        if ts.tzinfo is None:
            raise ValueError("EVE timestamp must carry timezone")
        alert = record["alert"]
        if not isinstance(alert, dict):
            raise ValueError("EVE alert must be an object")
        if "proto" in record and not isinstance(record["proto"], str):
            raise ValueError("EVE proto must be a string")
        native_id = alert.get("signature_id", alert.get("rule_id"))
        if native_id is None:
            raise ValueError("missing alert signature_id")
        payload = {
            "event_type": "security.alert",
            "src": {"ip": record["src_ip"], "port": record.get("src_port")},
            "dst": {"ip": record["dest_ip"], "port": record.get("dest_port")},
            "alert": {
                "rule_id": str(native_id),
                "signature": alert.get("signature"),
                "native_severity": alert.get("severity", alert.get("native_severity")),
                "category": alert.get("category"),
            },
        }
        if record.get("proto"):
            payload["network"] = {
                "transport": record["proto"].lower(),
                "flow_id": str(record["flow_id"]) if "flow_id" in record else None,
            }
    else:
        raise ValueError("unsupported source type")
    locator = SourceLocator(
        object_id=context.object_id, record_start=line, record_end=line, raw_sha256=context.sha256
    )
    event = NormalizedEvent.model_validate(
        {
            "schema_version": "1.0",
            "workspace_id": context.workspace_id,
            "dataset_id": context.dataset_id,
            "event_id": stable_event_id(
                UUID(context.workspace_id), UUID(context.dataset_id), context.sensor_id, [locator]
            ),
            "event_time": ts,
            "ingested_at": datetime.now(UTC),
            "time_quality": {
                "original": original,
                "timezone": ts.tzname() or context.timezone,
                "offset_ms": 0,
                "uncertainty_ms": 1000,
                "basis": "source_timestamp_uncalibrated",
            },
            "sensor": {
                "sensor_id": context.sensor_id,
                "type": "zeek"
                if context.source_type.startswith("zeek_")
                else "pcap"
                if context.source_type == "pcap_http"
                else context.source_type,
                "instance_id": context.dataset_id,
                "observation_domain": context.dataset_id,
            },
            "source_locators": [locator],
            "parser_version": (
                f"{context.source_type}-json@3.0.1"
                if context.source_type == "zeek_http"
                else f"{context.source_type}-json@1.0.0"
            ),
            "quality_flags": ["clock_uncertain"] + (["synthetic"] if synthetic else []),
            **payload,
        }
    )
    from packages.ingest.identity import apply_context

    return apply_context(event, context)
