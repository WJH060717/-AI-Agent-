"""Executable HTTP request observations, never malware or execution verdicts."""

from collections import defaultdict
from datetime import timedelta
from typing import Literal

from pydantic import Field, StrictInt

from packages.contracts.models import Contract, NormalizedEvent
from packages.detection.common import finding
from packages.detection.limits import checkpoint


class R07Config(Contract):
    id: Literal["R07"] = "R07"
    version: Literal["1.0.0"] = "1.0.0"
    method: Literal["GET"] = "GET"
    statuses: list[StrictInt] = [200, 206]
    suffixes: list[str] = [".exe", ".dll", ".msi", ".scr", ".com", ".elf"]
    mime_types: list[str] = [
        "application/x-dosexec",
        "application/x-msdownload",
        "application/vnd.microsoft.portable-executable",
        "application/x-executable",
    ]
    association_seconds: StrictInt = Field(default=3600, ge=1, le=3600)
    dns_lookback_seconds: StrictInt = Field(default=300, ge=1, le=300)
    dns_limit: StrictInt = Field(default=32, ge=1, le=32)


def collector(event: NormalizedEvent) -> tuple:
    return (
        event.workspace_id,
        event.dataset_id,
        event.sensor.observation_domain,
        event.sensor.sensor_id,
        event.sensor.instance_id,
    )


def connection_key(event: NormalizedEvent) -> tuple | None:
    if not (
        event.sensor.type == "zeek"
        and event.network
        and event.network.uid
        and event.network.transport == "tcp"
        and event.src
        and event.dst
        and event.src.port is not None
        and event.dst.port is not None
    ):
        return None
    return (
        *collector(event),
        event.network.uid,
        event.src.ip,
        event.src.port,
        event.dst.ip,
        event.dst.port,
    )


def detect_http_requests(
    events: list[NormalizedEvent], session_id: str, rule: R07Config
) -> list[dict]:
    connections, dns_index = defaultdict(list), defaultdict(list)
    unique = {event.event_id: event for event in events}
    for event in unique.values():
        checkpoint(size=128)
        key = connection_key(event)
        if event.event_type == "network.connection" and key is not None:
            connections[key].append(event)
        if (
            event.event_type == "network.dns"
            and event.sensor.type == "zeek"
            and event.dns
            and event.src
            and event.dns.query
            and event.dns.qtype in {1, 28}
            and event.dns.rcode == 0
            and event.dns.rejected is False
            and event.dns.answers
        ):
            dns_index[(*collector(event), event.src.ip, event.dns.query)].append(event)
    result = []
    for event in sorted(unique.values(), key=lambda e: (e.event_time, e.event_id)):
        checkpoint()
        http = event.http
        if not (
            event.event_type == "network.http"
            and http
            and http.method == rule.method
            and http.status_code in rule.statuses
            and (
                http.uri_suffix in rule.suffixes
                or set(http.response_mime_types or []).intersection(rule.mime_types)
            )
        ):
            continue
        key = connection_key(event)
        if key is None:
            continue
        matches = []
        for conn in connections.get(key, []):
            checkpoint()
            duration = conn.network.duration_ms
            if duration is None or duration > rule.association_seconds * 1000:
                continue
            slack = timedelta(
                milliseconds=(conn.time_quality.uncertainty_ms + event.time_quality.uncertainty_ms)
            )
            if (
                conn.event_time - slack
                <= event.event_time
                <= (conn.event_time + timedelta(milliseconds=duration) + slack)
            ):
                matches.append(conn)
        if len(matches) != 1:
            continue
        context = []
        if http.host:
            for dns in dns_index.get((*collector(event), event.src.ip, http.host), []):
                checkpoint()
                gap = (event.event_time - dns.event_time).total_seconds()
                uncertainty = (
                    event.time_quality.uncertainty_ms + dns.time_quality.uncertainty_ms
                ) / 1000
                if (
                    gap > uncertainty
                    and gap + uncertainty <= rule.dns_lookback_seconds
                    and event.dst.ip in dns.dns.answers
                ):
                    context.append(dns)
                    if len(context) > rule.dns_limit:
                        context = []
                        break
        result.append(
            finding(
                rule,
                [matches[0], event, *context],
                session_id,
                [event.sensor.sensor_id, event.sensor.instance_id, event.event_id],
                "http_executable_request",
                stage=("body_observed" if (http.response_body_len or 0) > 0 else "request_only"),
                http_event_id=event.event_id,
                connection_event_id=matches[0].event_id,
                dns_context_status="included" if context else "not_included",
                limitations=[
                    "后缀/MIME和HTTP状态仅产生请求候选；内容、完成下载、执行及恶意性未知",
                    "正常安装或更新也可能符合；同采集器UID/端点/时间关联不证明进程归属",
                    f"DNS仅为先前{rule.dns_lookback_seconds}秒内的上下文，最多{rule.dns_limit}条；"
                    "缺失、不匹配或超限时不纳入，不证明因果",
                ],
            )
        )
    return result
