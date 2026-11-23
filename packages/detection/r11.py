"""Mixed malformed/encoded non-ASCII HTTP query candidates from PCAP observations."""

from collections import Counter, defaultdict
from datetime import timedelta
from typing import Literal

from pydantic import Field, StrictInt

from packages.contracts.models import Contract, NormalizedEvent
from packages.detection.common import finding
from packages.detection.limits import checkpoint
from packages.detection.r07 import collector
from packages.detection.r10 import bounded_windows, interval


class R11Config(Contract):
    id: Literal["R11"] = "R11"
    version: Literal["1.0.0"] = "1.0.0"
    shape_version: Literal["http-query-encoding@1"] = "http-query-encoding@1"
    methods: list[Literal["GET", "POST"]] = ["GET", "POST"]
    min_query_bytes: StrictInt = Field(default=32, ge=32, le=4096)
    min_requests: StrictInt = Field(default=2, ge=2, le=100)
    min_connections: StrictInt = Field(default=2, ge=2, le=100)
    window_seconds: StrictInt = Field(default=600, ge=60, le=1200)
    association_seconds: StrictInt = Field(default=3600, ge=1, le=3600)


def connection_key(event: NormalizedEvent) -> tuple | None:
    if not (
        event.sensor.type == "pcap"
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


def qualifies(event: NormalizedEvent, rule: R11Config) -> bool:
    http = event.http
    shape = http.query_shape if http else None
    encoding = http.query_encoding if http else None
    return bool(
        event.event_type == "network.http"
        and http
        and http.host
        and http.method in rule.methods
        and shape
        and shape.status == "observed"
        and shape.raw_bytes >= rule.min_query_bytes
        and shape.has_literal_kv is False
        and shape.percent_encoding == "invalid"
        and encoding
        and encoding.version == rule.shape_version
        and encoding.invalid_percent > 0
        and encoding.escaped_non_ascii > 0
        and http.response_shape
        and http.response_shape.framing == "complete"
    )


def detect_mixed_encoding(
    events: list[NormalizedEvent], session_id: str, rule: R11Config
) -> list[dict]:
    unique = {event.event_id: event for event in events}
    connections, groups = defaultdict(list), defaultdict(list)
    for event in unique.values():
        checkpoint(size=128)
        key = connection_key(event)
        if key is not None and event.event_type == "network.connection":
            connections[key].append(event)
    for event in unique.values():
        checkpoint()
        if not qualifies(event, rule):
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
                milliseconds=conn.time_quality.uncertainty_ms + event.time_quality.uncertainty_ms
            )
            if (
                conn.event_time - slack
                <= event.event_time
                <= conn.event_time + timedelta(milliseconds=duration) + slack
            ):
                matches.append(conn)
        if len(matches) == 1:
            groups[
                (
                    *collector(event),
                    str(event.src.ip),
                    str(event.dst.ip),
                    event.dst.port,
                    event.http.host,
                )
            ].append((event, matches[0]))
    result = []
    for group, pairs in sorted(groups.items(), key=lambda item: str(item[0])):
        pairs.sort(key=lambda pair: (pair[0].event_time, pair[0].event_id))
        for left, right in bounded_windows(pairs, rule):
            selected = pairs[left : right + 1]
            checkpoint(len(selected), size=len(selected) * 128)
            requests = [pair[0] for pair in selected]
            intervals = [interval(event) for event in requests]
            lower = max(
                0.0,
                (max(v[0] for v in intervals) - min(v[1] for v in intervals)).total_seconds(),
            )
            upper = (max(v[1] for v in intervals) - min(v[0] for v in intervals)).total_seconds()
            result.append(
                finding(
                    rule,
                    [event for pair in selected for event in pair],
                    session_id,
                    [*map(str, group[3:]), requests[0].event_id],
                    "mixed_percent_http_query",
                    http_event_ids=[e.event_id for e in requests],
                    connection_event_ids=sorted({pair[1].event_id for pair in selected}),
                    maliciousness="unknown",
                    statistics={
                        "requests": len(requests),
                        "connections": len({e.network.uid for e in requests}),
                        "status_counts": dict(
                            sorted(
                                Counter(
                                    str(e.http.status_code)
                                    if e.http.status_code is not None
                                    else "unknown"
                                    for e in requests
                                ).items()
                            )
                        ),
                        "span_lower_seconds": lower,
                        "span_upper_seconds": upper,
                    },
                    limitations=[
                        "混合百分号编码候选：非法转义与非ASCII字节转义重复共现，不证明C&C或恶意命令",
                        "正常旧客户端、遥测和损坏请求也可能符合；不能部分解码非法查询推断内容",
                        "失败响应不代表成功控制；响应格式仅为字节特征，不证明文件安全或执行",
                        "同采集器关联不证明进程socket归属、真实操作者或完整攻击链",
                    ],
                )
            )
    return result
