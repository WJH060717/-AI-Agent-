"""Composite HTTP callback leads; updates/telemetry may match the same evidence."""

from collections import Counter, defaultdict
from datetime import timedelta
from typing import Literal

from pydantic import Field, StrictInt

from packages.contracts.models import Contract, NormalizedEvent
from packages.detection.common import finding
from packages.detection.limits import checkpoint
from packages.detection.r07 import collector, connection_key


class R08Config(Contract):
    id: Literal["R08"] = "R08"
    version: Literal["1.0.0"] = "1.0.0"
    shape_version: Literal["http-client-shape@1"] = "http-client-shape@1"
    methods: list[Literal["GET", "POST"]] = ["GET", "POST"]
    min_requests: StrictInt = Field(default=3, ge=3, le=100)
    min_connections: StrictInt = Field(default=3, ge=3, le=100)
    min_span_seconds: StrictInt = Field(default=30, ge=1, le=300)
    window_seconds: StrictInt = Field(default=600, ge=300, le=1200)
    association_seconds: StrictInt = Field(default=3600, ge=1, le=3600)


def responded(event: NormalizedEvent) -> bool:
    return bool(
        event.http
        and event.http.status_code is not None
        and 200 <= event.http.status_code < 300
        and (event.http.response_body_len or 0) > 0
    )


def span_bounds(first: NormalizedEvent, last: NormalizedEvent) -> tuple[float, float]:
    span = (last.event_time - first.event_time).total_seconds()
    error = (first.time_quality.uncertainty_ms + last.time_quality.uncertainty_ms) / 1000
    return span - error, span + error


def windows(
    pairs: list[tuple[NormalizedEvent, NormalizedEvent]], rule: R08Config
) -> list[tuple[int, int]]:
    result = []
    left, responses = 0, 0
    uids = Counter()
    for right, (event, _) in enumerate(pairs):
        checkpoint()
        uids[event.network.uid] += 1
        responses += responded(event)
        while left <= right and span_bounds(pairs[left][0], event)[1] > rule.window_seconds:
            checkpoint()
            old = pairs[left][0]
            uids[old.network.uid] -= 1
            if uids[old.network.uid] == 0:
                del uids[old.network.uid]
            responses -= responded(old)
            left += 1
        if (
            right - left + 1 < rule.min_requests
            or len(uids) < rule.min_connections
            or responses == 0
            or span_bounds(pairs[left][0], event)[0] < rule.min_span_seconds
        ):
            continue
        if (
            result
            and left <= result[-1][1]
            and (span_bounds(pairs[result[-1][0]][0], event)[1] <= rule.window_seconds)
        ):
            result[-1] = (result[-1][0], right)
        else:
            result.append((left, right))
    return result


def detect_callbacks(events: list[NormalizedEvent], session_id: str, rule: R08Config) -> list[dict]:
    endpoint_group = getattr(rule, "grouping", "host") == "endpoint"
    unique = {event.event_id: event for event in events}
    connections, groups = defaultdict(list), defaultdict(list)
    for event in unique.values():
        checkpoint(size=128)
        key = connection_key(event)
        if key is not None and event.event_type == "network.connection":
            connections[key].append(event)
    for event in unique.values():
        checkpoint()
        http = event.http
        shape = http.client_shape if http else None
        if not (
            event.event_type == "network.http"
            and http
            and http.host
            and http.method in rule.methods
            and shape
            and shape.version == rule.shape_version
            and shape.user_agent_class == "other"
            and shape.query_status == "parsed"
            and (shape.opaque_hex_count or 0) > 0
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
                milliseconds=conn.time_quality.uncertainty_ms + event.time_quality.uncertainty_ms
            )
            if (
                conn.event_time - slack
                <= event.event_time
                <= (conn.event_time + timedelta(milliseconds=duration) + slack)
            ):
                matches.append(conn)
        if len(matches) != 1:
            continue
        group = (*collector(event), str(event.src.ip), str(event.dst.ip), event.dst.port)
        if not endpoint_group:
            group += (http.host,)
        groups[group].append((event, matches[0]))
    result = []
    for group, pairs in sorted(groups.items(), key=lambda item: str(item[0])):
        pairs.sort(key=lambda pair: (pair[0].event_time, pair[0].event_id))
        for left, right in windows(pairs, rule):
            selected = pairs[left : right + 1]
            checkpoint(len(selected), size=len(selected) * 128)
            requests = [pair[0] for pair in selected]
            hosts = sorted({event.http.host for event in requests})
            if endpoint_group and len(hosts) < rule.minimum_hosts:
                continue
            first, last = requests[0], requests[-1]
            lower, upper = span_bounds(first, last)
            result.append(
                finding(
                    rule,
                    [event for pair in selected for event in pair],
                    session_id,
                    [*map(str, group[3:]), first.event_id],
                    "multi_host_http_callback" if endpoint_group else "automated_http_callback",
                    **(
                        {"http_hosts": hosts, "association_scope": "remote_endpoint_only"}
                        if endpoint_group
                        else {}
                    ),
                    http_event_ids=[event.event_id for event in requests],
                    connection_event_ids=sorted({pair[1].event_id for pair in selected}),
                    maliciousness="unknown",
                    statistics={
                        "requests": len(requests),
                        "connections": len({event.network.uid for event in requests}),
                        "positive_responses": sum(responded(event) for event in requests),
                        "span_lower_seconds": lower,
                        "span_upper_seconds": upper,
                    },
                    limitations=[
                        "疑似C&C回连候选：请求形态和多连接响应不证明恶意命令、执行或控制关系",
                        "正常更新、遥测和SDK也可能符合；User-Agent外形可伪装，不证明真实程序",
                        "只保留参数形态计数，不证明参数值相同、用户或设备身份；缺进程socket归属",
                        "仅统计符合条件且唯一关联的HTTP请求；失败请求不代表成功控制，未覆盖加密内容",
                    ]
                    + (
                        [
                            "多个Host仅在同一远端IP/端口聚合；共享主机、CDN或不同应用也可能符合，"
                            "不证明同一服务或控制者"
                        ]
                        if endpoint_group
                        else []
                    ),
                )
            )
    return result
