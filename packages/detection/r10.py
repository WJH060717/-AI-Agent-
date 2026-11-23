"""Repeated non-text HTTP query leads, without an intent or control verdict."""

from collections import Counter, defaultdict, deque
from datetime import timedelta
from typing import Literal

from pydantic import Field, StrictInt

from packages.contracts.models import Contract, NormalizedEvent
from packages.detection.common import finding
from packages.detection.limits import checkpoint
from packages.detection.r07 import collector, connection_key
from packages.detection.r08 import span_bounds


class R10Config(Contract):
    id: Literal["R10"] = "R10"
    version: Literal["1.0.0", "1.0.1"] = "1.0.1"
    shape_version: Literal["http-query-shape@1"] = "http-query-shape@1"
    methods: list[Literal["GET", "POST"]] = ["GET", "POST"]
    min_query_bytes: StrictInt = Field(default=32, ge=32, le=4096)
    min_requests: StrictInt = Field(default=2, ge=2, le=100)
    min_connections: StrictInt = Field(default=2, ge=2, le=100)
    window_seconds: StrictInt = Field(default=600, ge=60, le=1200)
    association_seconds: StrictInt = Field(default=3600, ge=1, le=3600)


def qualifies(event: NormalizedEvent, rule: R10Config) -> bool:
    http = event.http
    shape = http.query_shape if http else None
    return bool(
        event.event_type == "network.http"
        and http
        and http.host
        and http.method in rule.methods
        and shape
        and shape.version == rule.shape_version
        and shape.status == "observed"
        and shape.raw_bytes >= rule.min_query_bytes
        and shape.has_literal_kv is False
        and (
            (shape.raw_non_utf8 is True and shape.percent_encoding == "invalid")
            or (
                shape.percent_encoding == "valid"
                and shape.decoded_non_utf8 is True
                and shape.decoded_control_count > 0
            )
        )
    )


def windows(
    pairs: list[tuple[NormalizedEvent, NormalizedEvent]], rule: R10Config
) -> list[tuple[int, int]]:
    if rule.version != "1.0.0":
        return bounded_windows(pairs, rule)
    # Preserve the archived development candidate's exact reproduction semantics.
    result, left, uids = [], 0, Counter()
    for right, (event, _) in enumerate(pairs):
        checkpoint()
        uids[event.network.uid] += 1
        while left <= right and span_bounds(pairs[left][0], event)[1] > rule.window_seconds:
            checkpoint()
            uid = pairs[left][0].network.uid
            uids[uid] -= 1
            if uids[uid] == 0:
                del uids[uid]
            left += 1
        if right - left + 1 < rule.min_requests or len(uids) < rule.min_connections:
            continue
        if (
            result
            and left <= result[-1][1]
            and span_bounds(pairs[result[-1][0]][0], event)[1] <= rule.window_seconds
        ):
            result[-1] = (result[-1][0], right)
        else:
            result.append((left, right))
    return result


def interval(event: NormalizedEvent) -> tuple:
    error = timedelta(milliseconds=event.time_quality.uncertainty_ms)
    return event.event_time - error, event.event_time + error


def bounded_windows(
    pairs: list[tuple[NormalizedEvent, NormalizedEvent]], rule: R10Config
) -> list[tuple[int, int]]:
    result, ranges, low, high = [], [], deque(), deque()
    left, uids = 0, Counter()
    for right, (event, _) in enumerate(pairs):
        checkpoint()
        lower, upper = interval(event)
        while low and low[-1][1] >= lower:
            checkpoint()
            low.pop()
        while high and high[-1][1] <= upper:
            checkpoint()
            high.pop()
        low.append((right, lower))
        high.append((right, upper))
        uids[event.network.uid] += 1
        while left <= right and (high[0][1] - low[0][1]).total_seconds() > rule.window_seconds:
            checkpoint()
            uid = pairs[left][0].network.uid
            uids[uid] -= 1
            if not uids[uid]:
                del uids[uid]
            left += 1
            while low and low[0][0] < left:
                low.popleft()
            while high and high[0][0] < left:
                high.popleft()
        if right - left + 1 < rule.min_requests or len(uids) < rule.min_connections:
            continue
        bounds = (low[0][1], high[0][1])
        merged = (
            (min(ranges[-1][0], bounds[0]), max(ranges[-1][1], bounds[1])) if ranges else bounds
        )
        if (
            result
            and left <= result[-1][1]
            and (merged[1] - merged[0]).total_seconds() <= rule.window_seconds
        ):
            result[-1] = (result[-1][0], right)
            ranges[-1] = merged
        else:
            result.append((left, right))
            ranges.append(bounds)
    return result


def detect_nontext_queries(
    events: list[NormalizedEvent], session_id: str, rule: R10Config
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
        for left, right in windows(pairs, rule):
            selected = pairs[left : right + 1]
            checkpoint(len(selected), size=len(selected) * 128)
            requests = [pair[0] for pair in selected]
            if rule.version == "1.0.0":
                lower, upper = span_bounds(requests[0], requests[-1])
            else:
                intervals = [interval(event) for event in requests]
                lower = max(
                    0.0,
                    (max(v[0] for v in intervals) - min(v[1] for v in intervals)).total_seconds(),
                )
                upper = (
                    max(v[1] for v in intervals) - min(v[0] for v in intervals)
                ).total_seconds()
            result.append(
                finding(
                    rule,
                    [event for pair in selected for event in pair],
                    session_id,
                    [*map(str, group[3:]), requests[0].event_id],
                    "nontext_http_query",
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
                        "非文本HTTP查询候选：重复异常字节形态不证明C&C、加密算法、恶意命令或执行",
                        "正常二进制遥测、旧编码或损坏日志也可能符合；缺响应内容与进程socket归属",
                        "失败或未知响应不代表成功控制；同一Host和端点不证明同一服务或操作者",
                        "只保留结构计数，不证明查询字节相同、用户身份或完整攻击链",
                    ],
                )
            )
    return result
