"""Conservative periodic connection observations, never a C2 verdict."""

from bisect import bisect_left, bisect_right
from collections import defaultdict
from math import sqrt
from pathlib import Path
from statistics import mean, pstdev
from typing import Literal

from pydantic import Field

from packages.contracts.models import Contract, NormalizedEvent
from packages.detection.common import finding
from packages.detection.limits import checkpoint


class R05Config(Contract):
    id: Literal["R05"] = "R05"
    version: str = "1.0.0"
    window_seconds: int = Field(default=1200, ge=300, le=1200)
    min_connections: int = Field(default=8, ge=8, le=100)
    min_span_seconds: int = Field(default=300, ge=300, le=1200)
    max_cv: float = Field(default=0.15, ge=0, le=0.15, allow_inf_nan=False)
    max_episode_seconds: Literal[1800] = 1800


def config() -> R05Config:
    return R05Config.model_validate_json(
        (Path(__file__).resolve().parents[2] / "rules/R05.json").read_bytes()
    )


def _qualifying_windows(records: list[NormalizedEvent], rule: R05Config) -> list[tuple]:
    times = [e.event_time.timestamp() for e in records]
    errors = [e.time_quality.uncertainty_ms / 1000 for e in records]
    if not times:
        return []
    # Integer moments of the *same binary timestamps* avoid prefix cancellation.
    # This preserves the old timestamp subtraction, including sub-microsecond rounding.
    scale = max(t.as_integer_ratio()[1] for t in times)
    ticks = [int(t * scale) for t in times]
    squared, error_squared, barriers = [0], [0], [0]
    for i in range(1, len(records)):
        checkpoint()
        interval = ticks[i] - ticks[i - 1]
        error_ms = (
            records[i].time_quality.uncertainty_ms + records[i - 1].time_quality.uncertainty_ms
        )
        squared.append(squared[-1] + interval * interval)
        error_squared.append(error_squared[-1] + error_ms * error_ms)
        barriers.append(i if times[i] - times[i - 1] <= errors[i] + errors[i - 1] else barriers[-1])
    windows = []
    for right in range(rule.min_connections - 1, len(records)):
        checkpoint()
        first = max(barriers[right], bisect_left(times, times[right] - rule.window_seconds))
        last = min(
            right - rule.min_connections + 1,
            bisect_right(times, times[right] - rule.min_span_seconds, 0, right) - 1,
        )
        # Earliest qualifying left is the last hit of the previous reverse scan.
        # Inspect every eligible contiguous suffix until that hit; CV is not monotone.
        for left in range(first, last + 1):
            checkpoint()
            span = times[right] - times[left]
            lower_span = span - errors[left] - errors[right]
            if lower_span < rule.min_span_seconds:
                continue
            count = right - left
            total = ticks[right] - ticks[left]
            variance = count * (squared[right] - squared[left]) - total * total
            deviation = sqrt(max(0, variance)) / count / scale
            average = span / count
            error_mean = (error_squared[right] - error_squared[left]) / count / 1_000_000
            upper = (deviation + sqrt(error_mean)) / (lower_span / count)
            if abs(upper - rule.max_cv) < 1e-10:
                # Preserve historical decisions at the threshold using original Welford order.
                n, average, m2, err = 0, 0.0, 0.0, 0.0
                for k in range(right - 1, left - 1, -1):
                    checkpoint()
                    n += 1
                    interval = times[k + 1] - times[k]
                    delta = interval - average
                    average += delta / n
                    m2 += delta * (interval - average)
                    err += (errors[k + 1] + errors[k]) ** 2
                deviation = sqrt(max(0.0, m2 / count))
                upper = (deviation + sqrt(err / count)) / (lower_span / count)
            if upper <= rule.max_cv:
                windows.append(
                    (
                        left,
                        right,
                        {
                            "count": count + 1,
                            "mean_interval_seconds": average,
                            "cv": deviation / average,
                            "cv_upper": upper,
                            "span_seconds": span,
                            "span_lower_seconds": lower_span,
                        },
                    )
                )
                break
    return windows


def _witnesses(windows: list[tuple], records: list[NormalizedEvent]) -> list[dict]:
    """Deterministic interval cover, without every redundant sliding hit."""
    ordered = sorted(windows, key=lambda w: (w[0], -w[1]))
    covered, end, position = ordered[0][0], max(w[1] for w in ordered), 0
    witnesses = []
    while covered < end:
        best = None
        while position < len(ordered) and ordered[position][0] <= covered:
            item = ordered[position]
            if item[1] > covered and (best is None or item[1] > best[1]):
                best = item
            position += 1
        if best is None:
            raise ValueError("periodic window coverage is disconnected")
        witnesses.append(
            {
                "start_event_id": records[best[0]].event_id,
                "end_event_id": records[best[1]].event_id,
                **best[2],
            }
        )
        covered = best[1]
    return witnesses


def _episode_statistics(records: list[NormalizedEvent], witness_count: int) -> dict:
    times = [e.event_time.timestamp() for e in records]
    errors = [e.time_quality.uncertainty_ms / 1000 for e in records]
    intervals = [b - a for a, b in zip(times, times[1:], strict=False)]
    uncertainty = [a + b for a, b in zip(errors, errors[1:], strict=False)]
    average, deviation = mean(intervals), pstdev(intervals)
    span = times[-1] - times[0]
    lower = span - errors[0] - errors[-1]
    return {
        "count": len(records),
        "mean_interval_seconds": average,
        "cv": deviation / average,
        "cv_upper": (deviation + sqrt(mean([u * u for u in uncertainty])))
        / (lower / len(intervals)),
        "span_seconds": span,
        "span_lower_seconds": lower,
        "cv_semantics": "merged_episode_summary",
        "qualifying_window_count": witness_count,
    }


def detect_periodic(
    events: list[NormalizedEvent], session_id: str, rule: R05Config | None = None
) -> list[dict]:
    rule = rule or config()
    groups = defaultdict(list)
    for e in {e.event_id: e for e in events}.values():
        checkpoint()
        if (
            e.event_type != "network.connection"
            or not e.src
            or not e.dst
            or not e.network
            or e.dst.port is None
        ):
            continue
        # An ambiguous inventory lookup must not fall back to pretending this is a stable endpoint.
        if e.src.resolution_quality == "ambiguous" or e.dst.resolution_quality == "ambiguous":
            continue
        source = (
            str(e.src.asset_id)
            if e.src.asset_id and e.src.resolution_quality == "inventory_interval"
            else str(e.src.ip)
        )
        key = (
            str(e.workspace_id),
            str(e.dataset_id),
            e.sensor.observation_domain,
            e.sensor.sensor_id,
            e.sensor.instance_id,
            source,
            str(e.dst.ip),
            e.dst.port,
            e.network.transport,
        )
        groups[key].append(e)
    result = []
    for key, records in groups.items():
        checkpoint()
        ordered = sorted(records, key=lambda e: (e.event_time, e.event_id))
        episodes = []
        for window in sorted(_qualifying_windows(ordered, rule), key=lambda w: (w[0], w[1])):
            left, right, _ = window
            if (
                episodes
                and left <= episodes[-1][1]
                and (
                    ordered[max(right, episodes[-1][1])].event_time
                    - ordered[episodes[-1][0]].event_time
                ).total_seconds()
                < rule.max_episode_seconds
            ):
                episodes[-1][1] = max(episodes[-1][1], right)
                episodes[-1][2].append(window)
            else:
                episodes.append([left, right, [window]])
        for left, right, windows in episodes:
            members = ordered[left : right + 1]
            witnesses = _witnesses(windows, ordered)
            item = finding(
                rule,
                members,
                session_id,
                [*key[3:], members[0].event_id, members[-1].event_id],
                "periodic_connection",
                statistics=_episode_statistics(members, len(witnesses)),
                qualifying_windows=witnesses,
                interpretation="达标窗口合并的周期连接候选段；整体统计不等于单窗阈值；监控心跳也可符合，不能直接认定C2",
            )
            result.append(item)
    return sorted(result, key=lambda f: f["id"])
