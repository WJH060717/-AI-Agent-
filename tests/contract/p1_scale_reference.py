from math import sqrt

from packages.contracts.models import NormalizedEvent
from packages.detection.r05 import R05Config


def legacy_windows(records: list[NormalizedEvent], rule: R05Config) -> list[tuple]:
    times = [e.event_time.timestamp() for e in records]
    errors = [e.time_quality.uncertainty_ms / 1000 for e in records]
    windows = []
    for right in range(rule.min_connections - 1, len(records)):
        count, average, m2, error_squared = 0, 0.0, 0.0, 0.0
        best = None
        # CV is not monotone: inspect contiguous suffixes without deleting interior records.
        for left in range(right - 1, -1, -1):
            span = times[right] - times[left]
            if span > rule.window_seconds:
                break
            interval = times[left + 1] - times[left]
            error = errors[left + 1] + errors[left]
            if interval <= error:
                break
            count += 1
            delta = interval - average
            average += delta / count
            m2 += delta * (interval - average)
            error_squared += error * error
            lower_span = span - errors[left] - errors[right]
            if count + 1 < rule.min_connections or lower_span < rule.min_span_seconds:
                continue
            deviation = sqrt(max(0.0, m2 / count))
            upper = (deviation + sqrt(error_squared / count)) / (lower_span / count)
            if upper <= rule.max_cv:
                best = (
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
        if best:
            windows.append(best)
    return windows
