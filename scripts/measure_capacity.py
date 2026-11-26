"""Measure public synthetic detection scale and record the investigation limits.

This is engineering capacity evidence, not a formal labelled evaluation. It
does not import private archives or enable a model.
"""

import argparse
import json
import platform
import time
import tracemalloc
from datetime import UTC, datetime
from pathlib import Path

from packages.config import Settings
from packages.detection.limits import DetectionBudget
from packages.detection.registry import detect_all
from tests.contract.test_p1_scale import mixed_events


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--sizes", default="1000,10000,100000")
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit("refusing to overwrite capacity output")
    settings = Settings(_env_file=None)
    rows = []
    for size in [int(value) for value in args.sizes.split(",")]:
        events, session, _ = mixed_events(size)
        tracemalloc.start()
        started = time.perf_counter()
        with DetectionBudget() as budget:
            findings = detect_all(events, session)
        elapsed = time.perf_counter() - started
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        rows.append(
            {
                "input_events": size,
                "detection_seconds": round(elapsed, 3),
                "detection_peak_bytes": peak,
                "detection_work": budget.work,
                "finding_count": len(findings),
                "rule_ids": sorted({finding["rule_id"] for finding in findings}),
            }
        )
    result = {
        "created_at": datetime.now(UTC).isoformat(),
        "synthetic_engineering_only": True,
        "formal_evaluation": False,
        "model_enabled": False,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "limits": {
            "detection_event_limit": settings.detection_event_limit,
            "detection_finding_limit": settings.detection_finding_limit,
            "snapshot_event_limit": settings.snapshot_event_limit,
            "snapshot_scan_limit": settings.snapshot_scan_limit,
            "replay_event_limit": settings.replay_event_limit,
            "model_context_input_tokens": 12000,
            "agent_tool_calls": 6,
            "agent_model_calls": 4,
        },
        "rows": rows,
        "note": "detection scale and investigation snapshot scale are separate; not 100k end-to-end attribution",
    }
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()