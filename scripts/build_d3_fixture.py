"""Safe synthetic R01 development fixtures, never a test-set performance claim."""

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path


def main() -> None:
    root = Path("data/fixtures/d3")
    root.mkdir(parents=True, exist_ok=True)
    start = datetime(2026, 11, 14, 1, tzinfo=UTC).timestamp()
    objects = []
    for name, count, vary in (
        ("port_scan", 24, True),
        ("below_threshold", 19, True),
        ("normal_repeated_service", 24, False),
    ):
        content = b"".join(
            (
                json.dumps(
                    {
                        "ts": start + i,
                        "uid": f"synthetic-{name}-{i}",
                        "id.orig_h": "192.0.2.10",
                        "id.orig_p": 42000 + i,
                        "id.resp_h": "10.10.0.20",
                        "id.resp_p": i + 1 if vary else 22,
                        "proto": "tcp",
                        "synthetic": True,
                    }
                )
                + "\n"
            ).encode()
            for i in range(count)
        )
        path = root / f"{name}.jsonl"
        path.write_bytes(content)
        objects.append(
            {"path": path.name, "sha256": hashlib.sha256(content).hexdigest(), "records": count}
        )
    (root / "manifest.json").write_text(
        json.dumps(
            {
                "provenance_type": "synthetic",
                "split": "development",
                "scope": "local data generation only; no network scanning performed",
                "objects": objects,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print("Generated 3 synthetic D3 development files; use separate datasets for counterexamples")


if __name__ == "__main__":
    main()
