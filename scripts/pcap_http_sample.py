"""Local PCAP-to-JSONL adapter. Explicit tuple scope; no labels or network calls."""

import argparse
import json
from pathlib import Path

from packages.ingest.pcap import MAX_CAPTURE, adapt


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pcap", type=Path, required=True)
    parser.add_argument(
        "--scope",
        type=Path,
        required=True,
        help="JSON array of [src_ip, src_port, dst_ip, dst_port]",
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.pcap.stat().st_size > MAX_CAPTURE or args.scope.stat().st_size > 262144:
        raise ValueError("input size limit")
    result = adapt(
        args.pcap.read_bytes(), {tuple(row) for row in json.loads(args.scope.read_bytes())}
    )
    args.output.mkdir(parents=True, exist_ok=False)
    for kind in ("pcap", "pcap_http"):
        (args.output / f"{kind}.jsonl").write_bytes(
            b"".join(json.dumps(row).encode() + b"\n" for row in result[kind])
        )
    (args.output / "provenance.json").write_text(
        json.dumps(
            {key: value for key, value in result.items() if key not in {"pcap", "pcap_http"}},
            indent=2,
        ),
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "connections": len(result["pcap"]),
                "http": len(result["pcap_http"]),
                "rejected": len(result["rejected"]),
            }
        )
    )


if __name__ == "__main__":
    main()
