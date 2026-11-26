"""Validate the public experiment ledger without executing a formal evaluation."""

import argparse
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ledger", type=Path, default=Path("eval/current-ledger.json"))
    parser.add_argument("--runs", type=Path, default=Path("eval/runs.json"))
    args = parser.parse_args()
    ledger = json.loads(args.ledger.read_text(encoding="utf-8"))
    runs = json.loads(args.runs.read_text(encoding="utf-8"))["runs"]
    actual = {
        status: sum(run["status"] == status for run in runs)
        for status in {run["status"] for run in runs}
    }
    expected = {"planned": 33, "prepared": 3}
    if actual != expected:
        raise SystemExit(f"run status drift: {actual} != {expected}")
    if ledger["counts"]["planned"] != actual["planned"]:
        raise SystemExit("ledger planned count mismatch")
    if ledger["counts"]["prepared"] != actual["prepared"]:
        raise SystemExit("ledger prepared count mismatch")
    if any(ledger["counts"][stage] for stage in ("collected", "labeled", "reviewed", "run")):
        raise SystemExit("public ledger cannot claim completed private stages")
    if any(group["status"] != "not_run" for group in ledger["groups"].values()):
        raise SystemExit("B0-B3 cannot be marked run without archived predictions")
    print(json.dumps({"valid": True, "runs": actual, "stages": ledger["stages"]}))


if __name__ == "__main__":
    main()