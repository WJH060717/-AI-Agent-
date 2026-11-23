"""D12 recovery/analysis evidence checks on bound local outputs."""

import json
from pathlib import Path

from eval.analysis_d12 import verify_analysis
from scripts.d10_gate import CheckRecord, GateError

ROOT = Path(__file__).resolve().parents[1]


def check_d12_experiments(records: list[CheckRecord]) -> None:
    for record in records:
        if record.name not in {"analysis", "recovery"} or record.exit_code:
            continue
        outputs = {Path(n).name: Path(n) for n in record.outputs}
        if record.name == "recovery":
            if "recovery.json" not in outputs:
                raise GateError("RECOVERY_OUTPUT_UNBOUND")
            data = json.loads(outputs["recovery.json"].read_bytes())
            if (
                data.get("version") != "d12-recovery@1.0.0"
                or data.get("engine") != "postgresql"
                or any(
                    data.get(k) is not True
                    for k in (
                        "verified",
                        "old_report_unchanged",
                        "new_investigation_completed",
                        "token_and_hmac_preserved",
                    )
                )
                or data.get("tables_verified") != 28
                or data.get("reports_verified", 0) < 1
                or data.get("events_verified", 0) < 1
                or data.get("private_backup_distributed") is not False
                or data.get("non_author_accepted") is not False
                or data.get("concurrent_writer_blocked") is not True
                or data.get("negatives")
                != {
                    "existing_source_rejected": True,
                    "existing_target_rejected": True,
                    "nonempty_database_with_new_directories_rejected": True,
                }
            ):
                raise GateError("RECOVERY_EVIDENCE_INCOMPLETE")
        else:
            if record.command.count("--output") != 1:
                raise GateError("ANALYSIS_OUTPUT_UNBOUND")
            position = record.command.index("--output") + 1
            if position >= len(record.command):
                raise GateError("ANALYSIS_OUTPUT_UNBOUND")
            folder = Path(record.command[position]).resolve()
            if (
                not {
                    str(folder / name)
                    for name in (
                        "inputs.json",
                        "manifest.json",
                        "summary.json",
                        "index.html",
                        "resources.svg",
                        "metrics.csv",
                    )
                }
                <= record.outputs.keys()
            ):
                raise GateError("ANALYSIS_OUTPUT_UNBOUND")
            config = json.loads((folder / "inputs.json").read_bytes())
            frozen_inputs = json.loads((ROOT / "eval/d12-inputs.json").read_bytes())
            if config != frozen_inputs:
                raise GateError("ANALYSIS_EVIDENCE_ROSTER_MISMATCH")
            manifest = json.loads((folder / "manifest.json").read_bytes())
            if not {str((folder / n).resolve()) for n in manifest["files"]} <= set(record.outputs):
                raise GateError("ANALYSIS_OUTPUT_UNBOUND")
            verify_analysis(ROOT, folder)
            # Historical inputs deliberately retain their original basenames.
            # Only the manifest's own output directory identifies rendered results.
            summary = json.loads((folder / "summary.json").read_bytes())
            if (
                not summary["evaluations"]
                or not summary["benchmarks"]
                or not config["screenshots"]
                or any(
                    g["attempts"] == 0 for e in summary["evaluations"] for g in e["groups"].values()
                )
                or any(
                    not b["resource_series"]
                    or all(r["working_set_bytes"] is None for r in b["resource_series"])
                    for b in summary["benchmarks"]
                )
            ):
                raise GateError("ANALYSIS_EVIDENCE_INCOMPLETE")
