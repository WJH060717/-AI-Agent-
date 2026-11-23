"""Run actual, version-bound D10 checks; full P0 readiness is a separate strict gate."""

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from scripts.d10_gate import GateError, evaluate, record_check
from scripts.release_manifest import (
    build_candidate,
    encoded,
    manifest_digest,
    verify_manifest,
    write_new,
)


def run_check(
    root: Path,
    name: str,
    command: list[str],
    log: Path,
    frozen: str,
    *,
    outputs: list[Path] | None = None,
) -> dict:
    started = datetime.now(UTC).isoformat()
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    with log.open("xb") as stream:
        process = subprocess.Popen(
            command,
            cwd=root,
            env=env,
            stdout=stream,
            stderr=subprocess.STDOUT,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            start_new_session=os.name != "nt",
        )
        try:
            code = process.wait(timeout=2000 if name == "benchmark" else 1200)
        except subprocess.TimeoutExpired:
            if os.name == "nt":
                subprocess.run(
                    ["taskkill", "/PID", str(process.pid), "/T", "/F"], capture_output=True
                )
            else:
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=10)
            stream.write(b"\nD10_CHECK_TIMEOUT\n")
            code = 124
    result = record_check(name, command, code, log, frozen, started, outputs=outputs)
    print(f"{name}: exit {code}", flush=True)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--freeze", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="NEW evidence directory")
    parser.add_argument("--postgres", action="store_true")
    parser.add_argument("--browser", action="store_true")
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--benchmark", type=Path, help="Completed D11 full benchmark directory")
    parser.add_argument("--analysis-input", type=Path, help="D12 immutable offline input manifest")
    parser.add_argument("--require-release", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    try:
        frozen = json.loads(args.freeze.read_bytes())
        verify_manifest(root, frozen)
        stage = frozen["version"].split("-")[0]
        if stage == "d11" and args.benchmark is None:
            raise GateError("D11_BENCHMARK_REQUIRED")
        if stage == "d12" and args.analysis_input is None:
            raise GateError("D12_ANALYSIS_INPUT_REQUIRED")
        output.mkdir(parents=True, exist_ok=False)
        identity = manifest_digest(frozen)
        python = sys.executable
        npm = shutil.which("npm.cmd" if os.name == "nt" else "npm")
        if npm is None:
            raise GateError("NPM_NOT_AVAILABLE")
        junit = output / "pytest.xml"
        commands = [
            ("contracts", [python, "-m", "scripts.export_contracts"], root),
            ("python", [python, "-m", "pytest", "-q", "--tb=short", f"--junitxml={junit}"], root),
            ("ruff", [python, "-m", "ruff", "check", "."], root),
            ("format", [python, "-m", "ruff", "format", "--check", "."], root),
            ("dependencies", [python, "-m", "pip", "check"], root),
            ("versions", [python, "-m", "scripts.verify_environment"], root),
            *[
                (name, [npm, "run", name], root / "apps/web")
                for name in ("typegen", "typecheck", "lint", "build")
            ],
            ("inventory", [python, "-m", "eval.freeze"], root),
        ]
        if args.postgres:
            commands.append(("postgres", [python, "-m", "scripts.test_postgres"], root))
        experiment = output / "evaluation"
        evaluation_files = [
            experiment / name
            for name in (
                "config.json",
                "preflight.json",
                "manifest.json",
                "predictions.jsonl",
                "metrics.json",
            )
        ]
        bound_outputs = {"python": [junit]}
        if stage in {"d11", "d12"}:
            commands.extend(
                [
                    (
                        "evaluation",
                        [
                            python,
                            "-m",
                            "eval.run",
                            "--config",
                            "eval/configs/d11-engineering.json",
                            "--output",
                            str(experiment),
                        ],
                        root,
                    ),
                    (
                        "evaluation_verify",
                        [
                            python,
                            "-m",
                            "scripts.d11_evidence",
                            "evaluation",
                            "--input",
                            str(experiment),
                            "--output",
                            str(output / "evaluation-verified.json"),
                        ],
                        root,
                    ),
                    (
                        "benchmark",
                        [
                            python,
                            "-m",
                            "scripts.d11_evidence",
                            "benchmark",
                            "--input",
                            str(args.benchmark.resolve()) if args.benchmark else "unused",
                            "--wait-seconds",
                            "1900",
                            "--output",
                            str(output / "benchmark-verified.json"),
                        ],
                        root,
                    ),
                ]
            )
            bound_outputs.update(
                {
                    "evaluation": evaluation_files,
                    "evaluation_verify": [*evaluation_files, output / "evaluation-verified.json"],
                    "benchmark": [
                        *(
                            (args.benchmark or Path("unused")) / name
                            for name in ("protocol.json", "samples.jsonl", "summary.json")
                        ),
                        output / "benchmark-verified.json",
                    ],
                }
            )
        if stage == "d12":
            commands = [entry for entry in commands if entry[0] != "benchmark"]
            commands.extend(
                [
                    (
                        "recovery",
                        [
                            python,
                            "-m",
                            "scripts.recovery_d12",
                            "--output",
                            str(output / "recovery"),
                        ],
                        root,
                    ),
                    (
                        "analysis",
                        [
                            python,
                            "-m",
                            "eval.analysis_d12",
                            "--manifest",
                            str(args.analysis_input.resolve()),
                            "--output",
                            str(output / "analysis"),
                        ],
                        root,
                    ),
                ]
            )
            bound_outputs["recovery"] = [output / "recovery/recovery.json"]
        records = []
        for name, command, cwd in commands:
            result = run_check(
                cwd,
                name,
                command,
                output / f"{name}.log",
                identity,
                outputs=bound_outputs.get(name),
            )
            records.append(result)
            if name == "analysis" and result["exit_code"] == 0:
                # Files exist only after rendering. Bind all assets and the original inputs.
                from packages.storage.service import file_digest

                paths = [p for p in (output / "analysis").iterdir() if p.is_file()]
                source_manifest = json.loads((output / "analysis/inputs.json").read_bytes())
                paths.extend(root / n for n in source_manifest["files"])
                result["outputs"] = {str(p.resolve()): file_digest(p) for p in paths}
            if result["exit_code"]:
                break
        verify_manifest(root, frozen)
        if args.browser and all(r["exit_code"] == 0 for r in records):
            candidate = args.candidate.resolve() if args.candidate else output / "candidate"
            if args.candidate:
                verify_manifest(candidate, frozen)
            else:
                build_candidate(root, frozen, candidate)
            browser_commands = [
                (
                    "browser_d8",
                    [
                        python,
                        "-m",
                        "scripts.browser_d3",
                        "--day8",
                        "--artifacts",
                        str(output / "browser-d8"),
                    ],
                ),
                (
                    "browser_native",
                    [
                        python,
                        "-m",
                        "scripts.browser_d3",
                        "--day9",
                        "--candidate",
                        str(candidate),
                        "--artifacts",
                        str(output / "browser"),
                    ],
                ),
            ]
            if stage in {"d11", "d12"}:
                browser_commands.append(
                    (
                        "browser_d11",
                        [
                            python,
                            "-m",
                            "scripts.browser_d3",
                            "--day11",
                            "--candidate",
                            str(candidate),
                            "--artifacts",
                            str(output / "browser-d11"),
                        ],
                    )
                )
            for name, command in browser_commands:
                records.append(run_check(root, name, command, output / f"{name}.log", identity))
                if records[-1]["exit_code"]:
                    break
            verify_manifest(candidate, frozen)
        verify_manifest(root, frozen)
        write_new(output / "checks.json", encoded({"freeze_sha256": identity, "checks": records}))
        result = evaluate(root, identity, records, junit, stage=stage)
        write_new(output / "gate.json", encoded(result))
        print(json.dumps(result, ensure_ascii=False, indent=2))
        if not result["engineering_passed"]:
            raise SystemExit(1)
        if args.require_release and not result["p0_release_ready"]:
            raise SystemExit(2)
    except (ValueError, OSError, KeyError) as exc:
        parser.exit(1, f"D10_CHECK_FAILED:{type(exc).__name__}\n")


if __name__ == "__main__":
    main()
