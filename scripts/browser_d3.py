"""Disposable real-browser D3 smoke. Starts/stops only its own local child processes."""

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

from packages.config import Settings
from packages.storage.database import Database
from packages.storage.service import DataService

ROOT = Path(__file__).resolve().parents[1]


def port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for(url: str) -> None:
    for _ in range(120):
        try:
            with urllib.request.urlopen(url, timeout=1):
                return
        except OSError:
            time.sleep(0.2)
    raise RuntimeError(f"Local test service did not start: {url}")


def main() -> None:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--day4", action="store_true")
    group.add_argument("--day5", action="store_true")
    group.add_argument("--day6", action="store_true")
    group.add_argument("--day7", action="store_true")
    group.add_argument("--day8", action="store_true")
    group.add_argument("--day9", action="store_true")
    group.add_argument("--day11", action="store_true")
    parser.add_argument("--scenario", choices=["S1", "S2", "S3"])
    parser.add_argument(
        "--candidate", type=Path, help="Run D9 scenes from a verified native candidate"
    )
    parser.add_argument("--artifacts", type=Path, help="NEW evidence directory")
    args = parser.parse_args()
    day4, day5, day6 = args.day4, args.day5, args.day6
    day8 = args.day8
    day9 = args.day9
    day11 = args.day11
    if args.scenario and not day9:
        parser.error("--scenario requires --day9")
    if args.candidate and not (day9 or day11):
        parser.error("--candidate requires --day9 or --day11")
    service_root = args.candidate.resolve() if args.candidate else ROOT
    if args.candidate:
        from scripts.release_manifest import verify_manifest

        verify_manifest(service_root, json.loads((service_root / "freeze.json").read_bytes()))
    day7 = args.day7 or day8 or day9
    stub = None
    processes = []
    artifacts = ROOT / (
        "artifacts/d11-browser"
        if day11
        else "artifacts/d9-browser"
        if day9
        else "artifacts/d8-browser"
        if day8
        else "artifacts/d7-browser"
        if day7
        else "artifacts/d6-browser"
        if day6
        else "artifacts/d5-browser"
        if day5
        else "artifacts/d4-browser"
        if day4
        else "artifacts/d3-browser"
    )
    artifacts = args.artifacts.resolve() if args.artifacts else artifacts
    artifacts.mkdir(parents=True, exist_ok=args.artifacts is None)
    with tempfile.TemporaryDirectory(
        prefix="trace-d3-browser-", ignore_cleanup_errors=True
    ) as temporary:
        folder = Path(temporary)
        settings = Settings(
            _env_file=None,
            app_env="test",
            database_url=f"sqlite:///{folder / 'test.db'}",
            raw_store=folder / "raw",
            staging_store=folder / "staging",
        )
        tokens = {}
        if not args.candidate:
            database = Database(settings)
            database.migrate()
            _, tokens = DataService(database, settings).init_workspace("browser-smoke")
            database.engine.dispose()
        api_port, web_port = port(), port()
        raw = folder / "scan.jsonl"
        start = datetime(2026, 11, 14, 1, tzinfo=UTC).timestamp()
        raw.write_text(
            "".join(
                json.dumps(
                    {
                        "ts": start + i,
                        "uid": f"s{i}",
                        "id.orig_h": "192.0.2.10",
                        "id.orig_p": 42000 + i,
                        "id.resp_h": "10.10.0.20",
                        "id.resp_p": i + 1,
                        "proto": "tcp",
                        "synthetic": True,
                    }
                )
                + "\n"
                for i in range(24)
            ),
            encoding="utf-8",
        )
        env = os.environ.copy()
        env.update(
            DATABASE_URL=settings.database_url.get_secret_value(),
            RAW_STORE=str(settings.raw_store),
            STAGING_STORE=str(settings.staging_store),
            APP_ENV="test",
            MODEL_PROVIDER="disabled",
            APP_BIND="127.0.0.1",
            APP_PORT=str(api_port),
            TRACE_API_TARGET=f"http://127.0.0.1:{api_port}",
            D3_E2E_URL=f"http://127.0.0.1:{web_port}",
            D3_E2E_TOKEN=tokens.get("admin", ""),
            D9_E2E_VIEWER=tokens.get("viewer", ""),
            D3_E2E_FILE=str(raw),
            TRACE_E2E_ARTIFACTS=str(artifacts),
            PLAYWRIGHT_BROWSERS_PATH=str(ROOT / ".tools/pw-browsers"),
        )
        if day11:
            env["DETECTION_EVENT_LIMIT"] = "2"
        if day4:
            from scripts.build_d4_fixture import build

            build(folder / "d4")
            env["D4_E2E_DIR"] = str(folder / "d4")
        if day9:
            from scripts.build_d9_fixture import build

            build(folder / "d9")
            env["D6_E2E_DIR"] = str(folder / "d9/S1")
        if day5:
            from scripts.build_d5_fixture import build

            build(folder / "d5")
            env["D5_E2E_DIR"] = str(folder / "d5")
        if day6:
            from scripts.build_d6_fixture import build
            from scripts.model_stub import ProtocolStub

            build(folder / "d6")
            stub = ProtocolStub()
            stub_port = stub.start()
            env.update(
                D6_E2E_DIR=str(folder / "d6"),
                MODEL_PROVIDER="compatible",
                MODEL_BASE_URL=f"http://127.0.0.1:{stub_port}/v1",
                MODEL_NAME="protocol-test-stub",
                MODEL_API_KEY="local-browser-dummy",
                MODEL_TEST_STUB="true",
            )
        if day7:
            from scripts.build_d7_fixture import build
            from scripts.model_stub import ProtocolStub

            build(folder / "d7")
            stub = ProtocolStub()
            stub_port = stub.start()
            env.update(
                D7_E2E_DIR=str(folder / "d7"),
                MODEL_PROVIDER="compatible",
                MODEL_BASE_URL=f"http://127.0.0.1:{stub_port}/v1",
                MODEL_NAME="protocol-test-stub",
                MODEL_API_KEY="local-browser-dummy",
                MODEL_TEST_STUB="true",
            )
        flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        node = shutil.which("node")
        if node is None:
            raise RuntimeError("Node is required for the browser check")
        with (artifacts / "services.log").open("w", encoding="utf-8") as log:
            try:
                if args.candidate:
                    env.pop("PYTHONPATH", None)
                    env.update(
                        WEB_DIST=str(service_root / "apps/web/dist"),
                        D3_E2E_URL=f"http://127.0.0.1:{api_port}",
                    )
                    settings.raw_store.mkdir()
                    settings.staging_store.mkdir()
                    for command in ("migrate", "init-demo"):
                        initialized = subprocess.run(
                            [sys.executable, "-m", "apps.api.manage", command],
                            cwd=service_root,
                            env=env,
                            capture_output=True,
                            timeout=30,
                            creationflags=flags,
                        )
                        if initialized.returncode:
                            raise RuntimeError("CANDIDATE_INITIALIZATION_FAILED")
                        if command == "init-demo":
                            tokens = json.loads(initialized.stdout)["tokens_shown_once"]
                    env.update(D3_E2E_TOKEN=tokens["admin"], D9_E2E_VIEWER=tokens["viewer"])
                    checked = subprocess.run(
                        [sys.executable, "-m", "scripts.preflight"],
                        cwd=service_root,
                        env=env,
                        capture_output=True,
                        timeout=30,
                        creationflags=flags,
                    )
                    (artifacts / "preflight.json").write_bytes(checked.stdout)
                    if checked.returncode:
                        raise RuntimeError("CANDIDATE_PREFLIGHT_FAILED")
                commands = [
                    ([sys.executable, "-m", "apps.api.main"], service_root),
                    (
                        [
                            sys.executable,
                            "-m",
                            "apps.worker",
                            "--max-jobs",
                            "50"
                            if day9
                            else "4"
                            if day8
                            else "3"
                            if day7
                            else "5"
                            if day6
                            else "4"
                            if day4 or day5
                            else "2",
                        ],
                        service_root,
                    ),
                    (
                        [
                            node,
                            "node_modules/vite/bin/vite.js",
                            "--port",
                            str(web_port),
                            "--strictPort",
                        ],
                        ROOT / "apps/web",
                    ),
                ]
                if args.candidate:
                    commands = commands[:2]
                for command, cwd in commands:
                    processes.append(
                        subprocess.Popen(
                            command, cwd=cwd, env=env, stdout=log, stderr=log, creationflags=flags
                        )
                    )
                wait_for(f"http://127.0.0.1:{api_port}/api/v1/health/live")
                wait_for(env["D3_E2E_URL"])
                result = subprocess.run(
                    [
                        node,
                        "node_modules/@playwright/test/cli.js",
                        "test",
                        "d11.spec.ts"
                        if day11
                        else "d9.spec.ts"
                        if day9
                        else "d8.spec.ts"
                        if day8
                        else "d7.spec.ts"
                        if day7
                        else "d6.spec.ts"
                        if day6
                        else "d5.spec.ts"
                        if day5
                        else "d4.spec.ts"
                        if day4
                        else "d3.spec.ts",
                        *(["--grep", f"D9 {args.scenario}:"] if args.scenario else []),
                        "--output",
                        str(artifacts / "results"),
                    ],
                    cwd=ROOT / "apps/web",
                    env=env,
                    timeout=240 if day9 else 100,
                    creationflags=flags,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    encoding="utf-8",
                    errors="replace",
                )
                (artifacts / "playwright.log").write_text(result.stdout, encoding="utf-8")
                print(result.stdout.encode("ascii", errors="backslashreplace").decode("ascii"))
                if result.returncode:
                    raise RuntimeError(f"Browser smoke failed; see {artifacts}")
            finally:
                if stub is not None:
                    stub.stop()
                for process in reversed(processes):
                    if process.poll() is None:
                        if os.name == "nt":
                            subprocess.run(
                                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL,
                            )
                        else:
                            process.terminate()
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=5)


if __name__ == "__main__":
    main()
