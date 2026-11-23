"""Disposable real API/worker/browser replay acceptance; no external model."""

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from packages.storage.database import Database
from packages.storage.service import DataService
from scripts.benchmark_d11 import ROOT, benchmark_settings, process_environment, stop_process
from scripts.benchmark_p1_replay import source_records
from scripts.browser_d3 import port, wait_for


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts", type=Path, required=True)
    args = parser.parse_args()
    output = args.artifacts.resolve()
    output.mkdir(parents=True, exist_ok=False)
    private = ROOT / ".tools" / output.name
    private.mkdir(exist_ok=False)
    settings = benchmark_settings(private)
    settings.detection_event_limit = 100000
    db = Database(settings)
    db.migrate()
    service = DataService(db, settings)
    workspace, tokens = service.init_workspace("P1 scale browser synthetic")
    actor = service.system_actor(workspace)
    dataset = service.create_dataset(
        actor, {"name": "Replay 10001", "provenance_type": "synthetic"}, "d"
    )
    service.stage_bytes(
        actor, dataset["dataset_id"], "zeek", "browser", "UTC", source_records(10001), "source"
    )
    service.process_one()
    assert (
        service.overview(actor, dataset["dataset_id"], dataset["default_session_id"])[
            "detection_status"
        ]
        == "complete"
    )
    db.engine.dispose()
    api_port, web_port = port(), port()
    env = process_environment(settings, api_port)
    env.update(
        APP_PORT=str(api_port),
        TRACE_API_TARGET=f"http://127.0.0.1:{api_port}",
        D3_E2E_URL=f"http://127.0.0.1:{web_port}",
        D3_E2E_TOKEN=tokens["admin"],
        D9_E2E_VIEWER=tokens["viewer"],
        P1_DATASET=dataset["dataset_id"],
        P1_SOURCE_SESSION=dataset["default_session_id"],
        TRACE_E2E_ARTIFACTS=str(output),
        PLAYWRIGHT_BROWSERS_PATH=str(ROOT / ".tools/pw-browsers"),
    )
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    node = shutil.which("node")
    assert node
    processes = []
    with (output / "services.log").open("w", encoding="utf-8") as log:
        try:
            for command, cwd in [
                ([sys.executable, "-m", "apps.api.main"], ROOT),
                ([sys.executable, "-m", "apps.worker"], ROOT),
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
            ]:
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
                    "p1-scale.spec.ts",
                    "--output",
                    str(output / "results"),
                ],
                cwd=ROOT / "apps/web",
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                encoding="utf-8",
                errors="replace",
                timeout=240,
                creationflags=flags,
            )
            (output / "playwright.log").write_text(result.stdout, encoding="utf-8")
            (output / "result.json").write_text(
                json.dumps(
                    {
                        "exit_code": result.returncode,
                        "source_events": 10001,
                        "model_provider": "disabled",
                    }
                ),
                encoding="utf-8",
            )
            print(result.stdout.encode("ascii", errors="backslashreplace").decode("ascii"))
            if result.returncode:
                raise RuntimeError("Browser verification failed")
        finally:
            for process in reversed(processes):
                stop_process(process)


if __name__ == "__main__":
    main()
