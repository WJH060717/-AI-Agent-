"""Isolated UI regression with real API/worker; never uses a paid model."""

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
from scripts.browser_d3 import port, wait_for
from scripts.build_d9_fixture import build


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--grep")
    args = parser.parse_args()
    output = args.artifacts.resolve()
    output.mkdir(parents=True, exist_ok=False)
    private = ROOT / ".tools" / output.name
    private.mkdir(exist_ok=False)
    settings = benchmark_settings(private)
    assert settings.model_provider == "disabled"
    db = Database(settings)
    db.migrate()
    service = DataService(db, settings)
    workspace, tokens = service.init_workspace("UI synthetic regression")
    actor = service.system_actor(workspace)
    dataset = service.create_dataset(
        actor, {"name": "入门示例", "provenance_type": "synthetic"}, "seed"
    )
    records = b"".join(
        (
            json.dumps(
                {
                    "ts": 1794618000 + i,
                    "uid": f"ui-{i}",
                    "id.orig_h": "192.0.2.10",
                    "id.orig_p": 42000 + i,
                    "id.resp_h": "10.10.0.20",
                    "id.resp_p": i + 1,
                    "proto": "tcp",
                    "synthetic": True,
                }
            )
            + "\n"
        ).encode()
        for i in range(24)
    )
    service.stage_bytes(actor, dataset["dataset_id"], "zeek", "browser", "UTC", records, "source")
    service.process_one()
    db.engine.dispose()
    build(private / "fixtures")
    api_port, web_port = port(), port()
    env = process_environment(settings, api_port)
    env.update(
        TRACE_API_TARGET=f"http://127.0.0.1:{api_port}",
        D3_E2E_URL=f"http://127.0.0.1:{web_port}",
        D3_E2E_TOKEN=tokens["admin"],
        D9_E2E_VIEWER=tokens["viewer"],
        UI_DATASET=dataset["dataset_id"],
        UI_SESSION=dataset["default_session_id"],
        UI_FIXTURES=str(private / "fixtures" / "S1"),
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
                ([sys.executable, "-m", "apps.api.main"], private),
                ([sys.executable, "-m", "apps.worker"], private),
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
            command = [
                node,
                "node_modules/@playwright/test/cli.js",
                "test",
                "simple-workflow.spec.ts",
                "--output",
                str(output / "results"),
                "--reporter=list",
            ]
            if args.grep:
                command += ["--grep", args.grep]
            result = subprocess.run(
                command,
                cwd=ROOT / "apps/web",
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                encoding="utf-8",
                errors="replace",
                timeout=480,
                creationflags=flags,
            )
            # Trace files may contain the disposable test tokens; keep artifacts local.
            (output / "playwright.log").write_text(result.stdout, encoding="utf-8")
            (output / "result.json").write_text(
                json.dumps(
                    {
                        "exit_code": result.returncode,
                        "model_provider": "disabled",
                        "source_events": 24,
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
