"""Record real UI on a new D13 installation. Credentials remain in a private install log."""

import argparse
import json
import os
import shutil
import socket
import subprocess
import time
import urllib.request
from pathlib import Path

from scripts.deploy_d13 import load_install, python_at, runtime_env


def assert_available(port: int) -> None:
    with socket.socket() as listener:
        try:
            listener.bind(("127.0.0.1", port))
        except OSError as exc:
            raise ValueError("PORT_OCCUPIED") from exc


def assert_running(children: list[subprocess.Popen]) -> None:
    if any(child.poll() is not None for child in children):
        raise RuntimeError("OWN_SERVICE_EXITED")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--private-install-log", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--smoke", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    target = args.target.resolve()
    record = load_install(target)
    tokens = None
    for line in args.private_install_log.read_text(encoding="utf-8").splitlines():
        if line.startswith('{"workspace_id"'):
            tokens = json.loads(line)["tokens_shown_once"]
    if not tokens or not tokens.get("admin"):
        raise ValueError("PRIVATE_INITIAL_TOKEN_UNAVAILABLE")
    assert_available(record["port"])
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    env = runtime_env(target, record["port"])
    children = []
    streams = []
    node = None
    try:
        for service in ("apps.api.main", "apps.worker"):
            stream = (output / ("api.log" if service.endswith("main") else "worker.log")).open("xb")
            streams.append(stream)
            children.append(
                subprocess.Popen(
                    [str(python_at(target)), "-m", service],
                    cwd=target / "app",
                    env=env,
                    stdout=stream,
                    stderr=subprocess.STDOUT,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                )
            )
        url = f"http://127.0.0.1:{record['port']}"
        for _ in range(100):
            assert_running(children)
            try:
                startup = (output / "api.log").read_text(encoding="utf-8", errors="replace")
                if f"Uvicorn running on {url}" not in startup:
                    time.sleep(0.2)
                    continue
                with urllib.request.urlopen(url + "/api/v1/health/live", timeout=1):
                    break
            except OSError:
                time.sleep(0.2)
        else:
            raise RuntimeError("LOCAL_API_NOT_READY")
        node_env = os.environ.copy()
        node_env.update(
            D13_URL=url,
            D13_TOKEN=tokens["admin"],
            D13_TARGET=str(target),
            D13_OUTPUT=str(output),
            D13_ROOT=str(root),
            D13_SMOKE=str(int(args.smoke)),
            PLAYWRIGHT_BROWSERS_PATH=str(root / ".tools/pw-browsers"),
        )
        assert_running(children)
        node = subprocess.Popen(
            [shutil.which("node") or "node", str(root / "docs/d13-record.mjs")],
            cwd=root,
            env=node_env,
        )
        deadline = time.monotonic() + 650
        while node.poll() is None:
            assert_running(children)
            if time.monotonic() >= deadline:
                raise RuntimeError("RECORDING_TIMEOUT")
            time.sleep(0.25)
        assert_running(children)
        if node.returncode != 0:
            raise RuntimeError("BROWSER_RECORDING_FAILED")
        (output / "services.json").write_text(
            json.dumps(
                {
                    "own_startup_verified": True,
                    "liveness_monitored": True,
                    "api_pid": children[0].pid,
                    "worker_pid": children[1].pid,
                }
            )
            + "\n",
            encoding="utf-8",
        )
    finally:
        if node is not None and node.poll() is None:
            node.terminate()
            node.wait(timeout=10)
        for child in children:
            if child.poll() is None:
                child.terminate()
        for child in children:
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        for stream in streams:
            stream.close()


if __name__ == "__main__":
    main()
