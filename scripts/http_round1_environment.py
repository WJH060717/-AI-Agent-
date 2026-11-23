"""Disposable installed-image environment, with independent volumes and no models."""

import json
import secrets
import subprocess
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from scripts.browser_d3 import port, wait_for
from scripts.browser_installed_audit import PROD, command


@contextmanager
def isolated(
    output: Path, backend_override: str | None = None, frontend_override: str | None = None
) -> Iterator[dict]:
    backend = backend_override or command("docker", "inspect", "-f", "{{.Image}}", f"{PROD}-api-1")
    frontend = frontend_override or command(
        "docker", "inspect", "-f", "{{.Image}}", f"{PROD}-web-1"
    )
    postgres = command("docker", "inspect", "-f", "{{.Image}}", f"{PROD}-db-1")
    prefix = "trace-http-round1-" + secrets.token_hex(4)
    network, web_network = prefix + "-internal", prefix + "-webnet"
    data, pgdata = prefix + "-data", prefix + "-pg"
    containers: list[str] = []
    networks: list[str] = []
    password = secrets.token_hex(24)
    metadata = {
        "backend_image": backend,
        "frontend_image": frontend,
        "postgres_image": postgres,
        "model_provider": "disabled",
        "api_worker_network_internal": True,
        "test_volumes": [data, pgdata],
        "prefix": prefix,
    }
    (output / "environment.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    try:
        for name, internal in [(network, True), (web_network, False)]:
            command("docker", "network", "create", *(["--internal"] if internal else []), name)
            networks.append(name)
        for volume in [data, pgdata]:
            command(
                "docker", "volume", "create", "--label", "purpose=http-round1-isolated-test", volume
            )
        dbname = prefix + "-db"
        command(
            "docker",
            "run",
            "-d",
            "--pull=never",
            "--name",
            dbname,
            "--network",
            network,
            "--network-alias",
            "db",
            "-e",
            "POSTGRES_USER=trace_owner",
            "-e",
            "POSTGRES_DB=trace",
            "-e",
            f"POSTGRES_PASSWORD={password}",
            "-v",
            pgdata + ":/var/lib/postgresql/data",
            postgres,
        )
        containers.append(dbname)
        for _ in range(40):
            try:
                command("docker", "exec", dbname, "pg_isready", "-U", "trace_owner", "-d", "trace")
                break
            except RuntimeError:
                time.sleep(0.5)
        else:
            raise RuntimeError("isolated_database_not_ready")
        common = ["--network", network, "-v", data + ":/data"]
        for value in [
            f"DATABASE_URL=postgresql+psycopg://trace_owner:{password}@db/trace",
            "MODEL_PROVIDER=disabled",
            "APP_ENV=test",
            "APP_BIND=0.0.0.0",
            "RAW_STORE=/data/raw",
            "STAGING_STORE=/data/staging",
            "WORKER_POLL_SECONDS=0.05",
            "API_READ_REQUESTS_PER_MINUTE=6000",
            "API_WRITE_REQUESTS_PER_MINUTE=1000",
        ]:
            common += ["-e", value]
        init = (
            "import json; from packages.config import Settings; "
            "from packages.storage.database import Database; "
            "from packages.storage.service import DataService; "
            "s=Settings(); assert s.model_provider=='disabled' and s.model_api_key is None; "
            "d=Database(s); d.migrate(); "
            "workspace,tokens=DataService(d,s).init_workspace('CTU-13 isolated real sample'); "
            "print(json.dumps({'workspace_id':workspace,'tokens':tokens}))"
        )
        identity = json.loads(
            command(
                "docker", "run", "--rm", "--pull=never", *common, backend, "python", "-c", init
            ).splitlines()[-1]
        )
        for role, module in [("api", "apps.api.main"), ("worker", "apps.worker")]:
            name = prefix + "-" + role
            command(
                "docker",
                "run",
                "-d",
                "--pull=never",
                "--name",
                name,
                "--network-alias",
                role,
                *common,
                backend,
                "python",
                "-m",
                module,
            )
            containers.append(name)
        web_port = port()
        webname = prefix + "-web"
        command(
            "docker",
            "run",
            "-d",
            "--pull=never",
            "--name",
            webname,
            "--network",
            web_network,
            "--network",
            network,
            "-p",
            f"127.0.0.1:{web_port}:8080",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=32m,mode=1777",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            frontend,
        )
        containers.append(webname)
        url = f"http://127.0.0.1:{web_port}"
        wait_for(url + "/api/v1/health/live")
        yield {**metadata, **identity, "url": url}
    finally:
        for container in reversed(containers):
            assert container.startswith(prefix + "-")
            if container.endswith(("-api", "-worker")):
                logs = subprocess.run(
                    ["docker", "logs", container],
                    capture_output=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=30,
                )
                (output / f"{container.rsplit('-', 1)[1]}.log").write_text(
                    logs.stdout + logs.stderr, encoding="utf-8"
                )
            command("docker", "rm", "-f", container)
        for name in reversed(networks):
            command("docker", "network", "rm", name)
