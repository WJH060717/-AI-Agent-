"""Audit installed images against a fresh, isolated PostgreSQL dataset.

Never mounts production volumes. Production checks are READ ONLY fingerprints,
public health and static assets. Disposable credentials stay in process memory.
"""

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import time
from pathlib import Path
from urllib.request import urlopen

from scripts.browser_d3 import port, wait_for
from scripts.build_d9_fixture import build

ROOT = Path(__file__).resolve().parents[1]
PROD = "trace-p1-compose-01"


def command(*args: str, source: str | None = None) -> str:
    result = subprocess.run(
        list(args), input=source, capture_output=True, encoding="utf-8",
        errors="replace", timeout=180,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )
    if result.returncode:
        # Do not echo args: disposable credentials may be among them.
        raise RuntimeError(f"Command {args[0]} failed: {result.stderr[-3000:]}")
    return result.stdout.strip()


def production_fingerprint() -> str:
    tables = command("docker", "exec", f"{PROD}-db-1", "psql", "-U", "trace_owner",
                     "-d", "trace", "-At", "-c",
                     "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename")
    statements = ["BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;"]
    for table in tables.splitlines():
        assert re.fullmatch(r"[a-z_0-9]+", table)
        # Only a row count and aggregate digest leave the database, never values.
        statements.append(
            f"SELECT '{table}',count(*),encode(sha256(convert_to("
            "COALESCE(string_agg(h,'' ORDER BY h),''),'UTF8')),'hex') FROM "
            "(SELECT encode(sha256(convert_to(to_jsonb(t)::text,'UTF8')),'hex') h "
            f'FROM "{table}" t) q;'
        )
    statements.append("COMMIT;")
    return command("docker", "exec", "-i", f"{PROD}-db-1", "psql", "-U", "trace_owner",
                   "-d", "trace", "-At", "-v", "ON_ERROR_STOP=1", source="\n".join(statements))


SEED = '''import json
from packages.config import Settings
from packages.storage.database import Database
from packages.storage.service import DataService
s = Settings(); assert s.model_provider == "disabled" and s.model_api_key is None
d = Database(s); d.migrate(); service = DataService(d,s)
workspace,tokens = service.init_workspace("Isolated installed UI audit")
actor = service.system_actor(workspace)
dataset = service.create_dataset(actor,{"name":"入门示例","provenance_type":"synthetic"},"seed")
records = b"".join((json.dumps({"ts":1794618000+i,"uid":f"ui-{i}",
"id.orig_h":"192.0.2.10","id.orig_p":42000+i,"id.resp_h":"10.10.0.20",
"id.resp_p":i+1,"proto":"tcp","synthetic":True})+"\\n").encode() for i in range(24))
service.stage_bytes(actor,dataset["dataset_id"],"zeek","browser","UTC",records,"source")
service.process_one()
print(json.dumps({"tokens":tokens,"dataset":dataset}))
'''


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--grep")
    args = parser.parse_args()
    output = args.artifacts.resolve()
    output.mkdir(parents=True, exist_ok=False)
    private = ROOT / ".tools" / output.name
    private.mkdir(exist_ok=False)
    build(private / "fixtures")
    before = production_fingerprint()
    (output / "production-before.txt").write_text(before, encoding="utf-8")
    frontend = command("docker", "inspect", "-f", "{{.Image}}", f"{PROD}-web-1")
    backend = command("docker", "inspect", "-f", "{{.Image}}", f"{PROD}-api-1")
    assert backend == command("docker", "inspect", "-f", "{{.Image}}", f"{PROD}-worker-1")
    prefix = "trace-ui-audit-" + secrets.token_hex(4)
    network, data, pgdata = prefix + "-net", prefix + "-data", prefix + "-pg"
    web_network = prefix + "-web-net"
    created: list[str] = []
    net_created = False
    web_net_created = False
    result_code = 1
    try:
        command("docker", "network", "create", "--internal", network)
        net_created = True
        command("docker", "network", "create", web_network)
        web_net_created = True
        for volume in (data, pgdata):
            command("docker", "volume", "create", "--label", "purpose=isolated-ui-audit", volume)
        password = secrets.token_hex(24)
        dbname = prefix + "-db"
        command("docker", "run", "-d", "--pull=never", "--name", dbname,
                "--network", network, "--network-alias", "db",
                "-e", "POSTGRES_USER=trace_owner", "-e", "POSTGRES_DB=trace",
                "-e", f"POSTGRES_PASSWORD={password}", "-v", pgdata + ":/var/lib/postgresql/data",
                "postgres:16.16")
        created.append(dbname)
        for _ in range(40):
            try:
                command("docker", "exec", dbname, "pg_isready", "-U", "trace_owner", "-d", "trace")
                break
            except RuntimeError:
                time.sleep(0.5)
        else:
            raise RuntimeError("Isolated PostgreSQL did not become ready")
        common = ["--network", network, "-v", data + ":/data"]
        for value in [f"DATABASE_URL=postgresql+psycopg://trace_owner:{password}@db/trace",
                      "MODEL_PROVIDER=disabled", "APP_ENV=test", "APP_BIND=0.0.0.0",
                      "RAW_STORE=/data/raw", "STAGING_STORE=/data/staging",
                      "WORKER_POLL_SECONDS=0.05", "API_READ_REQUESTS_PER_MINUTE=6000",
                      "API_WRITE_REQUESTS_PER_MINUTE=1000"]:
            common += ["-e", value]
        seeded = json.loads(command("docker", "run", "--rm", "-i", "--pull=never",
                                    *common, backend, "python", "-", source=SEED).splitlines()[-1])
        for role, module in [("api", "apps.api.main"), ("worker", "apps.worker")]:
            name = prefix + "-" + role
            command("docker", "run", "-d", "--pull=never", "--name", name,
                    "--network-alias", role, *common, backend, "python", "-m", module)
            created.append(name)
        web_port = port()
        webname = prefix + "-web"
        command("docker", "run", "-d", "--pull=never", "--name", webname,
                "--network", web_network, "--network", network,
                "-p", f"127.0.0.1:{web_port}:8080",
                "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=32m,mode=1777",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", frontend)
        created.append(webname)
        url = f"http://127.0.0.1:{web_port}"
        wait_for(url + "/api/v1/health/live")
        pages = {}
        for label, base in [("production", "http://127.0.0.1:8080"), ("isolated", url)]:
            with urlopen(base, timeout=10) as response:
                html = response.read()
            assets = re.findall(r'(?:src|href)="(/assets/[^\"]+)"', html.decode())
            pages[label] = {"index": hashlib.sha256(html).hexdigest()}
            for asset in assets:
                with urlopen(base + asset, timeout=10) as response:
                    pages[label][asset] = hashlib.sha256(response.read()).hexdigest()
        assert pages["production"] == pages["isolated"]
        (output / "images-and-isolation.json").write_text(json.dumps({
            "frontend": frontend, "backend": backend, "backend_network_internal": True,
            "network": network, "retained_test_volumes": [data, pgdata],
            "model_provider": "disabled", "production_assets_equal": True, "assets": pages,
        }, indent=2), encoding="utf-8")
        env = os.environ.copy()
        env.update(D3_E2E_URL=url, D3_E2E_TOKEN=seeded["tokens"]["admin"],
                   D9_E2E_VIEWER=seeded["tokens"]["viewer"],
                   UI_DATASET=seeded["dataset"]["dataset_id"],
                   UI_SESSION=seeded["dataset"]["default_session_id"],
                   UI_FIXTURES=str(private / "fixtures/S1"),
                   UI_AUDIT_WORKER=prefix + "-worker", UI_AUDIT_DB=dbname,
                   TRACE_E2E_ARTIFACTS=str(output),
                   PLAYWRIGHT_BROWSERS_PATH=str(ROOT / ".tools/pw-browsers"))
        node = shutil.which("node")
        assert node
        test_command = [node, "node_modules/@playwright/test/cli.js", "test",
                        "simple-workflow.spec.ts", "installed-audit.spec.ts", "--output",
                        str(output / "results"), "--reporter=list"]
        if args.grep:
            test_command += ["--grep", args.grep]
        result = subprocess.run(test_command, cwd=ROOT / "apps/web", env=env,
                                capture_output=True, encoding="utf-8",
                                errors="replace", timeout=600)
        result_code = result.returncode
        (output / "playwright.log").write_text(result.stdout + result.stderr, encoding="utf-8")
        print(result.stdout.encode("ascii", errors="backslashreplace").decode())
        calls = command("docker", "exec", prefix + "-api", "python", "-c",
                        "from packages.config import Settings; "
                        "from packages.storage.database import Database; "
                        "from sqlalchemy import text; import json; d=Database(Settings()); "
                        "c=d.engine.connect(); "
                        "rows=c.execute(text('SELECT budget_used FROM agent_transitions')).all(); "
                        "print(json.dumps([r[0] for r in rows]))")
        (output / "isolated-model-budgets.json").write_text(calls, encoding="utf-8")
        for budget in json.loads(calls):
            if isinstance(budget, str):
                budget = json.loads(budget)
            assert budget.get("model_calls", 0) == 0
    finally:
        for container in reversed(created):
            # Generated exact names only; never targets any existing container.
            assert container.startswith(prefix + "-")
            if container.endswith("-worker"):
                subprocess.run(["docker", "unpause", container], capture_output=True)
            command("docker", "rm", "-f", container)
        if net_created:
            command("docker", "network", "rm", network)
        if web_net_created:
            command("docker", "network", "rm", web_network)
        after = production_fingerprint()
        (output / "production-after.txt").write_text(after, encoding="utf-8")
        (output / "result.json").write_text(json.dumps({
            "exit_code": result_code, "production_data_unchanged": before == after,
            "production_tables_checked": len(before.splitlines()) - 2,
            "paid_model_calls": 0, "model_provider": "disabled",
        }, indent=2), encoding="utf-8")
        assert before == after, "Production changed during audit; investigate concurrent writes"
    if result_code:
        raise RuntimeError("Browser audit failed; inspect preserved artifacts")


if __name__ == "__main__":
    main()
