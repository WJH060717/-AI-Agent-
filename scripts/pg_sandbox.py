"""Disposable local PostgreSQL integration runtime; never touches existing databases."""

import argparse
import json
import os
import secrets
import subprocess
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / ".tools/pg-sandbox.json"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["init", "start", "stop"])
    args = parser.parse_args()
    if args.action == "init":
        if MANIFEST.exists():
            raise RuntimeError("Sandbox exists; use start/stop, do not overwrite it")
        archive = ROOT / ".tools/postgresql-16.16-1.zip"
        # PostgreSQL's Windows bootstrap cannot handle this project's Chinese path.
        runtime = Path(tempfile.mkdtemp(prefix="telemetry-d2-pg-"))
        if not str(runtime).isascii():
            raise RuntimeError("PostgreSQL Windows test runtime requires ASCII temp path")
        with zipfile.ZipFile(archive) as source:
            members = [
                n
                for n in source.namelist()
                if n.startswith(("pgsql/bin/", "pgsql/lib/", "pgsql/share/"))
            ]
            source.extractall(runtime, members=members)
        password = secrets.token_urlsafe(32)
        (runtime / "password").write_text(password, encoding="ascii")
        subprocess.run(
            [
                str(runtime / "pgsql/bin/initdb.exe"),
                "-D",
                str(runtime / "data"),
                "-U",
                "trace_owner",
                "--pwfile=" + str(runtime / "password"),
                "-A",
                "scram-sha-256",
                "-E",
                "UTF8",
                "--locale=C",
            ],
            cwd=runtime,
            check=True,
        )
        MANIFEST.write_text(json.dumps({"runtime": str(runtime), "port": 55432}), encoding="utf-8")
        print("Disposable PostgreSQL initialized; credentials stay in ignored local files")
        return
    info = json.loads(MANIFEST.read_text(encoding="utf-8"))
    runtime = Path(info["runtime"])
    argv = [str(runtime / "pgsql/bin/pg_ctl.exe"), "-D", str(runtime / "data")]
    if args.action == "start":
        argv += [
            "-l",
            str(runtime / "server.log"),
            "-o",
            f"-h 127.0.0.1 -p {info['port']}",
            "-w",
            "start",
        ]
    else:
        argv += ["-w", "stop"]
    subprocess.run(argv, cwd=runtime, check=True, env=os.environ.copy())


if __name__ == "__main__":
    main()
