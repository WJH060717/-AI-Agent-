"""Standard-library D13 installer. Also distributed verbatim as kit/deploy.py."""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath, PureWindowsPath

BASE_FREEZE = "9110dae9674ddedb75f08e538466df68ec9ff6e4b38eac5720f64fcd8ca11673"
VERSION = "d13-deployment-kit@1.0.0"


class DeployError(ValueError):
    pass


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: dict) -> str:
    return digest(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def no_links(path: Path) -> None:
    for item in (path, *path.parents):
        if item.is_symlink() or item.is_junction():
            raise DeployError("LINK_PATH_REFUSED")


def relative_file(root: Path, name: str) -> Path:
    path = PurePosixPath(name)
    if (
        not name
        or "\\" in name
        or PureWindowsPath(name).drive
        or path.is_absolute()
        or ".." in path.parts
        or path.as_posix() != name
        or any(ord(c) < 32 for c in name)
    ):
        raise DeployError("INVALID_PATH")
    return root / name


def safe_file(root: Path, name: str) -> Path:
    result = relative_file(root, name)
    no_links(result)
    if not result.resolve().is_relative_to(root.resolve()):
        raise DeployError("OUT_OF_SCOPE_PATH")
    return result


def file_records(root: Path, *, caches: bool = False) -> dict[str, dict]:
    no_links(root)
    records = {}
    for directory, folders, filenames in os.walk(root, followlinks=False):
        for name in folders + filenames:
            item = Path(directory) / name
            if item.is_symlink() or item.is_junction():
                raise DeployError("LINK_PATH_REFUSED")
        for filename in filenames:
            path = Path(directory) / filename
            relative = path.relative_to(root).as_posix()
            if caches and "__pycache__" in path.parts and path.suffix == ".pyc":
                continue
            records[relative] = {"sha256": digest(path.read_bytes()), "bytes": path.stat().st_size}
    return records


def verify_records(root: Path, records: dict, *, caches: bool = False) -> None:
    for name in records:
        relative_file(root, name)
    actual = file_records(root, caches=caches)
    if set(actual) != set(records):
        raise DeployError("FILE_SET_MISMATCH")
    if actual != records:
        raise DeployError("FILE_CHANGED")


def verify_base(app: Path) -> None:
    frozen = json.loads(safe_file(app, "freeze.json").read_bytes())
    if canonical(frozen) != BASE_FREEZE:
        raise DeployError("BASE_FREEZE_MISMATCH")
    actual = file_records(app, caches=True)
    allowed = set(frozen["files"]) | {
        "freeze.json",
        "version-manifest.json",
        "SHA256SUMS",
        "README-install.md",
    }
    if set(actual) != allowed:
        raise DeployError("BASE_FILE_SET_MISMATCH")
    for name, record in frozen["files"].items():
        relative_file(app, name)
        if actual.get(name) != {"sha256": record["sha256"], "bytes": record["bytes"]}:
            raise DeployError("BASE_FILE_CHANGED")


def verify_kit(kit: Path) -> dict:
    no_links(kit)
    manifest = json.loads((kit / "kit-manifest.json").read_bytes())
    if (
        manifest.get("version") != VERSION
        or manifest.get("base_freeze_sha256") != BASE_FREEZE
        or manifest.get("application_version") != "0.1.0.dev12"
    ):
        raise DeployError("KIT_VERSION_MISMATCH")
    records = dict(manifest["files"])
    records["kit-manifest.json"] = {
        "sha256": digest((kit / "kit-manifest.json").read_bytes()),
        "bytes": (kit / "kit-manifest.json").stat().st_size,
    }
    verify_records(kit, records)
    verify_base(kit / "app")
    return manifest


def process_env() -> dict[str, str]:
    # Do not inherit application settings, PYTHON*, PG*, proxy or pip configuration.
    allowed = {"PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "TEMP", "TMP", "HOME", "USERPROFILE"}
    env = {k: v for k, v in os.environ.items() if k.upper() in allowed}
    env.update(PYTHONIOENCODING="utf-8", PYTHONNOUSERSITE="1", PIP_CONFIG_FILE=os.devnull)
    return env


def runtime_env(target: Path, port: int) -> dict[str, str]:
    env = process_env()
    env.update(
        DATABASE_URL="sqlite:///" + (target / "data/demo.db").resolve().as_posix(),
        RAW_STORE=str((target / "data/raw").resolve()),
        STAGING_STORE=str((target / "data/staging").resolve()),
        WEB_DIST=str((target / "app/apps/web/dist").resolve()),
        APP_ENV="demo",
        APP_BIND="127.0.0.1",
        APP_PORT=str(port),
        MODEL_PROVIDER="disabled",
    )
    return env


def python_at(target: Path) -> Path:
    return target / (".venv/Scripts/python.exe" if os.name == "nt" else ".venv/bin/python")


def step(command: list[str], *, cwd: Path, env: dict[str, str]) -> None:
    try:
        subprocess.run(command, cwd=cwd, env=env, check=True, timeout=900)
    except (OSError, subprocess.SubprocessError) as exc:
        raise DeployError("STEP_FAILED_PARTIAL_TARGET_RETAINED") from exc


def install(kit: Path, target: Path, port: int, wheelhouse: Path | None = None) -> dict:
    if sys.version_info[:2] not in {(3, 12), (3, 13)}:
        raise DeployError("PYTHON_312_OR_313_REQUIRED")
    no_links(target)
    if target.exists():
        raise DeployError("TARGET_EXISTS")
    if not 1024 <= port <= 65535:
        raise DeployError("INVALID_PORT")
    target = target.absolute()
    kit = kit.absolute()
    if target.is_relative_to(kit) or kit.is_relative_to(target):
        raise DeployError("OVERLAPPING_PATH")
    manifest = verify_kit(kit)
    if wheelhouse is not None:
        no_links(wheelhouse)
        if not wheelhouse.is_dir():
            raise DeployError("WHEELHOUSE_MISSING")
    target.mkdir(parents=True, exist_ok=False)
    app = target / "app"
    app.mkdir()
    records = {
        k.removeprefix("app/"): v for k, v in manifest["files"].items() if k.startswith("app/")
    }
    for name in records:
        dest = safe_file(app, name)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(safe_file(kit / "app", name), dest)
    verify_records(app, records)
    for name in ("raw", "staging"):
        (target / "data" / name).mkdir(parents=True)
    env = runtime_env(target, port)
    step([sys.executable, "-m", "venv", str(target / ".venv")], cwd=target, env=process_env())
    python = str(python_at(target))
    pip = [python, "-m", "pip", "--isolated", "install", "--disable-pip-version-check"]
    if wheelhouse is not None:
        pip.extend(["--no-index", "--find-links", str(wheelhouse.resolve())])
    pip.extend(["--only-binary=:all:", "-r", "requirements-dev.lock"])
    step(pip, cwd=app, env=process_env())
    step([python, "-m", "pip", "check"], cwd=app, env=process_env())
    step([python, "-m", "apps.api.manage", "migrate"], cwd=app, env=env)
    # Inherits terminal only. Never capture role tokens in installation evidence.
    step([python, "-m", "apps.api.manage", "init-demo"], cwd=app, env=env)
    step([python, "-m", "scripts.preflight"], cwd=app, env=env)
    record = {
        "version": VERSION,
        "base_freeze_sha256": BASE_FREEZE,
        "port": port,
        "installed_at": datetime.now(UTC).isoformat(),
        "app_files": records,
    }
    (target / "installed.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    return record


def load_install(target: Path) -> dict:
    no_links(target)
    record = json.loads((target / "installed.json").read_bytes())
    if (
        set(record) != {"version", "base_freeze_sha256", "port", "installed_at", "app_files"}
        or record.get("version") != VERSION
        or record.get("base_freeze_sha256") != BASE_FREEZE
        or type(record.get("port")) is not int
        or not 1024 <= record["port"] <= 65535
    ):
        raise DeployError("INVALID_INSTALL_RECORD")
    verify_records(target / "app", record["app_files"], caches=True)
    verify_base(target / "app")
    for name in ("data/demo.db", "data/raw", "data/staging", ".venv"):
        no_links(target / name)
        if not (target / name).exists():
            raise DeployError("INCOMPLETE_INSTALL")
    return record


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["verify", "install", "run", "status"])
    parser.add_argument("--kit", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--target", type=Path)
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--wheelhouse", type=Path)
    parser.add_argument("--service", choices=["api", "worker"])
    args = parser.parse_args()
    try:
        if args.command == "verify":
            manifest = verify_kit(args.kit)
            print(
                json.dumps({"verified": True, "files": len(manifest["files"]), "base": BASE_FREEZE})
            )
            return
        if args.target is None:
            parser.error("--target required")
        target = args.target.absolute()
        if args.command == "install":
            install(args.kit, target, args.port, args.wheelhouse)
            print(
                json.dumps({"installed": True, "model": "disabled", "non_author_accepted": False})
            )
            return
        record = load_install(target)
        env = runtime_env(target, record["port"])
        module = "scripts.preflight"
        if args.command == "run":
            if args.service is None:
                parser.error("--service required for run")
            module = "apps.api.main" if args.service == "api" else "apps.worker"
        # Foreground service owns no unrelated processes; Ctrl+C terminates this child.
        child = subprocess.Popen(
            [str(python_at(target)), "-m", module], cwd=target / "app", env=env
        )
        try:
            code = child.wait()
        except KeyboardInterrupt:
            child.terminate()
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
            code = 130
        raise SystemExit(code)
    except (DeployError, OSError, ValueError, KeyError, TypeError) as exc:
        code = str(exc) if isinstance(exc, DeployError) else type(exc).__name__
        print(json.dumps({"ok": False, "error": code}), file=sys.stderr)
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
