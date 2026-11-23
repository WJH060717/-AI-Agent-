"""Standard-library offline installer/empty-target recovery around the fixed D13 kit."""

import argparse
import hashlib
import importlib.util
import json
import platform
import re
import shutil
import subprocess
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

VERSION = "d14-offline@1.0.0"
HELPER_SHA = "7c9401212d7f00d803fdfd84dde9dc763e897e81c94cefe823a3413e1164bd7b"
KIT_SHA = "c76e4a767289bd4527843db2864b9d0981ede9cf4f16fc2c82bcd20e85577344"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def no_links(path: Path) -> None:
    if any(p.is_symlink() or p.is_junction() for p in (path, *path.parents)):
        raise ValueError("LINK_PATH_REFUSED")


def helper(bundle: Path):
    path = bundle / "tools/deploy_d13.py"
    no_links(path)
    if sha(path) != HELPER_SHA:
        raise ValueError("HELPER_CHANGED")
    spec = importlib.util.spec_from_file_location("d14_frozen_deploy", path)
    module = importlib.util.module_from_spec(spec)
    previous = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module


def platform_key() -> str:
    return (
        "win-amd64-cp313"
        if sys.platform == "win32"
        and sys.version_info[:2] == (3, 13)
        and platform.machine().lower() in {"amd64", "x86_64"}
        else "unsupported"
    )


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def hashed_requirements(wheels: dict) -> str:
    return "".join(
        f"{name}=={entry['version']} --hash=sha256:{entry['sha256']}\n"
        for name, entry in sorted(wheels.items())
    )


def verify(bundle: Path) -> dict:
    frozen = helper(bundle)
    path = frozen.safe_file(bundle, "offline-manifest.json")
    manifest = json.loads(path.read_bytes())
    if manifest.get("version") != VERSION or manifest.get("platform") != "win-amd64-cp313":
        raise ValueError("INVALID_OFFLINE_MANIFEST")
    records = dict(manifest["files"])
    records["offline-manifest.json"] = {"sha256": sha(path), "bytes": path.stat().st_size}
    frozen.verify_records(bundle, records)
    if sha(bundle / "kit/kit-manifest.json") != KIT_SHA:
        raise ValueError("D13_KIT_CHANGED")
    frozen.verify_kit(bundle / "kit")
    required = {}
    for line in (bundle / "kit/app/requirements-dev.lock").read_text().splitlines():
        if "==" in line:
            name, version = line.split("==")
            required[normalize(name)] = version
    wheels = manifest["wheels"]
    if {name: entry["version"] for name, entry in wheels.items()} != required:
        raise ValueError("WHEEL_ROSTER_MISMATCH")
    actual = set(p.name for p in (bundle / "wheels").iterdir())
    expected = set()
    for entry in wheels.values():
        name = entry["filename"]
        if Path(name).name != name or not name.endswith(".whl"):
            raise ValueError("WHEEL_PATH_INVALID")
        path = frozen.safe_file(bundle, "wheels/" + name)
        if sha(path) != entry["sha256"]:
            raise ValueError("WHEEL_HASH_MISMATCH")
        expected.add(name)
    if actual != expected or (
        bundle / "requirements-hashed.txt"
    ).read_text() != hashed_requirements(wheels):
        raise ValueError("WHEEL_LOCK_MISMATCH")
    return manifest


def pip_arguments(bundle: Path, target: Path) -> list[str]:
    return [
        "--isolated",
        "install",
        "--disable-pip-version-check",
        "--no-index",
        "--no-cache-dir",
        "--require-hashes",
        "--only-binary=:all:",
        "--find-links",
        str((bundle / "wheels").resolve()),
        "-r",
        str((bundle / "requirements-hashed.txt").resolve()),
    ]


def command(bundle: Path, target: Path, module: str, arguments: list[str]) -> list[str]:
    frozen = helper(bundle)
    return [
        str(frozen.python_at(target)),
        "-I",
        str((bundle / "tools/network_guard.py").resolve()),
        "--app",
        str(target / "app"),
        "--audit",
        str(target / f"guard-{uuid.uuid4()}.jsonl"),
        "--module",
        module,
        "--",
        *arguments,
    ]


def step(arguments: list[str], cwd: Path, env: dict[str, str]) -> None:
    try:
        subprocess.run(arguments, cwd=cwd, env=env, check=True, timeout=900)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError("STEP_FAILED_PARTIAL_TARGET_RETAINED") from exc


def prepare(bundle: Path, target: Path, port: int) -> dict:
    no_links(target)
    if target.exists():
        raise ValueError("TARGET_EXISTS")
    if platform_key() != "win-amd64-cp313":
        raise ValueError("PLATFORM_REQUIRES_WINDOWS_X64_CPYTHON313")
    if not 1024 <= port <= 65535:
        raise ValueError("INVALID_PORT")
    if target.resolve().is_relative_to(bundle.resolve()) or bundle.resolve().is_relative_to(
        target.resolve()
    ):
        raise ValueError("OVERLAPPING_PATH")
    verify(bundle)
    frozen = helper(bundle)
    records = frozen.file_records(bundle / "kit/app")
    target.mkdir(parents=True, exist_ok=False)
    shutil.copytree(bundle / "kit/app", target / "app")
    frozen.verify_records(target / "app", records)
    step([sys.executable, "-m", "venv", str(target / ".venv")], target, frozen.process_env())
    step(
        command(bundle, target, "pip", pip_arguments(bundle, target)),
        target / "app",
        frozen.process_env(),
    )
    step(command(bundle, target, "pip", ["check"]), target / "app", frozen.process_env())
    return {
        "version": frozen.VERSION,
        "base_freeze_sha256": frozen.BASE_FREEZE,
        "installed_at": datetime.now(UTC).isoformat(),
        "port": port,
        "app_files": records,
    }


def provision(bundle: Path, target: Path, port: int, backup: Path | None = None) -> None:
    bundle, target = bundle.absolute(), target.absolute()
    if backup is not None:
        no_links(backup)
        if backup.resolve().is_relative_to(target.resolve()) or target.resolve().is_relative_to(
            backup.resolve()
        ):
            raise ValueError("BACKUP_PATH_OVERLAP")
        payload = json.loads((backup / "manifest.json").read_bytes())
        if payload.get("engine") != "sqlite" or payload.get("application_version") != "0.1.0.dev12":
            raise ValueError("RESTORE_REQUIRES_SAME_VERSION_SQLITE")
    record = prepare(bundle, target, port)
    frozen = helper(bundle)
    env = frozen.runtime_env(target, port)
    if backup is None:
        for name in ("raw", "staging"):
            (target / "data" / name).mkdir(parents=True)
        step(command(bundle, target, "apps.api.manage", ["migrate"]), target / "app", env)
        step(command(bundle, target, "scripts.preflight", []), target / "app", env)
        step(command(bundle, target, "apps.api.manage", ["init-demo"]), target / "app", env)
    else:
        step(
            command(
                bundle, target, "scripts.backup", ["restore", "--folder", str(backup.resolve())]
            ),
            target / "app",
            env,
        )
        step(command(bundle, target, "scripts.preflight", []), target / "app", env)
    with (target / "installed.json").open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(record, indent=2) + "\n")


def backup_arguments(bundle: Path, target: Path, folder: Path) -> list[str]:
    for path in (bundle, target, folder):
        no_links(path)
    destination = folder.resolve()
    for protected in (bundle.resolve(), (target / "app").resolve()):
        if destination.is_relative_to(protected) or protected.is_relative_to(destination):
            raise ValueError("BACKUP_PUBLIC_OR_APPLICATION_PATH_REFUSED")
    return ["create", "--folder", str(folder.absolute())]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action", choices=["verify", "install", "restore", "run", "status", "backup"]
    )
    parser.add_argument("--bundle", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--target", type=Path)
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--backup", type=Path)
    parser.add_argument("--service", choices=["api", "worker"])
    args = parser.parse_args()
    try:
        bundle = args.bundle.absolute()
        manifest = verify(bundle)
        if args.action == "verify":
            print(
                json.dumps(
                    {
                        "verified": True,
                        "wheels": len(manifest["wheels"]),
                        "platform": manifest["platform"],
                    }
                )
            )
            return
        if args.target is None:
            parser.error("--target required")
        target = args.target.absolute()
        if args.action in {"install", "restore"}:
            if args.action == "restore" and args.backup is None:
                parser.error("--backup required")
            provision(bundle, target, args.port, args.backup if args.action == "restore" else None)
            print(
                json.dumps(
                    {"installed": True, "model": "disabled", "restored": args.action == "restore"}
                )
            )
            return
        frozen = helper(bundle)
        record = frozen.load_install(target)
        module, arguments = "scripts.preflight", []
        if args.action == "run":
            if args.service is None:
                parser.error("--service required")
            module = "apps.api.main" if args.service == "api" else "apps.worker"
        elif args.action == "backup":
            if args.backup is None:
                parser.error("--backup required")
            module, arguments = (
                "scripts.backup",
                backup_arguments(bundle, target, args.backup),
            )
        process = subprocess.Popen(
            command(bundle, target, module, arguments),
            cwd=target / "app",
            env=frozen.runtime_env(target, record["port"]),
        )
        try:
            code = process.wait()
        except KeyboardInterrupt:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            code = 130
        raise SystemExit(code)
    except (ValueError, OSError, KeyError, TypeError) as exc:
        code = (
            str(exc)
            if type(exc) is ValueError and str(exc).replace("_", "").isalnum()
            else type(exc).__name__
        )
        print(json.dumps({"verified": False, "error": code}))
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
