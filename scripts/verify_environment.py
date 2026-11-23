"""Compare installed build/runtime package versions with the frozen lock files; no network."""

import json
import platform
import re
import subprocess
from importlib import metadata
from pathlib import Path


class EnvironmentMismatch(ValueError):
    pass


def python_versions(root: Path) -> dict[str, str]:
    found = {}
    for line in (root / "requirements-dev.lock").read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([A-Za-z0-9.+!-]+)", line)
        if not match:
            raise EnvironmentMismatch("UNPINNED_PYTHON_REQUIREMENT")
        name, expected = match.groups()
        try:
            actual = metadata.version(name)
        except metadata.PackageNotFoundError as exc:
            raise EnvironmentMismatch("PYTHON_PACKAGE_MISSING") from exc
        if actual != expected:
            raise EnvironmentMismatch("PYTHON_LOCK_MISMATCH")
        found[name] = actual
    if not found:
        raise EnvironmentMismatch("EMPTY_PYTHON_LOCK")
    return found


def verify_environment(root: Path) -> dict:
    python = python_versions(root)
    web = (root / "apps/web").resolve()
    lock = json.loads((web / "package-lock.json").read_bytes())
    if lock.get("lockfileVersion") != 3 or not lock.get("packages"):
        raise EnvironmentMismatch("UNSUPPORTED_NODE_LOCK")
    found, optional_missing = {}, []
    for name, entry in lock["packages"].items():
        if not name:
            continue
        package = web / name / "package.json"
        if not name.startswith("node_modules/") or not package.resolve().is_relative_to(web):
            raise EnvironmentMismatch("NODE_LOCK_PATH_INVALID")
        if not package.is_file():
            if entry.get("optional"):
                optional_missing.append(name)
                continue
            raise EnvironmentMismatch("NODE_PACKAGE_MISSING")
        actual = json.loads(package.read_bytes()).get("version")
        if actual != entry.get("version") or not isinstance(actual, str):
            raise EnvironmentMismatch("NODE_LOCK_MISMATCH")
        found[name] = actual
    if not found:
        raise EnvironmentMismatch("NODE_PACKAGES_UNAVAILABLE")
    return {
        "python_runtime": platform.python_version(),
        "python_packages": python,
        "node_packages": found,
        "optional_node_packages_not_installed": sorted(optional_missing),
        "scope": "Exact declared package versions, not package-byte attestation.",
    }


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    try:
        result = verify_environment(root)
        result["node_runtime"] = subprocess.check_output(
            ["node", "--version"], text=True, timeout=10
        ).strip()
        print(json.dumps(result, indent=2))
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        code = str(exc) if isinstance(exc, EnvironmentMismatch) else type(exc).__name__
        print(json.dumps({"verified": False, "error": code}))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
