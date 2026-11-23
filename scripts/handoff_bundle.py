"""Explicit source handoff selection, integrity verification and non-overwriting ZIP."""

import argparse
import hashlib
import json
import os
import shutil
import zipfile
from pathlib import Path, PurePosixPath, PureWindowsPath

SKIP_DIRS = {
    "__pycache__",
    "node_modules",
    ".venv",
    ".git",
    ".pytest_cache",
    ".ruff_cache",
    "test-results",
    "playwright-report",
    "browser",
    "results",
    "_local",
}
SOURCE_DIRS = (
    "apps",
    "packages",
    "scripts",
    "tests",
    "docs",
    "eval",
    "infra",
    "knowledge",
    "migrations",
    "rules",
    "data/fixtures",
    "data/manifests",
)
SOURCE_FILES = (
    "AGENTS.md",
    "PROJECT_SPEC.md",
    "PROJECT_PLAN.md",
    "README.md",
    "pyproject.toml",
    "requirements-dev.lock",
    ".dockerignore",
    ".gitignore",
    ".env.example",
)


def sha(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def no_links(path: Path) -> None:
    for p in (path, *path.parents):
        if p.is_symlink() or p.is_junction():
            raise ValueError("LINK_REFUSED")


def safe_path(root: Path, name: str) -> Path:
    relative = PurePosixPath(name)
    if (
        not name
        or "\\" in name
        or PureWindowsPath(name).drive
        or relative.is_absolute()
        or ".." in relative.parts
        or relative.as_posix() != name
    ):
        raise ValueError("UNSAFE_PATH")
    result = root / name
    no_links(result)
    if not result.resolve().is_relative_to(root.resolve()):
        raise ValueError("PATH_OUTSIDE_ROOT")
    return result


def excluded(path: Path) -> bool:
    return bool(
        set(path.parts) & SKIP_DIRS
        or path.suffix.lower() in {".pyc", ".db", ".sqlite", ".sqlite3", ".pem", ".key"}
        or (path.name.startswith(".env") and path.name != ".env.example")
        or path.name in {"access.json", "tokens.json", "credentials.json", "runtime.env"}
    )


def tree_files(root: Path, directory: str) -> list[str]:
    base = safe_path(root, directory)
    values = []
    for current, directories, files in os.walk(base, followlinks=False):
        for name in directories + files:
            no_links(Path(current) / name)
        directories[:] = [d for d in directories if d not in SKIP_DIRS]
        for name in files:
            p = Path(current) / name
            if not excluded(p.relative_to(root)):
                values.append(p.relative_to(root).as_posix())
    return sorted(values)


def copy_selection(root: Path, target: Path, selected: dict[str, str]) -> dict:
    no_links(root)
    no_links(target)
    if target.exists():
        raise FileExistsError("TARGET_EXISTS")
    if root.resolve().is_relative_to(target.resolve()):
        raise ValueError("OVERLAPPING_ROOT")
    checked = []
    folded = set()
    for destination, source in selected.items():
        src, dst = safe_path(root, source), safe_path(target, destination)
        if excluded(Path(source)) or excluded(Path(destination)) or not src.is_file():
            raise ValueError("PRIVATE_OR_MISSING_INPUT")
        if destination.casefold() in folded:
            raise ValueError("CASE_COLLISION")
        folded.add(destination.casefold())
        checked.append((src, dst, destination))
    target.mkdir(parents=True, exist_ok=False)
    records = {}
    for src, dst, name in checked:
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)
        records[name] = {"sha256": sha(dst), "bytes": dst.stat().st_size}
    return records


def verify(root: Path) -> None:
    records = json.loads(safe_path(root, "manifest.json").read_bytes())["files"]
    for name, record in records.items():
        path = safe_path(root, name)
        if (
            not path.is_file()
            or path.stat().st_size != record["bytes"]
            or sha(path) != record["sha256"]
        ):
            raise ValueError("FILE_CHANGED: " + name)


def selection(root: Path) -> dict[str, str]:
    names = set(SOURCE_FILES)
    for directory in SOURCE_DIRS:
        names.update(tree_files(root, directory))
    # Archived public candidates and native offline dependencies are needed by
    # the historical packaging regression tests. Never recurse into this new bundle.
    for p in (root / "release").iterdir():
        if not p.name.startswith(("d1", "p1-")):
            continue
        if p.is_dir():
            names.update(tree_files(root, p.relative_to(root).as_posix()))
        elif not excluded(p):
            names.add(p.relative_to(root).as_posix())
    names.update(tree_files(root, ".tools/d13-wheels"))
    # Historical guard tests import these scripts; their private input directories
    # and spent authorization markers must never be copied with them.
    names.update((".tools/p1-context-01/trial.py", ".tools/p1-deepseek-01/trial.py"))
    from scripts.build_d15 import prior_evidence

    names.update(v["source"] for v in prior_evidence(root)["files"].values())
    names.update(("artifacts/d14-build-manifest.json", "artifacts/d14-final-integrity.json"))
    for p in (root / "artifacts").iterdir():
        if p.is_dir() and p.name.startswith(("cc-round", "http-round1", "ctu13")):
            for name in tree_files(root, p.relative_to(root).as_posix()):
                # Traces/failure logs may contain transient browser credentials.
                if name.endswith((".zip", ".webm", "browser.log")) or "/source-before/" in name:
                    continue
                names.add(name)
    return {"project/" + name: name for name in sorted(names)}


def stage(root: Path, target: Path) -> dict:
    selected = selection(root)
    for name in (
        "START.cmd",
        "STOP.cmd",
        "Start.ps1",
        "Stop.ps1",
        "Verify.ps1",
        "Common.ps1",
        "compose.yaml",
    ):
        selected[name] = "infra/handoff/" + name
    selected["START-HERE.md"] = "docs/handoff-quickstart.md"
    selected["HANDOFF.md"] = "docs/project-handoff.md"
    return copy_selection(root, target, selected)


def seal(root: Path, archive: Path) -> dict:
    no_links(root)
    no_links(archive)
    manifest = root / "manifest.json"
    checksum = archive.with_suffix(".sha256.txt")
    for path in (manifest, archive, checksum):
        no_links(path)
        if path.exists():
            raise FileExistsError("OUTPUT_EXISTS")
    if archive.resolve().is_relative_to(root.resolve()):
        raise ValueError("ARCHIVE_INSIDE_SOURCE")
    if (root / "_local").exists():
        raise ValueError("STARTED_BUNDLE_CANNOT_BE_PACKAGED")
    files = {}
    for directory, dirs, names in os.walk(root):
        for name in dirs + names:
            no_links(Path(directory) / name)
        for name in names:
            path = Path(directory) / name
            if path == root / "manifest.json":
                continue
            rel = path.relative_to(root).as_posix()
            if excluded(Path(rel)):
                raise ValueError("PRIVATE_INPUT_IN_PACKAGE")
            files[rel] = {"sha256": sha(path), "bytes": path.stat().st_size}
    value = {
        "version": "dev24-handoff@1",
        "application_version": "0.1.0.dev24",
        "model_provider": "disabled",
        "files": files,
    }
    with manifest.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2)
    verify(root)
    with zipfile.ZipFile(archive, "x", zipfile.ZIP_DEFLATED, compresslevel=6) as output:
        for name in [*sorted(files), "manifest.json"]:
            output.write(root / name, name)
    result = {
        "zip": archive.name,
        "sha256": sha(archive),
        "bytes": archive.stat().st_size,
        "files": len(files) + 1,
    }
    with checksum.open("x", encoding="ascii") as stream:
        stream.write(result["sha256"] + "  " + archive.name + "\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["stage", "seal", "verify"])
    parser.add_argument("--target", required=True, type=Path)
    args = parser.parse_args()
    if args.command == "stage":
        print("Copied files:", len(stage(Path(__file__).resolve().parents[1], args.target)))
    elif args.command == "seal":
        print(json.dumps(seal(args.target, args.target.with_suffix(".zip"))))
    else:
        verify(args.target)
        print("Integrity verified")
