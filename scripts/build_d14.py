"""Package the fixed native kit and a complete platform-specific hash-locked wheelhouse."""

import argparse
import email
import json
import shutil
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from packaging.tags import sys_tags
from packaging.utils import parse_wheel_filename

from scripts.deploy_d13 import file_records, no_links, verify_kit
from scripts.offline_d14 import KIT_SHA, VERSION, hashed_requirements, normalize, sha, verify


def wheel_records(folder: Path, lock: Path) -> dict:
    required = {
        normalize(line.split("==")[0]): line.split("==")[1]
        for line in lock.read_text().splitlines()
        if "==" in line
    }
    found = {}
    no_links(folder)
    for wheel in sorted(folder.iterdir()):
        no_links(wheel)
        name, version, _, tags = parse_wheel_filename(wheel.name)
        if not tags.intersection(sys_tags()) or name in found or required.get(name) != str(version):
            raise ValueError("UNEXPECTED_OR_INCOMPATIBLE_WHEEL")
        with zipfile.ZipFile(wheel) as archive:
            entries = [n for n in archive.namelist() if n.endswith(".dist-info/METADATA")]
            if len(entries) != 1:
                raise ValueError("INVALID_WHEEL_METADATA")
            metadata = email.message_from_bytes(archive.read(entries[0]))
            if normalize(metadata["Name"]) != name or metadata["Version"] != str(version):
                raise ValueError("WHEEL_METADATA_MISMATCH")
        found[name] = {"version": str(version), "filename": wheel.name, "sha256": sha(wheel)}
    if set(found) != set(required):
        raise ValueError("INCOMPLETE_WHEELHOUSE")
    return found


def build(root: Path, wheels: Path, target: Path) -> dict:
    for path in (root, wheels, target, target.with_suffix(".zip")):
        no_links(path)
    if target.exists() or target.with_suffix(".zip").exists():
        raise FileExistsError("TARGET_EXISTS")
    if root.resolve().is_relative_to(target.resolve()) or any(
        target.resolve().is_relative_to(p.resolve()) or p.resolve().is_relative_to(target.resolve())
        for p in (root / "release/d13-kit-02", wheels, root / "docs", root / "scripts")
    ):
        raise ValueError("OVERLAPPING_PATH")
    kit = root / "release/d13-kit-02"
    if sha(kit / "kit-manifest.json") != KIT_SHA:
        raise ValueError("D13_KIT_CHANGED")
    verify_kit(kit)
    records = wheel_records(wheels, kit / "app/requirements-dev.lock")
    target.mkdir(parents=True, exist_ok=False)
    shutil.copytree(kit, target / "kit")
    shutil.copytree(wheels, target / "wheels")
    (target / "tools").mkdir()
    shutil.copyfile(kit / "deploy.py", target / "tools/deploy_d13.py")
    shutil.copyfile(root / "scripts/network_guard_d14.py", target / "tools/network_guard.py")
    shutil.copyfile(root / "scripts/offline_d14.py", target / "offline.py")
    shutil.copyfile(root / "docs/d14-runbook.md", target / "README-offline.md")
    (target / "requirements-hashed.txt").write_text(hashed_requirements(records), encoding="utf-8")
    manifest = {
        "version": VERSION,
        "platform": "win-amd64-cp313",
        "created_at": datetime.now(UTC).isoformat(),
        "python_runtime_included": False,
        "p0_release_ready": False,
        "wheels": records,
        "files": file_records(target),
    }
    (target / "offline-manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    verify(target)
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheels", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    build(Path(__file__).resolve().parents[1], args.wheels, args.output)
    with zipfile.ZipFile(args.output.with_suffix(".zip"), "x", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(args.output.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(args.output).as_posix())
    print(
        json.dumps({"built": True, "offline_dependencies": True, "python_runtime_included": False})
    )
