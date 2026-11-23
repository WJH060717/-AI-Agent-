"""Build an immutable deployment/documentation kit around the unchanged D12 candidate."""

import argparse
import json
import shutil
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from scripts.deploy_d13 import (
    BASE_FREEZE,
    VERSION,
    DeployError,
    file_records,
    no_links,
    verify_base,
    verify_kit,
)

DOCS = ["runbook", "scenarios", "defense", "demo", "limitations", "operator-checklist"]


def check_target(root: Path, target: Path) -> None:
    no_links(root)
    no_links(target)
    no_links(target.with_suffix(".zip"))
    source = root.resolve()
    dest = target.resolve()
    if source.is_relative_to(dest) or any(
        dest.is_relative_to(source / name)
        for name in ("release/d12-candidate-04", "docs", "scripts")
    ):
        raise DeployError("OVERLAPPING_PATH")
    if target.exists() or target.with_suffix(".zip").exists():
        raise FileExistsError("TARGET_OR_ZIP_EXISTS")


def build(root: Path, target: Path) -> dict:
    check_target(root, target)
    base = root / "release/d12-candidate-04"
    verify_base(base)
    file_records(root / "docs/d13-notices")  # Validate links before copytree follows anything.
    target.mkdir(parents=True, exist_ok=False)
    frozen = json.loads((base / "freeze.json").read_bytes())
    names = [
        *frozen["files"],
        "freeze.json",
        "version-manifest.json",
        "SHA256SUMS",
        "README-install.md",
    ]
    for name in names:
        dest = target / "app" / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(base / name, dest)
    shutil.copyfile(root / "scripts/deploy_d13.py", target / "deploy.py")
    (target / "docs").mkdir()
    for name in DOCS:
        shutil.copyfile(root / f"docs/d13-{name}.md", target / f"docs/d13-{name}.md")
    shutil.copyfile(root / "docs/d13-showcase.html", target / "showcase.html")
    shutil.copytree(root / "docs/d13-notices", target / "dependency-notices")
    shutil.copyfile(root / "docs/d13-runbook.md", target / "README-install.md")
    manifest = {
        "version": VERSION,
        "created_at": datetime.now(UTC).isoformat(),
        "application_version": "0.1.0.dev12",
        "base_freeze_sha256": BASE_FREEZE,
        "non_author_accepted": False,
        "p0_release_ready": False,
        "files": file_records(target),
    }
    (target / "kit-manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    verify_kit(target)
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    build(root, args.output)
    with zipfile.ZipFile(args.output.with_suffix(".zip"), "x", zipfile.ZIP_DEFLATED) as archive:
        for file in sorted(args.output.rglob("*")):
            if file.is_file():
                archive.write(file, file.relative_to(args.output).as_posix())
    print(json.dumps({"built": True, "base_freeze_sha256": BASE_FREEZE}))


if __name__ == "__main__":
    main()
