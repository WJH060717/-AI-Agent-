"""Archive installed dependency metadata and available license texts, without legal conclusions."""

import argparse
import importlib.metadata
import json
import re
from pathlib import Path

from scripts.deploy_d13 import digest, file_records


def build(root: Path, output: Path) -> None:
    output.mkdir(parents=True, exist_ok=False)
    entries = []

    def preserve(kind: str, name: str, files: list[Path]) -> list[dict]:
        saved = []
        for index, path in enumerate(files):
            if not path.is_file() or path.stat().st_size > 500_000:
                continue
            data = path.read_bytes()
            relative = f"{kind}/{re.sub(r'[^a-zA-Z0-9.-]', '_', name)}/{index}-{path.name}"
            destination = output / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            saved.append({"path": relative, "sha256": digest(data)})
        return saved

    for line in (root / "requirements-dev.lock").read_text().splitlines():
        if "==" not in line:
            continue
        name, version = line.split("==")
        dist = importlib.metadata.distribution(name)
        if dist.version != version:
            raise ValueError("DEPENDENCY_VERSION_DRIFT")
        files = [
            Path(dist.locate_file(path))
            for path in dist.files or []
            if path.name.lower().startswith(("license", "copying", "notice"))
        ]
        entries.append(
            {
                "ecosystem": "python",
                "name": name,
                "version": version,
                "license_expression": dist.metadata.get("License-Expression"),
                "license_metadata": dist.metadata.get("License"),
                "texts": preserve("python", name, files),
            }
        )
    web = root / "apps/web"
    lock = json.loads((web / "package-lock.json").read_bytes())
    for name, record in lock["packages"].items():
        if not name.startswith("node_modules/"):
            continue
        folder = web / name
        if not folder.resolve().is_relative_to(web.resolve()):
            raise ValueError("DEPENDENCY_PATH_INVALID")
        package = folder / "package.json"
        if not package.is_file():
            entries.append(
                {
                    "ecosystem": "node",
                    "name": name,
                    "version": record.get("version"),
                    "installed": False,
                    "optional": record.get("optional", False),
                    "texts": [],
                }
            )
            continue
        meta = json.loads(package.read_bytes())
        if meta.get("version") != record.get("version"):
            raise ValueError("DEPENDENCY_VERSION_DRIFT")
        files = [
            p
            for p in sorted(folder.iterdir())
            if p.name.lower().startswith(("license", "copying", "notice"))
        ]
        entries.append(
            {
                "ecosystem": "node",
                "name": name,
                "version": meta["version"],
                "installed": True,
                "license_metadata": meta.get("license"),
                "texts": preserve("node", name, files),
            }
        )
    payload = {
        "version": "d13-dependency-notices@1.0.0",
        "scope": (
            "Installed locked dependencies and available license files; "
            "not a complete legal clearance."
        ),
        "project_license": "not_declared",
        "packages": entries,
        "files": file_records(output),
    }
    (output / "inventory.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    build(Path(__file__).resolve().parents[1], args.output)
