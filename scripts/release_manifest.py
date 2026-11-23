"""Offline D10 source/build freeze and allowlisted native candidate packaging."""

import argparse
import hashlib
import json
import os
import re
import tomllib
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Literal

from pydantic import Field, ValidationError

from packages.contracts.models import Contract, Digest

MAX_FILE_BYTES = 10_000_000
MAX_TOTAL_BYTES = 50_000_000
REQUIRED = {
    "apps/api/main.py",
    "packages/config.py",
    "pyproject.toml",
    "requirements-dev.lock",
    "packages/contracts/generated/openapi.json",
    "rules/freeze.json",
    "eval/freeze-d9.json",
    "docs/d10-acceptance.json",
    "docs/d10-defects.json",
    "docs/d10-runbook.md",
    "docs/d10-demo.md",
    "docs/d10-limitations.md",
    "apps/web/dist/index.html",
    ".env.example",
    "infra/release-inputs.json",
}
GENERATED = {
    f"packages/contracts/generated/{name}"
    for name in (
        "api.schema.json",
        "contracts.schema.json",
        "openapi.json",
        "api.ts",
        "contracts.ts",
    )
}
WEB_CONFIG = {
    "eslint.config.js",
    "index.html",
    "package-lock.json",
    "package.json",
    "playwright.config.ts",
    "tsconfig.json",
    "vite.config.ts",
}
EXECUTABLE = {".py", ".pyc", ".pyo", ".pyd", ".so", ".dll", ".pth", ".zip"}
DOCS = {
    "PROJECT_SPEC.md",
    "AGENTS.md",
    "docs/02-data-contracts.md",
    "docs/03-detection-graph.md",
    "docs/04-agent.md",
    "docs/05-api-ui.md",
    "docs/07-evaluation.md",
    "docs/08-deployment-demo.md",
    "docs/d10-runbook.md",
    "docs/d10-demo.md",
    "docs/d10-limitations.md",
}


class ReleaseError(ValueError):
    pass


class FileRecord(Contract):
    sha256: Digest
    bytes: int = Field(ge=0, le=MAX_FILE_BYTES)
    group: Literal[
        "api_contracts", "runtime", "rules_data", "web", "operations", "verification", "docs"
    ]


class Freeze(Contract):
    version: Literal["d10-freeze@1.0.0", "d11-freeze@1.0.0", "d12-freeze@1.0.0"]
    candidate_id: str = Field(pattern=r"^[a-z0-9][a-z0-9.-]{0,63}$")
    created_at: datetime
    versions: dict[str, str]
    files: dict[str, FileRecord]


class ReviewedInputs(Contract):
    version: Literal["d10-reviewed-inputs@1.0.0"]
    basis: str = Field(min_length=1)
    files: dict[str, Digest]


def manifest_digest(payload: dict) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def scoped_file(root: Path, name: str) -> Path:
    relative = PurePosixPath(name)
    if (
        not name
        or "\\" in name
        or PureWindowsPath(name).drive
        or relative.is_absolute()
        or ".." in relative.parts
        or relative.as_posix() != name
        or any(ord(c) < 32 for c in name)
    ):
        raise ReleaseError("INVALID_RELEASE_PATH")
    path = root / name
    for part in (path, *path.parents):
        if part == root:
            break
        if part.is_symlink() or part.is_junction():
            raise ReleaseError("LINK_NOT_ALLOWED")
    if not path.resolve().is_relative_to(root.resolve()):
        raise ReleaseError("PATH_OUT_OF_SCOPE")
    return path


def read_file(root: Path, name: str) -> bytes:
    path = scoped_file(root, name)
    if not path.is_file():
        raise ReleaseError("REQUIRED_FILE_MISSING")
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ReleaseError("RELEASE_FILE_TOO_LARGE")
    with path.open("rb") as stream:
        data = stream.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise ReleaseError("RELEASE_FILE_TOO_LARGE")
    return data


def catalog(root: Path, stage: str = "d10") -> dict[str, str]:
    result: dict[str, str] = {}
    reviewed = ReviewedInputs.model_validate_json(read_file(root, "infra/release-inputs.json"))
    for name, expected in reviewed.files.items():
        if not name.startswith(("data/fixtures/", "rules/", "tests/")):
            raise ReleaseError("INVALID_REVIEWED_INPUT_SCOPE")
        if hashlib.sha256(read_file(root, name)).hexdigest() != expected:
            raise ReleaseError("REVIEWED_INPUT_CHANGED")
    for path in root.iterdir():
        if path.is_file() and path.suffix.lower() in EXECUTABLE:
            raise ReleaseError("UNEXPECTED_ROOT_EXECUTABLE")

    def walk(folder: str, suffixes: set[str] | None, group: str) -> None:
        base = scoped_file(root, folder)
        if not base.exists():
            return
        for directory, folders, filenames in os.walk(base, followlinks=False):
            folders[:] = [d for d in folders if d not in {"__pycache__", ".pytest_cache"}]
            for child in folders + filenames:
                name = (Path(directory) / child).relative_to(root).as_posix()
                scoped_file(root, name)
            for filename in filenames:
                path = Path(directory) / filename
                name = path.relative_to(root).as_posix()
                if (
                    folder == "data/fixtures"
                    or folder in {"tests", "rules"}
                    and path.suffix in {".json", ".jsonl"}
                ):
                    if name not in reviewed.files:
                        raise ReleaseError("UNREVIEWED_INPUT")
                if suffixes is not None and path.suffix not in suffixes:
                    if path.suffix != ".md" and name not in GENERATED:
                        raise ReleaseError("UNEXPECTED_SOURCE_FILE")
                if (
                    folder == "packages/contracts"
                    and path.suffix in {".json", ".ts"}
                    and name not in GENERATED
                ):
                    raise ReleaseError("UNREVIEWED_CONTRACT_FILE")
                if suffixes is None or path.suffix in suffixes:
                    if folder == "apps/web/dist" and not (
                        name == "apps/web/dist/index.html"
                        or name.startswith("apps/web/dist/assets/")
                        and path.suffix
                        in {".js", ".css", ".svg", ".png", ".ico", ".woff", ".woff2"}
                    ):
                        raise ReleaseError("UNEXPECTED_WEB_ASSET")
                    result[name] = group

    walk("packages", {".py"}, "runtime")
    walk("packages/contracts", {".py", ".json", ".ts"}, "api_contracts")
    walk("apps/api", {".py"}, "api_contracts")
    walk("apps/worker", {".py"}, "runtime")
    walk("apps/web/src", {".ts", ".tsx", ".css"}, "web")
    walk("apps/web/dist", None, "web")
    walk("apps/web/tests", {".ts"}, "verification")
    walk("tests", {".py", ".json", ".jsonl"}, "verification")
    walk("scripts", {".py", ".ps1"}, "operations")
    walk("migrations", {".py", ".mako"}, "operations")
    walk("rules", {".json"}, "rules_data")
    walk("data/fixtures", {".json", ".jsonl", ".md"}, "rules_data")
    for name in DOCS:
        if (root / name).is_file():
            result[name] = "docs"
    for folder, suffixes, group in (
        ("apps", {".py"}, "runtime"),
        ("apps/web", {".json", ".ts", ".js", ".html"}, "web"),
        ("infra", {".yaml", ".sql", ".md"}, "operations"),
        ("eval", {".py", ".json"}, "verification"),
    ):
        if (root / folder).exists():
            for path in (root / folder).iterdir():
                if path.is_file() and folder == "apps/web" and path.name not in WEB_CONFIG:
                    if path.name not in {"README.md", ".gitignore"}:
                        raise ReleaseError("UNREVIEWED_WEB_CONFIG")
                if (
                    path.is_file()
                    and folder in {"apps", "eval"}
                    and path.suffix.lower() in EXECUTABLE - {".py"}
                ):
                    raise ReleaseError("UNEXPECTED_SOURCE_FILE")
                if path.is_file() and path.suffix in suffixes:
                    if (
                        folder == "eval"
                        and path.suffix == ".json"
                        and path.name not in {"runs.json", "dossiers.json", "freeze-d9.json"}
                    ):
                        continue
                    result[path.relative_to(root).as_posix()] = group
    for name in ("pyproject.toml", "requirements-dev.lock", ".env.example"):
        result[name] = "operations"
    result["infra/release-inputs.json"] = "operations"
    for name in ("docs/d10-acceptance.json", "docs/d10-defects.json"):
        result[name] = "verification"
    required = set(REQUIRED)
    if stage in {"d11", "d12"}:
        from eval.contracts import EvaluationConfig

        name = "eval/configs/d11-engineering.json"
        config = EvaluationConfig.model_validate_json(read_file(root, name))
        if config.profile != "engineering":
            raise ReleaseError("INVALID_BUNDLED_EVALUATION")
        for run in config.runs:
            inputs = [source.object for source in run.sources]
            if run.context is not None:
                inputs.append(run.context)
            for obj in inputs:
                if reviewed.files.get(obj.path) != obj.sha256:
                    raise ReleaseError("UNREVIEWED_EVALUATION_INPUT")
        result[name] = "verification"
        required.add(name)
        for suffix in ("acceptance.json", "defects.json", "runbook.md", "limitations.md"):
            name = f"docs/{stage}-{suffix}"
            result[name] = "docs" if suffix.endswith(".md") else "verification"
            required.add(name)
    if stage == "d12":
        result["eval/d12-inputs.json"] = "verification"
        required.add("eval/d12-inputs.json")
        for name in ("docs/d11-acceptance.json", "docs/d11-defects.json"):
            result[name] = "verification"
            required.add(name)
    if not required.issubset(result) or not any(
        n.startswith("apps/web/dist/assets/") for n in result
    ):
        raise ReleaseError("REQUIRED_FILE_MISSING")
    return result


def build_manifest(root: Path, candidate_id: str = "d10-candidate") -> dict:
    root = root.resolve()
    version = tomllib.loads(read_file(root, "pyproject.toml").decode())["project"]["version"]
    if version not in {"0.1.0.dev10", "0.1.0.dev11", "0.1.0.dev12"}:
        raise ReleaseError("VERSION_MISMATCH")
    stage = "d" + version.split("dev")[1]
    records = {}
    total = 0
    for name, group in sorted(catalog(root, stage).items()):
        data = read_file(root, name)
        total += len(data)
        if total > MAX_TOTAL_BYTES:
            raise ReleaseError("RELEASE_TOO_LARGE")
        records[name] = {
            "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data),
            "group": group,
        }
    version = tomllib.loads(read_file(root, "pyproject.toml").decode())["project"]["version"]
    api_version = json.loads(read_file(root, "packages/contracts/generated/openapi.json"))["info"][
        "version"
    ]
    if version != api_version:
        raise ReleaseError("VERSION_MISMATCH")
    payload = {
        "version": f"{stage}-freeze@1.0.0",
        "candidate_id": candidate_id,
        "created_at": datetime.now(UTC).isoformat(),
        "versions": {
            "application": version,
            "migration_head": "0006_d9",
            "model_profile": "disabled_default; live_model_not_accepted",
            "knowledge": "not_loaded",
            "data_status": "planned_and_prepared_not_formal_runs",
            **{
                group: manifest_digest({k: v for k, v in records.items() if v["group"] == group})
                for group in sorted({v["group"] for v in records.values()})
            },
        },
        "files": records,
    }
    Freeze.model_validate(payload)
    return payload


def verify_manifest(root: Path, payload: dict) -> None:
    try:
        frozen = Freeze.model_validate(payload)
        for name in frozen.files:
            scoped_file(root.resolve(), name)
        current = build_manifest(root, frozen.candidate_id)
        if any(payload[key] != current[key] for key in ("files", "versions", "version")):
            raise ReleaseError("FREEZE_DRIFT")
    except (ValidationError, KeyError) as exc:
        raise ReleaseError("INVALID_FREEZE") from exc


def write_new(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(data)


def encoded(payload: dict) -> bytes:
    return (json.dumps(payload, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def create_freeze(root: Path, output: Path, candidate_id: str) -> dict:
    payload = build_manifest(root, candidate_id)
    write_new(output, encoded(payload))
    return payload


def build_candidate(root: Path, frozen: dict, target: Path) -> None:
    verify_manifest(root, frozen)
    stage = frozen["version"].split("-")[0]
    target.mkdir(parents=True, exist_ok=False)
    for name, record in frozen["files"].items():
        data = read_file(root, name)
        if hashlib.sha256(data).hexdigest() != record["sha256"]:
            raise ReleaseError("SOURCE_CHANGED_DURING_COPY")
        write_new(target / name, data)
    write_new(target / "freeze.json", encoded(frozen))
    write_new(
        target / "version-manifest.json",
        encoded(
            {
                "candidate_id": frozen["candidate_id"],
                "freeze_sha256": manifest_digest(frozen),
                "versions": frozen["versions"],
                "release_ready": False,
                "acceptance": (
                    f"Run {stage.upper()} gates; this candidate alone is not release approval."
                ),
            }
        ),
    )
    write_new(target / "README-install.md", read_file(root, f"docs/{stage}-runbook.md"))
    write_new(
        target / "SHA256SUMS",
        "".join(
            f"{record['sha256']}  {name}\n" for name, record in sorted(frozen["files"].items())
        ).encode(),
    )
    verify_manifest(target, frozen)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["freeze", "verify", "package"])
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--freeze", type=Path, required=True)
    parser.add_argument("--id", default="d10-candidate-01")
    parser.add_argument("--target", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "freeze":
            payload = create_freeze(args.root, args.freeze, args.id)
        else:
            payload = json.loads(args.freeze.read_bytes())
            verify_manifest(args.root, payload)
            if args.command == "package":
                if args.target is None:
                    parser.error("package requires --target")
                build_candidate(args.root, payload, args.target)
        print(
            json.dumps(
                {
                    "verified": True,
                    "files": len(payload["files"]),
                    "freeze_sha256": manifest_digest(payload),
                }
            )
        )
    except (OSError, ValueError, KeyError) as exc:
        code = (
            str(exc)
            if isinstance(exc, ReleaseError) and re.fullmatch(r"[A-Z_]+", str(exc))
            else type(exc).__name__
        )
        parser.exit(1, f"RELEASE_CHECK_FAILED:{code}\n")


if __name__ == "__main__":
    main()
