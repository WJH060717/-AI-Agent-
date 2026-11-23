"""Build a new, traceable local D15 engineering candidate from fixed public inputs."""

import argparse
import html
import json
import shutil
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from scripts.verify_d15 import (
    BASE,
    OPEN_P1,
    PINS,
    VERSION,
    no_links,
    records,
    safe_name,
    safe_zip,
    sha,
    verify,
)

PRIOR_SHA = "ee0bd89ccc8e674fc529b2acfdf016e8073771c10f3a68e69692f9d1b74eff2b"
SOURCES = {
    "deployment/d14-offline-02.zip": "release/d14-offline-02.zip",
    "materials": "release/d14-materials.zip",
    "evaluation": "release/d12-analysis-evidence.zip",
}
DOCS = [
    "d15-runbook.md",
    "d15-technical-annex.md",
    "d15-limitations.md",
    "d15-delivery-checklist.md",
    "d15-acceptance.json",
    "d15-implementation.md",
]
REFERENCES = [
    "PROJECT_SPEC.md",
    "docs/d12-acceptance.json",
    "docs/d12-defects.json",
    "docs/d14-acceptance.json",
    "artifacts/d14-build-manifest.json",
    "artifacts/d14-final-integrity.json",
]
SOURCE_CODE = [
    "scripts/build_d15.py",
    "scripts/verify_d15.py",
    "tests/unit/test_delivery_d15.py",
    "docs/d15-open.mjs",
]


class FileRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    bytes: int = Field(ge=0)


class DeliveryManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    version: Literal["d15-delivery@1.0.0"]
    created_at: str
    application_version: Literal["0.1.0.dev12"]
    database_head: Literal["0006_d9"]
    base_freeze_sha256: str
    release_status: Literal["engineering_candidate"]
    p0_release_ready: Literal[False]
    open_p1: list[str]
    source_archives: dict[str, str]
    files: dict[str, FileRecord]


def freeze_path(target: Path) -> Path:
    return target.parent / (target.name + "-freeze.json")


def validate_target(root: Path, target: Path) -> None:
    for path in (root, target, target.with_suffix(".zip"), freeze_path(target)):
        no_links(path)
    if any(path.exists() for path in (target, target.with_suffix(".zip"), freeze_path(target))):
        raise FileExistsError("TARGET_EXISTS")
    source, destination = root.resolve(), target.resolve()
    if source.is_relative_to(destination):
        raise ValueError("OVERLAPPING_PATH")
    if destination.is_relative_to(source):
        relative = destination.relative_to(source)
        # Only a direct new child of release/ is allowed inside the workspace.
        if len(relative.parts) != 2 or relative.parts[0] != "release":
            raise ValueError("OVERLAPPING_OR_PRIVATE_PATH")


def prior_evidence(root: Path) -> dict[str, Any]:
    path = root / "artifacts/d14-build-manifest.json"
    no_links(path)
    if sha(path) != PRIOR_SHA:
        raise ValueError("D14_MANIFEST_CHANGED")
    prior = json.loads(path.read_bytes())
    preserved = {}
    for name, expected in prior["files"].items():
        safe_name(name)
        options = [root / name, root / "artifacts/d14-source-preserved-for-d15" / name]
        for option in options:
            no_links(option)
            if option.is_file() and option.stat().st_size == expected["bytes"]:
                if sha(option) == expected["sha256"]:
                    preserved[name] = {**expected, "source": option.relative_to(root).as_posix()}
                    break
        else:
            raise ValueError("D14_EVIDENCE_CHANGED: " + name)
    return {"version": "d14-preservation-after-d15@1.0.0", "verified": True, "files": preserved}


def write_json(path: Path, value: dict[str, Any]) -> None:
    with path.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def index_html() -> str:
    links = {
        "部署包（Windows CPython3.13）": "deployment/d14-offline-02.zip",
        "安装与核验手册": "docs/d15-runbook.md",
        "技术附件": "docs/d15-technical-annex.md",
        "已知限制 / 七项P1": "docs/d15-limitations.md",
        "角色职责与待签提交清单": "docs/d15-delivery-checklist.md",
        "展示页": "materials/docs/d14-showcase.html",
        "第一轮预录 7:59.2": "materials/media/d14-rehearsal-01.webm",
        "第二轮预录 7:59.2": "materials/media/d14-rehearsal-02.webm",
        "第一轮实际报告": "materials/rehearsal-01/S1.html",
        "第二轮实际报告": "materials/rehearsal-02/S1.html",
        "历史实验与资源曲线": "evaluation/artifacts/d12-check-04/analysis/index.html",
        "来源与归档索引": "source-catalog.json",
    }
    items = "\n".join(
        f'<li><a href="{html.escape(path, quote=True)}">{html.escape(label)}</a></li>'
        for label, path in links.items()
    )
    return f"""<!doctype html><html lang="zh-CN"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>D15 交付入口</title>
<style>body{{font:18px/1.7 system-ui,sans-serif;max-width:960px;margin:40px auto;padding:0 24px;
color:#132c39;background:#f5f7fa}}a{{color:#075b93}}li{{margin:10px 0}}.notice{{background:#fff3d1;
border-left:5px solid #936300;padding:18px}}code{{overflow-wrap:anywhere}}</style>
<h1>D15 本地工程交付候选</h1><p>应用 0.1.0.dev12 · 数据库 0006_d9 · 固定 D14 离线部署包</p>
<p class="notice">完整P0未通过，七项P1仍未关闭。未对外提交；人工复核/许可确认保持待签。
录像是合成数据、本地协议故障桩、自动操作的预录，不是真实LLM或真人现场验收。</p>
<h2>直接打开</h2><ul>{items}</ul><h2>接收后核验</h2>
<p>先按外部freeze核对ZIP，再运行 <code>python -I verify.py</code>。
普通exit0表示文件完整；<code>--strict</code>仍exit2并列出发布阻断。
hash不是数字签名；不把私有备份/令牌/数据库放入本目录。</p></html>"""


def build(root: Path, target: Path) -> dict[str, Any]:
    validate_target(root, target)
    source_entries = {}
    for destination, name in SOURCES.items():
        path = root / name
        no_links(path)
        if sha(path) != PINS[destination]:
            raise ValueError("PINNED_SOURCE_CHANGED")
        source_entries[destination] = safe_zip(path)
    preserved = prior_evidence(root)
    selected = {"docs/" + name: root / "docs" / name for name in DOCS}
    selected |= {"reference/" + Path(name).name: root / name for name in REFERENCES}
    selected |= {"source/" + name: root / name for name in SOURCE_CODE}
    selected["verify.py"] = root / "scripts/verify_d15.py"
    for path in selected.values():
        no_links(path)
        if not path.is_file():
            raise ValueError("MISSING_PUBLIC_INPUT")
    target.mkdir(parents=True, exist_ok=False)
    provenance = {}
    for destination, name in SOURCES.items():
        path = root / name
        if destination.endswith(".zip"):
            output = target / destination
            output.parent.mkdir(parents=True)
            shutil.copyfile(path, output)
        else:
            with zipfile.ZipFile(path) as archive:
                for info in source_entries[destination]:
                    if info.is_dir():
                        continue
                    output = target / destination / info.filename
                    output.parent.mkdir(parents=True, exist_ok=True)
                    with output.open("xb") as stream:
                        stream.write(archive.read(info))
        provenance[destination] = {
            "source": name,
            "sha256": PINS[destination],
            "entries": len(source_entries[destination]),
            "mode": "unchanged_zip" if destination.endswith(".zip") else "exact_entry_bytes",
        }
    for name, source in selected.items():
        output = target / name
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, output)
    write_json(
        target / "source-catalog.json",
        {
            "version": "d15-source-catalog@1.0.0",
            "archives": provenance,
            "data_kind": "authorized_synthetic_development",
            "formal_33_runs_collected": False,
            "real_llm_accepted": False,
            "runtime_eval_imported": False,
            "external_submission_completed": False,
            "original_raw_recordings": "Retained locally in D14 artifacts; excluded from delivery",
            "private_backups": "Excluded; retained only in controlled local storage",
            "history": "D11/D12 measurements retain original version and all failed rounds",
        },
    )
    write_json(target / "reference/d14-preservation.json", preserved)
    (target / "START-HERE.html").write_text(index_html(), encoding="utf-8")
    (target / "README.md").write_text(
        "# D15 本地工程交付候选\n\n打开START-HERE.html开始。安装与核验见docs/d15-runbook.md；"
        "角色职责/待签项见docs/d15-delivery-checklist.md。\n\n"
        "固定应用0.1.0.dev12、0006_d9。deployment为Windows CPython3.13离线包；"
        "materials为实际预录/截图/报告；evaluation为历史原始实验/失败与分析。\n\n"
        "普通verify仅检查完整性；--strict仍exit2，七P1未关闭。未对外提交；"
        "人工验收、正式数据、真实LLM、独立机器、物理断网和最终许可确认未完成。\n",
        encoding="utf-8",
    )
    manifest = DeliveryManifest(
        version=VERSION,
        created_at=datetime.now(UTC).isoformat(),
        application_version="0.1.0.dev12",
        database_head="0006_d9",
        base_freeze_sha256=BASE,
        release_status="engineering_candidate",
        p0_release_ready=False,
        open_p1=OPEN_P1,
        source_archives=PINS,
        files=records(target),
    ).model_dump()
    write_json(target / "release-manifest.json", manifest)
    checksums = {name: item["sha256"] for name, item in manifest["files"].items()}
    checksums["release-manifest.json"] = sha(target / "release-manifest.json")
    (target / "SHA256SUMS").write_text(
        "".join(f"{digest}  {name}\n" for name, digest in sorted(checksums.items())),
        encoding="utf-8",
    )
    verified = verify(target, checksums["release-manifest.json"])
    archive_path = target.with_suffix(".zip")
    with zipfile.ZipFile(archive_path, "x", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(target.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(target).as_posix())
    safe_zip(archive_path)
    frozen = {
        "version": "d15-freeze@1.0.0",
        "created_at": datetime.now(UTC).isoformat(),
        "candidate": target.name,
        "zip": archive_path.name,
        "zip_sha256": sha(archive_path),
        "zip_bytes": archive_path.stat().st_size,
        **verified,
        "application_version": "0.1.0.dev12",
        "base_freeze_sha256": BASE,
    }
    write_json(freeze_path(target), frozen)
    return frozen


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(build(Path(__file__).resolve().parents[1], args.output)))
