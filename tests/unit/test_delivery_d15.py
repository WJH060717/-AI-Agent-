import hashlib
import importlib.util
import json
import shutil
import stat
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def test_delivery_modules_exist():
    assert importlib.util.find_spec("scripts.build_d15") is not None
    assert importlib.util.find_spec("scripts.verify_d15") is not None


@pytest.fixture(scope="module")
def clean(tmp_path_factory):
    from scripts.build_d15 import build

    target = tmp_path_factory.mktemp("d15") / "candidate"
    build(ROOT, target)
    return target


@pytest.fixture
def bundle(clean, tmp_path):
    target = tmp_path / "copy"
    shutil.copytree(clean, target)
    return target


def rewrite_record(bundle, name):
    manifest = bundle / "release-manifest.json"
    value = json.loads(manifest.read_bytes())
    data = (bundle / name).read_bytes()
    value["files"][name] = {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
    manifest.write_text(json.dumps(value), encoding="utf-8")


def test_actual_bundle_fixed_sources_and_modes(clean):
    from scripts.verify_d15 import verify

    result = verify(clean)
    assert result["integrity_verified"] and not result["p0_release_ready"]
    assert len(result["open_p1"]) == 7
    assert (clean / "materials/media/d14-rehearsal-02.webm").is_file()
    assert (clean / "evaluation/artifacts/d11-benchmark-full-02/summary.json").is_file()
    assert not list(clean.rglob("*.db"))


@pytest.mark.parametrize("kind", ["changed", "missing", "extra"])
def test_file_drift_rejected(bundle, kind):
    from scripts.verify_d15 import verify

    path = bundle / "README.md"
    if kind == "changed":
        path.write_bytes(path.read_bytes() + b"changed")
    elif kind == "missing":
        path.unlink()
    else:
        (bundle / ".env").write_text("private", encoding="utf-8")
    with pytest.raises(ValueError):
        verify(bundle)


def test_wrong_external_digest_rejected(clean):
    from scripts.verify_d15 import verify

    with pytest.raises(ValueError, match="MANIFEST_DIGEST"):
        verify(clean, "0" * 64)


def test_mutable_manifest_cannot_close_p0(bundle):
    from scripts.verify_d15 import verify

    path = bundle / "release-manifest.json"
    value = json.loads(path.read_bytes())
    value["p0_release_ready"] = True
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="ACCEPTANCE"):
        verify(bundle)


def test_mutable_manifest_cannot_replace_deployment(bundle):
    from scripts.verify_d15 import verify

    name = "deployment/d14-offline-02.zip"
    path = bundle / name
    path.write_bytes(path.read_bytes() + b"changed")
    rewrite_record(bundle, name)
    with pytest.raises(ValueError, match="PINNED_SOURCE"):
        verify(bundle)


@pytest.mark.parametrize("which", ["directory", "zip"])
def test_existing_output_is_untouched(tmp_path, which):
    from scripts.build_d15 import build

    target = tmp_path / "existing"
    sentinel = target / "keep" if which == "directory" else target.with_suffix(".zip")
    sentinel.parent.mkdir(exist_ok=True)
    sentinel.write_bytes(b"keep")
    with pytest.raises(FileExistsError):
        build(ROOT, target)
    assert sentinel.read_bytes() == b"keep"


@pytest.mark.parametrize(
    "relative", ["docs/d15-invalid", "release/d14-offline-02/new", ".tools/private/new"]
)
def test_source_or_private_overlap_rejected(relative):
    from scripts.build_d15 import validate_target

    target = ROOT / relative
    with pytest.raises(ValueError, match="OVERLAP|PRIVATE"):
        validate_target(ROOT, target)
    assert not target.exists()


def test_changed_input_fails_before_output(tmp_path):
    from scripts.build_d15 import build

    source = tmp_path / "source"
    (source / "release").mkdir(parents=True)
    (source / "release/d14-offline-02.zip").write_bytes(b"changed")
    target = tmp_path / "target"
    with pytest.raises(ValueError, match="PINNED_SOURCE"):
        build(source, target)
    assert not target.exists()


@pytest.mark.parametrize(
    "name", ["../out", "/out", "C:/out", "x\\out", "x:ads", "CON", "x. ", "x/../out"]
)
def test_unsafe_zip_path_rejected(tmp_path, name):
    from scripts.verify_d15 import safe_zip

    archive = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive, "w") as out:
        info = zipfile.ZipInfo("entry")
        info.filename = name
        out.writestr(info, "bad")
    with pytest.raises(ValueError, match="PATH"):
        safe_zip(archive)


def test_case_alias_zip_and_symlink_rejected(tmp_path):
    from scripts.verify_d15 import safe_zip

    archive = tmp_path / "alias.zip"
    with zipfile.ZipFile(archive, "w") as out:
        out.writestr("File", "one")
        out.writestr("file", "two")
    with pytest.raises(ValueError, match="DUPLICATE"):
        safe_zip(archive)
    linked = tmp_path / "link.zip"
    info = zipfile.ZipInfo("link")
    info.create_system = 3
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(linked, "w") as out:
        out.writestr(info, "outside")
    with pytest.raises(ValueError, match="LINK"):
        safe_zip(linked)


def test_zip_expansion_limit_checked(tmp_path):
    from scripts.verify_d15 import safe_zip

    path = tmp_path / "large.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as out:
        out.writestr("data", b"a" * 101)
    with pytest.raises(ValueError, match="LIMIT"):
        safe_zip(path, max_bytes=100)


def test_cli_integrity_passes_strict_gate_blocks_without_writes(clean):
    before = sorted(p.relative_to(clean).as_posix() for p in clean.rglob("*") if p.is_file())
    for strict, code in [(False, 0), (True, 2)]:
        args = [sys.executable, "-I", str(clean / "verify.py"), "--bundle", str(clean)]
        if strict:
            args.append("--strict")
        result = subprocess.run(args, capture_output=True, text=True, check=False)
        assert result.returncode == code, result.stderr
        data = json.loads(result.stdout)
        assert data["integrity_verified"] and not data["p0_release_ready"]
    assert before == sorted(
        p.relative_to(clean).as_posix() for p in clean.rglob("*") if p.is_file()
    )
