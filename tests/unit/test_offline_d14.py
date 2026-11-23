import hashlib
import json
import shutil
import socket
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import build_d14, network_guard_d14, offline_d14

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def clean_bundle(tmp_path_factory):
    target = tmp_path_factory.mktemp("d14") / "bundle"
    build_d14.build(ROOT, ROOT / ".tools/d13-wheels", target)
    return target


@pytest.fixture
def bundle(tmp_path, clean_bundle):
    target = tmp_path / "bundle"
    shutil.copytree(clean_bundle, target)
    return target


def test_bundle_has_complete_hash_locked_wheels(clean_bundle):
    value = offline_d14.verify(clean_bundle)
    assert len(value["wheels"]) == 34
    assert value["platform"] == "win-amd64-cp313"
    text = (clean_bundle / "requirements-hashed.txt").read_text()
    assert text.count("--hash=sha256:") == 34


@pytest.mark.parametrize("kind", ["changed", "missing", "extra"])
def test_wheel_drift_rejected(bundle, kind):
    wheel = next((bundle / "wheels").glob("*.whl"))
    if kind == "changed":
        wheel.write_bytes(wheel.read_bytes() + b"changed")
    elif kind == "missing":
        wheel.unlink()
    else:
        (bundle / "wheels/unapproved.whl").write_bytes(b"not-approved")
    with pytest.raises(ValueError):
        offline_d14.verify(bundle)


def test_fixed_d13_helper_cannot_be_reapproved_by_manifest(bundle):
    path = bundle / "tools/deploy_d13.py"
    path.write_bytes(path.read_bytes() + b"\nchanged\n")
    manifest_path = bundle / "offline-manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest["files"]["tools/deploy_d13.py"] = {
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "bytes": path.stat().st_size,
    }
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="HELPER_CHANGED"):
        offline_d14.verify(bundle)


def test_package_existing_target_is_untouched(clean_bundle):
    before = (clean_bundle / "offline-manifest.json").read_bytes()
    with pytest.raises(FileExistsError):
        build_d14.build(ROOT, ROOT / ".tools/d13-wheels", clean_bundle)
    assert (clean_bundle / "offline-manifest.json").read_bytes() == before


def test_existing_runtime_rejected_before_spawn(clean_bundle, tmp_path, monkeypatch):
    target = tmp_path / "existing"
    target.mkdir()
    sentinel = target / "database"
    sentinel.write_bytes(b"keep")
    monkeypatch.setattr(offline_d14.subprocess, "run", lambda *a, **k: pytest.fail("spawned"))
    with pytest.raises(ValueError, match="TARGET_EXISTS"):
        offline_d14.prepare(clean_bundle, target, 18041)
    assert sentinel.read_bytes() == b"keep"


def test_wrong_platform_fails_before_target_creation(clean_bundle, tmp_path, monkeypatch):
    monkeypatch.setattr(offline_d14, "platform_key", lambda: "linux-cp313")
    target = tmp_path / "wrong-platform"
    with pytest.raises(ValueError, match="PLATFORM"):
        offline_d14.prepare(clean_bundle, target, 18041)
    assert not target.exists()


def test_install_subprocess_failure_does_not_mark_success(clean_bundle, tmp_path, monkeypatch):
    import subprocess

    def fail(*a, **k):
        raise subprocess.CalledProcessError(2, ["venv"])

    monkeypatch.setattr(offline_d14.subprocess, "run", fail)
    target = tmp_path / "failed"
    with pytest.raises(ValueError, match="STEP_FAILED"):
        offline_d14.prepare(clean_bundle, target, 18041)
    assert target.is_dir()
    assert not (target / "installed.json").exists()


def test_installer_args_never_allow_index_or_cache(clean_bundle, tmp_path):
    args = offline_d14.pip_arguments(clean_bundle, tmp_path)
    assert "--no-index" in args and "--no-cache-dir" in args and "--require-hashes" in args
    assert not any(a.startswith("http") for a in args)


@pytest.mark.parametrize("name", ["../escape", "C:/escape", "tools\\bad"])
def test_manifest_paths_checked_before_execution(bundle, name):
    path = bundle / "offline-manifest.json"
    value = json.loads(path.read_bytes())
    value["files"][name] = value["files"].pop("offline.py")
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="PATH"):
        offline_d14.verify(bundle)


@pytest.mark.parametrize("host", ["192.0.2.1", "example.invalid", "0.0.0.0", "::ffff:192.0.2.1"])
def test_network_guard_rejects_before_connect(host):
    with socket.socket() as connection:
        with pytest.raises(PermissionError, match="NON_LOOPBACK"):
            network_guard_d14.check_event("socket.connect", (connection, (host, 80)))


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "localhost"])
def test_network_guard_preserves_loopback(host):
    network_guard_d14.check_event("socket.getaddrinfo", (host, 80, 0, 0, 0))


def test_guard_does_not_accept_arbitrary_module():
    with pytest.raises(ValueError, match="MODULE"):
        network_guard_d14.validate_module("os")


@pytest.mark.parametrize("inside", ["bundle", "app"])
def test_backup_cli_rejects_public_or_application_path_before_spawn(tmp_path, monkeypatch, inside):
    bundle = tmp_path / "bundle"
    target = tmp_path / "runtime"
    bundle.mkdir()
    (target / "app").mkdir(parents=True)
    destination = (bundle if inside == "bundle" else target / "app") / "private-backup"
    monkeypatch.setattr(offline_d14, "verify", lambda path: {})
    monkeypatch.setattr(
        offline_d14,
        "helper",
        lambda path: SimpleNamespace(
            load_install=lambda path: {"port": 18041}, runtime_env=lambda *a: {}
        ),
    )
    monkeypatch.setattr(offline_d14, "command", lambda *a: pytest.fail("command created"))
    monkeypatch.setattr(
        offline_d14.sys,
        "argv",
        [
            "offline.py",
            "backup",
            "--bundle",
            str(bundle),
            "--target",
            str(target),
            "--backup",
            str(destination),
        ],
    )
    with pytest.raises(SystemExit) as result:
        offline_d14.main()
    assert result.value.code == 2
    assert not destination.exists()


def test_backup_sibling_private_destination_allowed(tmp_path):
    args = offline_d14.backup_arguments(
        tmp_path / "bundle", tmp_path / "runtime", tmp_path / "private"
    )
    assert args == ["create", "--folder", str((tmp_path / "private").absolute())]
