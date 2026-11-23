import json
import shutil
import socket
from pathlib import Path

import pytest

from scripts import build_d13, deploy_d13, record_d13

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def clean_kit(tmp_path_factory):
    target = tmp_path_factory.mktemp("d13-base") / "kit"
    build_d13.build(ROOT, target)
    return target


@pytest.fixture
def kit(tmp_path, clean_kit):
    target = tmp_path / "kit"
    shutil.copytree(clean_kit, target)
    return target


def test_kit_verifies_fixed_base_and_no_secrets(kit):
    result = deploy_d13.verify_kit(kit)
    assert result["base_freeze_sha256"] == deploy_d13.BASE_FREEZE
    assert result["application_version"] == "0.1.0.dev12"
    assert not any(p.name == ".env" for p in kit.rglob("*"))


@pytest.mark.parametrize("name", ["app/apps/api/main.py", "deploy.py", "docs/d13-runbook.md"])
def test_changed_file_rejected(kit, name):
    path = kit / name
    path.write_bytes(path.read_bytes() + b"\nchanged\n")
    with pytest.raises(deploy_d13.DeployError, match="FILE_CHANGED"):
        deploy_d13.verify_kit(kit)


def test_extra_code_and_env_rejected(kit):
    (kit / "app/.env").write_text("DATABASE_URL=sqlite:///existing.db")
    with pytest.raises(deploy_d13.DeployError, match="FILE_SET"):
        deploy_d13.verify_kit(kit)


@pytest.mark.parametrize("name", ["../outside", "C:/outside", "app/../other", "app\\bad"])
def test_manifest_path_rejected(kit, name):
    path = kit / "kit-manifest.json"
    manifest = json.loads(path.read_bytes())
    manifest["files"][name] = manifest["files"].pop("deploy.py")
    path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(deploy_d13.DeployError, match="PATH"):
        deploy_d13.verify_kit(kit)


def test_existing_target_refused_before_subprocess(kit, tmp_path, monkeypatch):
    dest = tmp_path / "keep"
    dest.mkdir()
    sentinel = dest / "valuable.db"
    sentinel.write_bytes(b"preserve")
    monkeypatch.setattr(deploy_d13.subprocess, "run", lambda *a, **kw: pytest.fail("spawned"))
    with pytest.raises(deploy_d13.DeployError, match="TARGET_EXISTS"):
        deploy_d13.install(kit, dest, 18080)
    assert sentinel.read_bytes() == b"preserve"


def test_ambient_settings_cannot_select_existing_database_or_model(tmp_path, monkeypatch):
    for key in ("DATABASE_URL", "MODEL_API_KEY", "PYTHONPATH", "PGSERVICE", "WEB_DIST"):
        monkeypatch.setenv(key, "UNSAFE")
    env = deploy_d13.runtime_env(tmp_path, 18080)
    assert env["DATABASE_URL"].endswith("/data/demo.db")
    assert env["MODEL_PROVIDER"] == "disabled"
    assert env["APP_BIND"] == "127.0.0.1"
    assert not any(env.get(k) == "UNSAFE" for k in env)
    assert "MODEL_API_KEY" not in env and "PYTHONPATH" not in env


def test_install_failure_keeps_partial_target_and_no_success(kit, tmp_path, monkeypatch):
    import subprocess

    def fail(*args, **kwargs):
        raise subprocess.CalledProcessError(17, ["venv"])

    monkeypatch.setattr(deploy_d13.subprocess, "run", fail)
    target = tmp_path / "failed"
    with pytest.raises(deploy_d13.DeployError, match="STEP_FAILED"):
        deploy_d13.install(kit, target, 18080)
    assert target.is_dir()
    assert not (target / "installed.json").exists()


def test_repeat_build_does_not_overwrite(kit):
    before = (kit / "kit-manifest.json").read_bytes()
    with pytest.raises(FileExistsError):
        build_d13.build(ROOT, kit)
    assert (kit / "kit-manifest.json").read_bytes() == before


def test_tampered_installed_path_not_used(tmp_path):
    (tmp_path / "installed.json").write_text('{"port":18080,"database_url":"foreign"}')
    with pytest.raises(deploy_d13.DeployError, match="INSTALL_RECORD"):
        deploy_d13.load_install(tmp_path)


@pytest.mark.parametrize("name", ["sitecustomize.py", ".env"])
def test_mutable_manifest_cannot_approve_extra_base_file(kit, name):
    (kit / "app" / name).write_bytes(b"# unauthorized")
    path = kit / "kit-manifest.json"
    manifest = json.loads(path.read_bytes())
    manifest["files"][f"app/{name}"] = deploy_d13.file_records(kit / "app")[name]
    path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(deploy_d13.DeployError, match="BASE_FILE_SET"):
        deploy_d13.verify_kit(kit)


def test_installed_manifest_cannot_approve_extra_config(kit):
    (kit / "app/.env").write_text("MODEL_PROVIDER=compatible")
    record = {
        "version": deploy_d13.VERSION,
        "base_freeze_sha256": deploy_d13.BASE_FREEZE,
        "port": 18080,
        "installed_at": "2026-11-15T00:00:00+00:00",
        "app_files": deploy_d13.file_records(kit / "app"),
    }
    (kit / "installed.json").write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(deploy_d13.DeployError, match="BASE_FILE_SET"):
        deploy_d13.load_install(kit)


def test_builder_refuses_immutable_base_overlap_before_writes():
    target = ROOT / "release/d12-candidate-04/nested-d13-build"
    with pytest.raises(deploy_d13.DeployError, match="OVERLAPPING_PATH"):
        build_d13.check_target(ROOT, target)
    assert not target.exists()


def test_builder_refuses_link_parent_before_mkdir(tmp_path, monkeypatch):
    parent = tmp_path / "link"
    parent.mkdir()
    monkeypatch.setattr(Path, "is_junction", lambda path: path == parent)
    target = parent / "kit"
    with pytest.raises(deploy_d13.DeployError, match="LINK_PATH"):
        build_d13.build(ROOT, target)
    assert not target.exists()


def test_builder_refuses_existing_zip_before_creating_directory(tmp_path):
    target = tmp_path / "kit"
    target.with_suffix(".zip").write_bytes(b"keep")
    with pytest.raises(FileExistsError):
        build_d13.build(ROOT, target)
    assert not target.exists()
    assert target.with_suffix(".zip").read_bytes() == b"keep"


def test_recorder_rejects_occupied_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        with pytest.raises(ValueError, match="PORT_OCCUPIED"):
            record_d13.assert_available(listener.getsockname()[1])


def test_recorder_rejects_exited_service():
    class Exited:
        def poll(self):
            return 1

    with pytest.raises(RuntimeError, match="SERVICE_EXITED"):
        record_d13.assert_running([Exited()])
