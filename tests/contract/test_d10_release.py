import hashlib
import json
import subprocess

import pytest


@pytest.fixture
def source(tmp_path):
    root = tmp_path / "source"
    files = {
        "apps/api/main.py": "# API source\n",
        "packages/config.py": "# typed settings\n",
        "packages/agent/prompt.py": "# prompt\n",
        "pyproject.toml": '[project]\nversion="0.1.0.dev10"\n',
        "requirements-dev.lock": "pydantic==2.14.0\n",
        "packages/contracts/generated/openapi.json": '{"info":{"version":"0.1.0.dev10"}}',
        "rules/freeze.json": '{"version":"test-only"}',
        "eval/freeze-d9.json": '{"version":"test-only"}',
        "docs/d10-acceptance.json": "{}",
        "docs/d10-defects.json": "{}",
        "docs/d10-runbook.md": "# Candidate startup\n",
        "docs/d10-demo.md": "# Synthetic demo\n",
        "docs/d10-limitations.md": "# Not a full P0 acceptance\n",
        "apps/web/dist/index.html": '<html><script src="/assets/app.js"></script></html>',
        "apps/web/dist/assets/app.js": "window.loaded=true;",
        ".env.example": "MODEL_PROVIDER=disabled\n",
        ".env": "DATABASE_PASSWORD=private\n",
        "data/raw/private.log": "raw-private",
        "eval/ground_truth/secret.json": '{"hidden":"truth"}',
    }
    for name, value in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding="utf-8")
    (root / "infra").mkdir()
    (root / "infra/release-inputs.json").write_text(
        json.dumps(
            {
                "version": "d10-reviewed-inputs@1.0.0",
                "basis": "Synthetic unit-test input, not a human label review",
                "files": {
                    "rules/freeze.json": hashlib.sha256(
                        (root / "rules/freeze.json").read_bytes()
                    ).hexdigest()
                },
            }
        )
    )
    return root


def test_frozen_candidate_is_relocatable_and_excludes_runtime_secrets(source, tmp_path):
    from scripts.release_manifest import build_candidate, create_freeze, verify_manifest

    manifest = create_freeze(source, tmp_path / "freeze.json", "d10-test")
    target = tmp_path / "candidate"
    build_candidate(source, manifest, target)
    verify_manifest(target, manifest)
    assert (target / "apps/web/dist/assets/app.js").read_text() == "window.loaded=true;"
    assert not (target / ".env").exists() and not (target / "data/raw").exists()
    assert not (target / "eval/ground_truth").exists()
    assert "private" not in (target / "version-manifest.json").read_text()
    assert (target / "README-install.md").is_file()
    with pytest.raises(FileExistsError):
        build_candidate(source, manifest, target)
    with pytest.raises(FileExistsError):
        create_freeze(source, tmp_path / "freeze.json", "d10-test")


@pytest.mark.parametrize("change", ["modify", "add", "remove", "manifest_omission"])
def test_freeze_rejects_source_or_manifest_drift(source, tmp_path, change):
    from scripts.release_manifest import ReleaseError, create_freeze, verify_manifest

    manifest = create_freeze(source, tmp_path / "freeze.json", "d10-test")
    file = source / "packages/agent/prompt.py"
    if change == "modify":
        file.write_text("changed prompt")
    elif change == "add":
        (file.parent / "extra.py").write_text("new behavior")
    elif change == "remove":
        file.unlink()
    else:
        del manifest["files"]["packages/agent/prompt.py"]
    with pytest.raises(ReleaseError, match="FREEZE_DRIFT"):
        verify_manifest(source, manifest)


def test_freeze_rejects_paths_outside_root_even_with_matching_hash(source, tmp_path):
    from scripts.release_manifest import ReleaseError, create_freeze, verify_manifest

    manifest = create_freeze(source, tmp_path / "freeze.json", "d10-test")
    item = manifest["files"].pop("packages/agent/prompt.py")
    manifest["files"]["../outside.py"] = item
    with pytest.raises(ReleaseError):
        verify_manifest(source, manifest)


def test_freeze_rejects_directory_link_to_external_source(source, tmp_path):
    from scripts.release_manifest import ReleaseError, create_freeze

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.py").write_text("secret")
    link = source / "packages/escape"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(outside)],
            check=True,
            capture_output=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    with pytest.raises(ReleaseError, match="LINK_NOT_ALLOWED"):
        create_freeze(source, tmp_path / "freeze.json", "d10-test")


def test_freeze_requires_real_build_and_consistent_version(source, tmp_path):
    from scripts.release_manifest import ReleaseError, create_freeze

    path = source / "packages/contracts/generated/openapi.json"
    path.write_text(json.dumps({"info": {"version": "0.1.0.dev9"}}))
    with pytest.raises(ReleaseError, match="VERSION_MISMATCH"):
        create_freeze(source, tmp_path / "freeze.json", "d10-test")
    path.write_text(json.dumps({"info": {"version": "0.1.0.dev10"}}))
    (source / "apps/web/dist/index.html").unlink()
    with pytest.raises(ReleaseError, match="REQUIRED_FILE_MISSING"):
        create_freeze(source, tmp_path / "freeze.json", "d10-test")


@pytest.mark.parametrize(
    "name",
    [
        "packages/config.cp313-win_amd64.pyd",
        "packages/config.pyc",
        "packages/config.so",
        "json.py",
        "sitecustomize.py",
    ],
)
def test_freeze_rejects_untracked_executable_files(source, tmp_path, name):
    from scripts.release_manifest import ReleaseError, create_freeze, verify_manifest

    frozen = create_freeze(source, tmp_path / "freeze.json", "d10-test")
    (source / name).write_bytes(b"untrusted executable placeholder")
    with pytest.raises(ReleaseError):
        verify_manifest(source, frozen)


@pytest.mark.parametrize(
    "name",
    [
        "data/fixtures/unreviewed.jsonl",
        "tests/unreviewed.json",
        "rules/unreviewed.json",
        "apps/web/private.json",
    ],
)
def test_new_freeze_cannot_automatically_admit_unreviewed_inputs(source, tmp_path, name):
    from scripts.release_manifest import ReleaseError, create_freeze

    path = source / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('{"synthetic_test_secret":"not-approved-for-bundle"}')
    with pytest.raises(ReleaseError):
        create_freeze(source, tmp_path / "freeze.json", "d10-test")


def test_reviewed_input_bytes_cannot_drift_when_creating_new_freeze(source, tmp_path):
    from scripts.release_manifest import ReleaseError, create_freeze

    (source / "rules/freeze.json").write_text('{"changed":"configuration"}')
    with pytest.raises(ReleaseError):
        create_freeze(source, tmp_path / "freeze.json", "d10-test")
