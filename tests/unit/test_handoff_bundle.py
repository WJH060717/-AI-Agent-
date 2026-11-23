import json

import pytest

from scripts.handoff_bundle import copy_selection, safe_path, verify


@pytest.mark.parametrize("name", ["../secret", "C:/secret", "/secret", "a\\b", "a/../b", "a//b"])
def test_handoff_refuses_unsafe_paths(tmp_path, name):
    with pytest.raises(ValueError):
        safe_path(tmp_path, name)


def test_handoff_never_overwrites_destination(tmp_path):
    source, target = tmp_path / "source", tmp_path / "target"
    source.mkdir()
    target.mkdir()
    (target / "keep").write_text("original")
    with pytest.raises(FileExistsError):
        copy_selection(source, target, {})
    assert (target / "keep").read_text() == "original"


def test_handoff_manifest_detects_changes_and_excludes_runtime(tmp_path):
    source, target = tmp_path / "source", tmp_path / "target"
    source.mkdir()
    (source / "code.py").write_text("pass\n")
    records = copy_selection(source, target, {"project/code.py": "code.py"})
    (target / "manifest.json").write_text(json.dumps({"files": records}))
    verify(target)
    (target / "_local").mkdir()
    (target / "_local/access.json").write_text('"local only"')
    verify(target)
    (target / "project/code.py").write_text("changed")
    with pytest.raises(ValueError, match="CHANGED"):
        verify(target)


def test_handoff_refuses_secret_inputs_and_link_before_writes(tmp_path):
    source, target = tmp_path / "source", tmp_path / "target"
    source.mkdir()
    (source / ".env").write_text("secret")
    with pytest.raises(ValueError):
        copy_selection(source, target, {"project/.env": ".env"})
    assert not target.exists()


def test_handoff_refuses_existing_runtime_in_package_selection(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "token.txt").write_text("secret")
    with pytest.raises(ValueError):
        copy_selection(source, tmp_path / "target", {"_local/access.json": "token.txt"})


def test_handoff_seal_keeps_nested_manifests_and_refuses_started_bundle(tmp_path):
    import zipfile

    from scripts.handoff_bundle import seal

    root = tmp_path / "bundle"
    (root / "project/data").mkdir(parents=True)
    (root / "project/data/manifest.json").write_text('{"original":true}')
    seal(root, tmp_path / "bundle.zip")
    with zipfile.ZipFile(tmp_path / "bundle.zip") as z:
        assert z.read("project/data/manifest.json") == b'{"original":true}'
    started = tmp_path / "started"
    (started / "_local").mkdir(parents=True)
    with pytest.raises(ValueError, match="STARTED"):
        seal(started, tmp_path / "another.zip")


@pytest.mark.parametrize("existing", ["manifest", "digest"])
def test_seal_refuses_all_existing_outputs_before_mutation(tmp_path, existing):
    from scripts.handoff_bundle import seal

    root = tmp_path / "bundle"
    root.mkdir()
    (root / "source.txt").write_text("source")
    protected = root / "manifest.json" if existing == "manifest" else tmp_path / "bundle.sha256.txt"
    protected.write_text("preserve original")
    with pytest.raises(FileExistsError):
        seal(root, tmp_path / "bundle.zip")
    assert protected.read_text() == "preserve original"
    assert not (tmp_path / "bundle.zip").exists()


def test_changed_docker_context_is_rejected_before_compose():
    import os
    import subprocess
    from pathlib import Path

    if os.name != "nt":
        pytest.skip("Windows PowerShell launcher")
    common = Path(__file__).resolve().parents[2] / "infra/handoff/Common.ps1"
    quoted = str(common).replace("'", "''")
    script = f"""
    . '{quoted}'
    function Invoke-HandoffDocker([string[]]$Arguments) {{
      if ($Arguments[0] -eq 'context' -and $Arguments[1] -eq 'show') {{ return 'other-local' }}
      if ($Arguments[0] -eq 'context') {{ return 'npipe:////./pipe/dockerDesktopLinuxEngine' }}
      if ($Arguments[0] -eq 'version') {{ return 'linux/amd64' }}
      throw 'Unexpected Docker operation'
    }}
    $env:DOCKER_HOST = $null
    $state = [PSCustomObject]@{{docker_context='original';docker_endpoint='npipe:////./pipe/dockerDesktopLinuxEngine'}}
    try {{ $null = Assert-EngineBinding $state; exit 7 }}
    catch {{ if ($_.Exception.Message -like '*different Docker*') {{ exit 0 }}; exit 8 }}
    """
    run = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command", script], capture_output=True, timeout=20
    )
    assert run.returncode == 0


def test_windows_powershell_atomic_state_update(tmp_path):
    import os
    import subprocess
    from pathlib import Path

    if os.name != "nt":
        pytest.skip("Windows PowerShell launcher")
    common = str(Path(__file__).resolve().parents[2] / "infra/handoff/Common.ps1").replace(
        "'", "''"
    )
    state = str(tmp_path / "state.json").replace("'", "''")
    script = (f". '{common}'; Write-LocalJson '{state}' @{{version=1}}; "
              f"Write-LocalJson '{state}' @{{version=2}}")
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command", script], capture_output=True, timeout=20
    )
    assert result.returncode == 0
    assert json.loads((tmp_path / "state.json").read_bytes())["version"] == 2


@pytest.mark.parametrize("tampered", [False, True])
def test_full_verification_without_optional_hash_cmdlet(tmp_path, tampered):
    import hashlib
    import os
    import shutil
    import subprocess
    from pathlib import Path

    if os.name != "nt":
        pytest.skip("Windows PowerShell launcher")
    source = Path(__file__).resolve().parents[2] / "infra/handoff"
    records = {}
    for name in ("Start.ps1", "Stop.ps1", "Common.ps1", "Verify.ps1",
                 "compose.yaml", "images.json", "images.tar"):
        path = tmp_path / name
        if name in {"Common.ps1", "Verify.ps1"}:
            shutil.copyfile(source / name, path)
        else:
            path.write_bytes(b"fixture")
        records[name] = {"bytes": path.stat().st_size,
                         "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    (tmp_path / "manifest.json").write_text(json.dumps({
        "version": "dev24-handoff@1", "files": records,
    }))
    if tampered:
        (tmp_path / "images.tar").write_bytes(b"changed")
    quoted = str(tmp_path / "Verify.ps1").replace("'", "''")
    # Reproduce a mixed PowerShell host where this optional function is unavailable.
    command = f"function Get-FileHash {{ throw 'unavailable' }}; & '{quoted}'"
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command", command], capture_output=True, timeout=30
    )
    assert (result.returncode == 0) == (not tampered)


@pytest.mark.parametrize("kind", ["index", "platform", "config", "unknown"])
def test_docker_content_ids_accept_only_archived_image(kind):
    import os
    import subprocess
    from pathlib import Path

    if os.name != "nt":
        pytest.skip("Windows PowerShell launcher")
    common = str(Path(__file__).resolve().parents[2] / "infra/handoff/Common.ps1").replace(
        "'", "''"
    )
    ids = {name: "sha256:" + char * 64 for name, char in
           zip(("index", "platform", "config", "unknown"), "abcd", strict=True)}
    expected = "$false" if kind == "unknown" else "$true"
    command = (
        f". '{common}'; $image=[PSCustomObject]@{{id='{ids['index']}'; "
        f"config_id='{ids['config']}'; platform_id='{ids['platform']}'}}; "
        f"if ((Test-HandoffImageId $image '{ids[kind]}') -ne {expected}) {{ exit 5 }}"
    )
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command", command], capture_output=True, timeout=30
    )
    assert result.returncode == 0
