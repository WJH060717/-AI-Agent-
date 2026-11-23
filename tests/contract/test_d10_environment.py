import json

import pytest


def test_environment_requires_exact_python_and_installed_node_versions(tmp_path, monkeypatch):
    from scripts.verify_environment import EnvironmentMismatch, verify_environment

    (tmp_path / "requirements-dev.lock").write_text("demo-lib==1.2.3\n")
    web = tmp_path / "apps/web"
    package = web / "node_modules/demo-web"
    package.mkdir(parents=True)
    (web / "package-lock.json").write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"version": "test"},
                    "node_modules/demo-web": {"version": "2.3.4"},
                    "node_modules/optional-other-platform": {"version": "1.0.0", "optional": True},
                },
            }
        )
    )
    (package / "package.json").write_text('{"version":"2.3.4"}')
    monkeypatch.setattr("scripts.verify_environment.metadata.version", lambda name: "1.2.3")
    assert verify_environment(tmp_path)["python_packages"]["demo-lib"] == "1.2.3"
    monkeypatch.setattr("scripts.verify_environment.metadata.version", lambda name: "1.2.4")
    with pytest.raises(EnvironmentMismatch, match="PYTHON_LOCK_MISMATCH"):
        verify_environment(tmp_path)
    monkeypatch.setattr("scripts.verify_environment.metadata.version", lambda name: "1.2.3")
    (package / "package.json").write_text('{"version":"2.3.5"}')
    with pytest.raises(EnvironmentMismatch, match="NODE_LOCK_MISMATCH"):
        verify_environment(tmp_path)
    (package / "package.json").unlink()
    with pytest.raises(EnvironmentMismatch, match="NODE_PACKAGE_MISSING"):
        verify_environment(tmp_path)
