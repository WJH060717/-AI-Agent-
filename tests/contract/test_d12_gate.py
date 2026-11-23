import pytest

from scripts.d10_gate import GateError, required_checks
from scripts.d12_evidence import check_d12_experiments


def test_d12_requires_recovery_analysis_and_live_regression_not_new_full_benchmark():
    needed = required_checks("d12")
    assert {"recovery", "analysis", "evaluation", "evaluation_verify", "browser_d11"} <= needed
    assert "benchmark" not in needed


def test_self_reported_recovery_without_bound_output_is_rejected():
    from types import SimpleNamespace

    with pytest.raises(GateError, match="UNBOUND"):
        check_d12_experiments([SimpleNamespace(name="recovery", exit_code=0, outputs={})])


def test_empty_analysis_cannot_satisfy_required_evidence(tmp_path):
    import json
    from types import SimpleNamespace

    from eval.analysis_d12 import build_analysis

    config = tmp_path / "input.json"
    config.write_text(
        json.dumps(
            dict(
                version="d12-analysis-inputs@1.0.0",
                files={},
                evaluations=[],
                benchmarks=[],
                screenshots=[],
            )
        )
    )
    folder = tmp_path / "analysis"
    build_analysis(tmp_path, config, folder)
    record = SimpleNamespace(
        name="analysis",
        exit_code=0,
        command=["python", "--output", str(folder)],
        outputs={str(p.resolve()): "unused" for p in folder.iterdir()},
    )
    with pytest.raises(GateError, match="ANALYSIS_EVIDENCE"):
        check_d12_experiments([record])


@pytest.mark.parametrize("collision", ["summary.json", "inputs.json", "manifest.json"])
def test_analysis_gate_selects_outputs_by_directory_not_colliding_basename(
    tmp_path, monkeypatch, collision
):
    import json
    from types import SimpleNamespace

    from scripts import d12_evidence

    folder = tmp_path / "analysis"
    folder.mkdir()
    (tmp_path / "eval").mkdir()
    config = {"screenshots": ["x.png"]}
    (tmp_path / "eval/d12-inputs.json").write_text(json.dumps(config))
    names = [
        "inputs.json",
        "manifest.json",
        "summary.json",
        "index.html",
        "resources.svg",
        "metrics.csv",
    ]
    for name in names:
        (folder / name).write_text("{}")
    (folder / "inputs.json").write_text(json.dumps(config))
    (folder / "manifest.json").write_text(json.dumps({"files": {n: "unused" for n in names}}))
    (folder / "summary.json").write_text(
        json.dumps(
            {
                "evaluations": [{"groups": {"B0": {"attempts": 1}}}],
                "benchmarks": [{"resource_series": [{"working_set_bytes": 1}]}],
            }
        )
    )
    other = tmp_path / collision
    other.write_text('{"historical_input":true}')
    outputs = {str(p.resolve()): "unused" for p in [*(folder / n for n in names), other]}
    monkeypatch.setattr(d12_evidence, "ROOT", tmp_path)
    monkeypatch.setattr(d12_evidence, "verify_analysis", lambda root, output: {"verified": True})
    check_d12_experiments(
        [
            SimpleNamespace(
                name="analysis",
                exit_code=0,
                outputs=outputs,
                command=["python", "--output", str(folder)],
            )
        ]
    )
