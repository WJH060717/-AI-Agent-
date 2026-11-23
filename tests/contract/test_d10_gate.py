import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def test_acceptance_covers_all_cases_without_promoting_unfinished_work():
    from scripts.d10_gate import validate_acceptance

    cases, defects = validate_acceptance(ROOT)
    assert len(cases) == 40
    assert {c.id for c in cases if c.scope == "blocked"} >= {"TC-036", "TC-037", "TC-038"}
    assert any(d.id == "D10-001" and d.state == "open" for d in defects)


@pytest.mark.parametrize("change", ["omit", "fake_test", "waive", "remove_blocker"])
def test_acceptance_rejects_missing_case_fake_evidence_or_hidden_gap(tmp_path, change):
    from scripts.d10_gate import GateError, validate_acceptance

    cases = json.loads((ROOT / "docs/d10-acceptance.json").read_bytes())
    defects = json.loads((ROOT / "docs/d10-defects.json").read_bytes())
    if change == "omit":
        cases["cases"].pop()
    elif change == "fake_test":
        cases["cases"][0]["tests"] = ["tests/nonexistent.py::test_fake"]
    elif change == "waive":
        cases["cases"][7]["scope"] = "partial"
    else:
        defects["defects"] = [d for d in defects["defects"] if "TC-036" not in d["cases"]]
    with pytest.raises(GateError):
        validate_acceptance(ROOT, cases, defects)


def test_junit_rejects_skipped_failed_empty_and_missing_safety_evidence(tmp_path):
    from scripts.d10_gate import GateError, read_pytest_evidence

    path = tmp_path / "result.xml"
    path.write_text(
        '<testsuites><testsuite><testcase classname="tests.unit.test_a" '
        'name="test_a[0]"/></testsuite></testsuites>'
    )
    assert read_pytest_evidence(path) == {"tests/unit/test_a.py::test_a"}
    for body in ("<skipped/>", "<failure/>", "<error/>"):
        path.write_text(
            '<testsuite><testcase classname="tests.unit.test_a" name="test_a">'
            f"{body}</testcase></testsuite>"
        )
        with pytest.raises(GateError):
            read_pytest_evidence(path)
    path.write_text("<testsuite/>")
    with pytest.raises(GateError):
        read_pytest_evidence(path)


def test_evidence_record_is_bound_to_real_log_and_freeze(tmp_path):
    from scripts.d10_gate import GateError, check_record, record_check

    log = tmp_path / "check.log"
    log.write_text("passed\n")
    record = record_check(
        "python", ["python", "-m", "pytest"], 0, log, "a" * 64, "2026-11-15T00:00:00+00:00"
    )
    check_record(record, "a" * 64)
    with pytest.raises(GateError):
        check_record(record, "b" * 64)
    log.write_text("changed\n")
    with pytest.raises(GateError):
        check_record(record, "a" * 64)


def test_full_release_gate_stays_blocked_with_passed_engineering_checks():
    from scripts.d10_gate import readiness, validate_acceptance

    cases, defects = validate_acceptance(ROOT)
    result = readiness(cases, defects, engineering_passed=True)
    assert result["engineering_passed"] is True
    assert result["p0_release_ready"] is False
    assert "TC-037" in result["incomplete_cases"] and "D10-001" in result["open_release_blockers"]
    assert readiness(cases, defects, engineering_passed=False)["p0_release_ready"] is False


def test_check_runner_records_actual_failure_instead_of_promoting_command(tmp_path):
    import sys

    from scripts.check_d10 import run_check

    result = run_check(
        tmp_path,
        "intentional-failure",
        [sys.executable, "-c", "print('check ran');raise SystemExit(5)"],
        tmp_path / "check.log",
        "a" * 64,
    )
    assert result["exit_code"] == 5
    assert "check ran" in (tmp_path / "check.log").read_text()


def test_release_still_requires_data_evidence_when_declared_cases_are_complete():
    from scripts.d10_gate import readiness, validate_acceptance

    cases, _ = validate_acceptance(ROOT)
    declared_complete = [case.model_copy(update={"scope": "implemented"}) for case in cases]
    assert readiness(declared_complete, [], engineering_passed=True)["p0_release_ready"] is False


def test_junit_is_bound_to_the_check_that_produced_it(tmp_path):
    from scripts.d10_gate import GateError, check_record, record_check

    log, junit = tmp_path / "python.log", tmp_path / "pytest.xml"
    log.write_text("passed")
    junit.write_text(
        '<testsuite><testcase classname="tests.unit.test_a" name="test_a"/></testsuite>'
    )
    record = record_check(
        "python",
        ["python", "-m", "pytest"],
        0,
        log,
        "a" * 64,
        "2026-11-15T00:00:00+00:00",
        outputs=[junit],
    )
    check_record(record, "a" * 64)
    junit.write_text(
        '<testsuite><testcase classname="tests.unit.test_b" name="test_b"/></testsuite>'
    )
    with pytest.raises(GateError):
        check_record(record, "a" * 64)
