"""Offline acceptance/evidence validation. Never imported by API, worker or Agent."""

import argparse
import ast
import hashlib
import json
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import Field, ValidationError

from packages.contracts.models import Contract, Digest
from scripts.release_manifest import manifest_digest, read_file, verify_manifest

NONWAIVABLE = {"TC-008", "TC-009", "TC-022", "TC-023", "TC-024", "TC-030", "TC-031", "TC-032"}
REQUIRED_CHECKS = {
    "python",
    "ruff",
    "format",
    "dependencies",
    "typegen",
    "typecheck",
    "lint",
    "build",
    "inventory",
    "postgres",
    "browser_d8",
    "browser_native",
    "contracts",
    "versions",
}


class GateError(ValueError):
    pass


class Case(Contract):
    id: str = Field(pattern=r"^TC-\d{3}$")
    requirement: str = Field(pattern=r"^REQ-00[1-8]$")
    scope: Literal["implemented", "partial", "blocked"]
    tests: list[str]
    limitation: str = Field(min_length=1)


class Acceptance(Contract):
    version: Literal["d10-acceptance@1.0.0", "d11-acceptance@1.0.0", "d12-acceptance@1.0.0"]
    cases: list[Case]


class Defect(Contract):
    id: str = Field(pattern=r"^D1[01]-\d{3}$")
    priority: Literal["P0", "P1", "P2"]
    state: Literal["open", "resolved"]
    cases: list[str] = Field(min_length=1)
    title: str = Field(min_length=1)
    next: str = Field(min_length=1)


class Defects(Contract):
    version: Literal["d10-defects@1.0.0", "d11-defects@1.0.0", "d12-defects@1.0.0"]
    priority_policy: str
    defects: list[Defect]


class CheckRecord(Contract):
    name: str
    command: list[str] = Field(min_length=1)
    exit_code: int
    started_at: datetime
    finished_at: datetime
    log: str
    log_sha256: Digest
    freeze_sha256: Digest
    outputs: dict[str, Digest] = Field(default_factory=dict)


def validate_acceptance(
    root: Path,
    acceptance: dict | None = None,
    defects_payload: dict | None = None,
    *,
    stage: str = "d10",
) -> tuple[list[Case], list[Defect]]:
    try:
        cases = Acceptance.model_validate(
            acceptance
            if acceptance is not None
            else json.loads(read_file(root, f"docs/{stage}-acceptance.json"))
        ).cases
        defects = Defects.model_validate(
            defects_payload
            if defects_payload is not None
            else json.loads(read_file(root, f"docs/{stage}-defects.json"))
        ).defects
        expected = {f"TC-{i:03d}" for i in range(1, 41)}
        if len(cases) != 40 or {c.id for c in cases} != expected:
            raise GateError("ACCEPTANCE_CASES_INCOMPLETE")
        if len({d.id for d in defects}) != len(defects) or any(
            not set(d.cases) <= expected for d in defects
        ):
            raise GateError("INVALID_DEFECT_MAPPING")
        for case in cases:
            number = int(case.id[3:])
            requirement = next(
                i for i, end in enumerate((4, 9, 15, 20, 27, 30, 36, 40), 1) if number <= end
            )
            if case.requirement != f"REQ-{requirement:03d}":
                raise GateError("REQUIREMENT_MAPPING_MISMATCH")
            if case.id in NONWAIVABLE and case.scope != "implemented":
                raise GateError("NONWAIVABLE_CASE_DOWNGRADED")
            if case.scope == "implemented" and not case.tests:
                raise GateError("MISSING_TEST_MAPPING")
            if case.scope != "implemented" and not any(
                d.state == "open" and d.priority in {"P0", "P1"} and case.id in d.cases
                for d in defects
            ):
                raise GateError("UNTRACKED_ACCEPTANCE_GAP")
            for selector in case.tests:
                filename, *function = selector.split("::")
                raw = read_file(root, filename)
                if filename.endswith(".py"):
                    if len(function) != 1 or function[0] not in {
                        n.name for n in ast.parse(raw).body if isinstance(n, ast.FunctionDef)
                    }:
                        raise GateError("TEST_FUNCTION_NOT_FOUND")
                elif (
                    not filename.startswith("apps/web/tests/")
                    or not filename.endswith(".spec.ts")
                    or function
                ):
                    raise GateError("INVALID_TEST_SELECTOR")
        return cases, defects
    except (OSError, ValueError, SyntaxError) as exc:
        if isinstance(exc, GateError):
            raise
        raise GateError("INVALID_ACCEPTANCE_EVIDENCE") from exc


def read_pytest_evidence(path: Path) -> set[str]:
    if path.stat().st_size > 10_000_000:
        raise GateError("TEST_EVIDENCE_TOO_LARGE")
    cases = ET.fromstring(path.read_bytes()).findall(".//testcase")
    if not cases or any(
        list(case) and any(c.tag in {"error", "failure", "skipped"} for c in case) for case in cases
    ):
        raise GateError("TESTS_FAILED_SKIPPED_OR_EMPTY")
    return {
        case.attrib["classname"].replace(".", "/") + ".py::" + case.attrib["name"].split("[")[0]
        for case in cases
    }


def record_check(
    name: str,
    command: list[str],
    exit_code: int,
    log: Path,
    frozen: str,
    started: str,
    *,
    outputs: list[Path] | None = None,
) -> dict:
    return CheckRecord(
        name=name,
        command=command,
        exit_code=exit_code,
        started_at=started,
        finished_at=datetime.now(UTC),
        log=str(log.resolve()),
        log_sha256=hashlib.sha256(log.read_bytes()).hexdigest(),
        freeze_sha256=frozen,
        outputs={
            str(path.resolve()): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in outputs or []
            if path.is_file()
        },
    ).model_dump(mode="json")


def check_record(payload: dict, frozen: str) -> CheckRecord:
    try:
        record = CheckRecord.model_validate(payload)
        if (
            record.freeze_sha256 != frozen
            or record.started_at.tzinfo is None
            or record.finished_at < record.started_at
        ):
            raise GateError("CHECK_VERSION_OR_TIME_MISMATCH")
        if hashlib.sha256(Path(record.log).read_bytes()).hexdigest() != record.log_sha256:
            raise GateError("CHECK_LOG_CHANGED")
        if any(
            hashlib.sha256(Path(path).read_bytes()).hexdigest() != expected
            for path, expected in record.outputs.items()
        ):
            raise GateError("CHECK_OUTPUT_CHANGED")
        return record
    except (ValidationError, OSError, TypeError) as exc:
        raise GateError("CHECK_EVIDENCE_INVALID") from exc


def readiness(
    cases: list[Case], defects: list[Defect], *, engineering_passed: bool, data_ready: bool = False
) -> dict:
    incomplete = [c.id for c in cases if c.scope != "implemented"]
    blockers = [d.id for d in defects if d.state == "open" and d.priority in {"P0", "P1"}]
    return {
        "engineering_passed": engineering_passed,
        "p0_release_ready": engineering_passed and data_ready and not incomplete and not blockers,
        "data_and_labels_ready": data_ready,
        "incomplete_cases": incomplete,
        "open_release_blockers": blockers,
    }


def required_checks(stage: str) -> set[str]:
    if stage not in {"d10", "d11", "d12"}:
        raise GateError("INVALID_STAGE")
    if stage == "d12":
        return REQUIRED_CHECKS | {
            "evaluation",
            "evaluation_verify",
            "analysis",
            "recovery",
            "browser_d11",
        }
    return REQUIRED_CHECKS | (
        {"evaluation", "evaluation_verify", "benchmark", "browser_d11"} if stage == "d11" else set()
    )


def check_experiments(records: list[CheckRecord]) -> None:
    from scripts.d11_evidence import verify_benchmark, verify_evaluation

    expected = {
        "benchmark": {"protocol.json", "samples.jsonl", "summary.json", "benchmark-verified.json"},
        "evaluation": {
            "config.json",
            "preflight.json",
            "manifest.json",
            "predictions.jsonl",
            "metrics.json",
        },
        "evaluation_verify": {
            "config.json",
            "preflight.json",
            "manifest.json",
            "predictions.jsonl",
            "metrics.json",
            "evaluation-verified.json",
        },
    }
    for record in records:
        if record.name not in expected or record.exit_code:
            continue
        outputs = {Path(name).name: Path(name) for name in record.outputs}
        if not expected[record.name] <= outputs.keys():
            raise GateError("EXPERIMENT_OUTPUT_UNBOUND")
        names = expected[record.name] - {"benchmark-verified.json", "evaluation-verified.json"}
        folders = {outputs[name].parent for name in names}
        if len(folders) != 1:
            raise GateError("EXPERIMENT_OUTPUT_SCOPE_MISMATCH")
        if record.name == "benchmark":
            verify_benchmark(folders.pop())
        else:
            verify_evaluation(folders.pop())


def evaluate(
    root: Path, frozen: str, checks: list[dict], junit: Path, *, stage: str = "d10"
) -> dict:
    from eval.freeze import verify_freeze

    cases, defects = validate_acceptance(root, stage=stage)
    records = [check_record(record, frozen) for record in checks]
    if stage == "d11":
        check_experiments(records)
    if stage == "d12":
        from scripts.d12_evidence import check_d12_experiments

        check_experiments(records)
        check_d12_experiments(records)
    names = {record.name for record in records}
    if len(names) != len(records):
        raise GateError("DUPLICATE_CHECK_RECORD")
    missing = sorted(required_checks(stage) - names)
    failed = [record.name for record in records if record.exit_code != 0]
    if "python" in names and "python" not in failed:
        execution = next(record for record in records if record.name == "python")
        if str(junit.resolve()) not in execution.outputs:
            raise GateError("PYTEST_REPORT_UNBOUND")
    passed_tests = (
        read_pytest_evidence(junit) if "python" in names and "python" not in failed else set()
    )
    missing_tests = sorted(
        {
            selector
            for case in cases
            for selector in case.tests
            if "::" in selector and selector not in passed_tests
        }
    )
    safety_tests = {
        selector
        for case in cases
        if case.id in NONWAIVABLE
        for selector in case.tests
        if "::" in selector
    }
    safe = (
        safety_tests <= passed_tests
        and "browser_native" in names
        and "browser_native" not in failed
    )
    inventory = verify_freeze(root, json.loads(read_file(root, "eval/freeze-d9.json")))
    return {
        **readiness(
            cases,
            defects,
            engineering_passed=not (missing or failed or missing_tests) and safe,
            data_ready=inventory["data_collection_complete"]
            and inventory["labels_review_complete"],
        ),
        "nonwaivable_safety_passed": safe,
        "missing_checks": missing,
        "failed_checks": failed,
        "missing_mapped_tests": missing_tests,
        "pytest_report_sha256": hashlib.sha256(junit.read_bytes()).hexdigest()
        if junit.is_file()
        else None,
        "freeze_sha256": frozen,
        "basis": (
            "Local process evidence; not a third-party attestation or formal dataset evaluation."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Recheck D10 evidence without rerunning tests")
    parser.add_argument("--freeze", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--require-release", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    try:
        frozen = json.loads(args.freeze.read_bytes())
        verify_manifest(root, frozen)
        checks = json.loads((args.evidence / "checks.json").read_bytes())
        identity = manifest_digest(frozen)
        if checks["freeze_sha256"] != identity:
            raise GateError("CHECK_VERSION_MISMATCH")
        stage = frozen["version"].split("-")[0]
        result = evaluate(
            root, identity, checks["checks"], args.evidence / "pytest.xml", stage=stage
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))
        if not result["engineering_passed"]:
            raise SystemExit(1)
        if args.require_release and not result["p0_release_ready"]:
            raise SystemExit(2)
    except (OSError, ValueError, KeyError, ET.ParseError) as exc:
        parser.exit(1, f"D10_EVIDENCE_INVALID:{type(exc).__name__}\n")


if __name__ == "__main__":
    main()
