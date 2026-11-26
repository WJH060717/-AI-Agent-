import json

from packages.detection.auth_guess import R31Config, detect_auth_failure_guessing
from packages.ingest.parsers import parse_record
from tests.integration.d4_helpers import auth_record, parse_context, raw_lines


def auth_events(records):
    raw = raw_lines(records)
    context = parse_context("linux_auth", raw)
    return [
        parse_record(line, index + 1, context)
        for index, line in enumerate(raw.splitlines())
    ]


def test_pure_single_account_failures_fire_only_without_success():
    records = [auth_record(i, "failure") for i in range(8)]
    findings = detect_auth_failure_guessing(auth_events(records), "session")
    assert len(findings) == 1 and findings[0]["pattern"] == "single_account"
    assert findings[0]["failure_count"] == 8 and findings[0]["distinct_accounts"] == 1
    assert findings[0]["kind"] == "auth_failure_guessing"
    assert "normal" not in findings[0]["interpretation"].lower()
    assert len(findings[0]["evidence_ids"]) == 8

    short = detect_auth_failure_guessing(auth_events(records[:7]), "session")
    assert short == []

    with_success = auth_events(
        [*records, auth_record(8, "success") | {"session_id": "ses-1"}]
    )
    assert detect_auth_failure_guessing(with_success, "session") == []


def test_repeated_delivery_is_deduplicated_and_spray_needs_distinct_accounts():
    duplicate = [auth_record(0, "failure") for _ in range(8)]
    assert detect_auth_failure_guessing(auth_events(duplicate), "session") == []

    spray = []
    for index in range(8):
        account = f"u{index % 5}"
        spray.append(
            auth_record(index, "failure")
            | {"user": {"name": account, "uid": str(1000 + index % 5), "realm": "local"}}
        )
    findings = detect_auth_failure_guessing(auth_events(spray), "session")
    assert len(findings) == 1 and findings[0]["pattern"] == "multi_account_spray"
    assert findings[0]["distinct_accounts"] == 5

    two_accounts = spray[:5] + [spray[0] | {"timestamp": "2026-11-14T01:00:30Z"}] * 3
    assert detect_auth_failure_guessing(auth_events(two_accounts), "session") == []


def test_rule_freeze_rejects_drift():
    from packages.detection.auth_guess import load_rule

    rule = load_rule()
    assert rule.version == "1.0.0" and isinstance(rule, R31Config)