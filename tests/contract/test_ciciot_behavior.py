import pytest

from eval.ciciot_behavior import EXPECTED, grade


@pytest.mark.parametrize(
    "historical_status,expected_hit,report_verified,controls_ready,control_hit,result",
    [
        ("cross_class", True, True, True, False, "behavior_pass"),
        ("unknown", False, True, True, False, "behavior_not_detected"),
        ("unknown", True, False, True, False, "behavior_report_unverified"),
        ("unknown", True, True, False, False, "behavior_control_unresolved"),
        ("unknown", True, True, True, True, "behavior_control_unresolved"),
        ("unverified", True, True, True, False, "unverified"),
        ("failed", True, True, True, False, "failed"),
    ],
)
def test_behavior_score_uses_only_verified_expected_hits(
    historical_status,
    expected_hit,
    report_verified,
    controls_ready,
    control_hit,
    result,
):
    expected = EXPECTED["Recon-OSScan"]
    behavior, rule, version = expected if expected_hit else EXPECTED["Recon-PortScan"]
    case = {
        "status": historical_status,
        "verified_candidates": [
            {
                "behavior_report_verified": report_verified,
                "behavior_assessments": [
                    {
                        "behavior": behavior,
                        "rule_id": rule,
                        "rule_version": version,
                        "trace_status": "unsuccessful",
                    }
                ],
            }
        ],
    }
    assert (
        grade(case, expected, controls_ready, {expected} if control_hit else set())["status"]
        == result
    )
