import pytest
from pydantic import ValidationError


def progress(
    phase="queued",
    state="queued",
    actions=(),
    ready=False,
    truncated=False,
    prepared=False,
    terminal_phase=None,
):
    from packages.agent.pipeline import progress_for_run

    return progress_for_run(
        4,
        phase,
        state,
        list(actions),
        ready,
        truncated,
        prepared=prepared,
        terminal_phase=terminal_phase,
    )


def test_queued_inputs_are_available_not_verified_and_knowledge_is_not_run():
    result = progress()
    assert [s.stage for s in result.stages] == [
        "collect",
        "normalize",
        "detect",
        "trace",
        "intelligence",
        "present",
    ]
    assert [s.status for s in result.stages] == ["available"] * 3 + ["not_run"] * 3


@pytest.mark.parametrize("state", ["partial", "failed", "cancelled"])
def test_terminal_incomplete_state_never_displays_all_complete(state):
    result = progress(
        phase=state, state=state, ready=state == "partial", prepared=True, terminal_phase="querying"
    )
    stages = {s.stage: s for s in result.stages}
    assert stages["trace"].status == state
    assert stages["present"].status == (state if state == "partial" else "not_run")
    assert stages["intelligence"].status == "not_run"


def test_completed_deterministic_report_does_not_claim_intelligence_was_used():
    result = progress(phase="completed", state="completed", ready=True, truncated=True)
    assert result.stages[3].status == "partial"
    assert result.stages[4].status == "not_run"
    assert result.stages[5].status == "completed"


def test_knowledge_stage_follows_real_completed_result_and_warnings():
    action = {
        "seq": 2,
        "kind": "tool",
        "name": "get_technique_context",
        "status": "completed",
        "result_payload": {
            "data": {"items": [{"technique_id": "T1110"}]},
            "warnings": ["KNOWLEDGE_CONTEXT_ONLY"],
        },
    }
    result = progress("checking", "running", [action])
    assert result.stages[4].status == "completed"
    assert result.stages[4].action_seqs == [2]
    action["result_payload"]["warnings"].append("TECHNIQUE_NOT_IN_CURATED_SET")
    assert progress("checking", "running", [action]).stages[4].status == "partial"


def test_wrong_stage_order_or_duplicate_stages_are_rejected():
    from packages.contracts.models import PipelineProgress

    original = progress().model_dump()
    original["stages"].reverse()
    with pytest.raises(ValidationError):
        PipelineProgress.model_validate(original)


def test_truncated_knowledge_is_partial_even_without_warning():
    action = {
        "seq": 2,
        "kind": "tool",
        "name": "get_technique_context",
        "status": "completed",
        "result_payload": {
            "data": {"items": [{"technique_id": "T1110"}]},
            "warnings": ["KNOWLEDGE_CONTEXT_ONLY"],
            "truncated": True,
        },
    }
    assert progress("checking", "running", [action]).stages[4].status == "partial"


def test_later_success_does_not_hide_another_knowledge_query_partial_result():
    actions = [
        {
            "seq": 2,
            "kind": "tool",
            "name": "get_technique_context",
            "status": "completed",
            "result_payload": {"data": {"items": []}, "warnings": ["TECHNIQUE_NOT_IN_CURATED_SET"]},
        },
        {
            "seq": 4,
            "kind": "tool",
            "name": "get_technique_context",
            "status": "completed",
            "result_payload": {
                "data": {"items": [{"technique_id": "T1110"}]},
                "warnings": ["KNOWLEDGE_CONTEXT_ONLY"],
            },
        },
    ]
    stage = progress("completed", "completed", actions, ready=True).stages[4]
    assert stage.status == "partial" and stage.action_seqs == [2, 4]


def test_queued_cancellation_never_claims_trace_ran():
    result = progress("cancelled", "cancelled", terminal_phase="queued")
    assert result.stages[3].status == "not_run"


def test_terminal_state_keeps_prepared_inputs_and_targets_actual_stage():
    result = progress("cancelled", "cancelled", prepared=True, terminal_phase="drafting")
    assert [s.status for s in result.stages[:3]] == ["completed"] * 3
    assert result.stages[3].status == "completed"
    assert result.stages[5].status == "cancelled"


def test_live_prepared_graph_cropping_remains_partial_during_drafting():
    result = progress("drafting", "running", prepared=True, truncated=True)
    assert result.stages[3].status == "partial"
