from packages.contracts.agent import SearchArgs
from tests.contract.test_d5_paths import chain
from tests.contract.test_p1_retrieval import hints


def test_packet_query_contract_is_supported():
    assert SearchArgs(types=["network.packet"]).types == ["network.packet"]


def test_gap_advice_explains_target_without_changing_tool_arguments():
    events, _ = chain()
    event = events[1]
    result = hints(
        events,
        [event.event_id],
        gaps=[
            {"gap_id": "gap-session", "code": "session_process", "asset_id": str(event.asset_id)}
        ],
    )
    query = result["queries"][0]
    assert query["gap_id"] == "gap-session"
    assert query["expected_evidence"] and query["selection_reason"]
    SearchArgs.model_validate(query["arguments"])
    assert events[3].process.entity_id not in str(result)


def test_completed_continuation_does_not_resurrect_old_cursor():
    events, _ = chain()
    args = {"types": ["host.process"], "limit": 1}
    results = [
        {"name": "search_events", "arguments": args, "next_cursor": "old"},
        {"name": "search_events", "arguments": args | {"cursor": "old"}, "next_cursor": None},
    ]
    assert hints(events, [events[1].event_id], results=results)["continue_result"] is None


def test_html_exports_actual_evidence_increment_and_escapes_reasons():
    from packages.storage.reports import render_html

    # Existing renderer accepts dictionaries, mirroring export serialization.
    report = {
        "report_id": "report",
        "summary": "summary",
        "mode": "deterministic_fallback",
        "generated_at": "time",
        "validation": "passed",
        "claims": [],
        "provenance": {},
        "investigation_analysis": {
            "before": {"known_evidence_ids": ["a" * 64]},
            "after": {"known_evidence_ids": ["a" * 64, "b" * 64]},
            "stop_reason": "MAX_PLANNING_ROUNDS",
            "changes": [
                {
                    "action_seq": 2,
                    "before_status": "open",
                    "after_status": "weakened",
                    "reason": "<script>bad</script>",
                }
            ],
        },
    }
    result = render_html({"report": report, "evidence": [], "run_state": "completed"})
    assert "新增非种子证据 1 条" in result
    assert "#e-" + "b" * 64 in result
    assert "<script>" not in result and "&lt;script&gt;" in result


def test_changed_page_size_still_finishes_same_continuation():
    events, _ = chain()
    results = [
        {"name": "search_events", "arguments": {"limit": 1}, "next_cursor": "old"},
        {"name": "search_events", "arguments": {"limit": 2, "cursor": "old"}, "next_cursor": None},
    ]
    assert hints(events, [events[1].event_id], results=results)["continue_result"] is None
