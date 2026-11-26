"""Retrieval hints must use known evidence, preserve continuation and avoid false novelty."""

from copy import deepcopy

from tests.contract.test_d5_paths import chain


def hints(events, seeds, retrieved=(), actions=(), gaps=(), results=()):
    from packages.agent.retrieval import planning_hints

    return planning_hints(
        events, set(seeds), set(retrieved), list(actions), {"gaps": list(gaps)}, list(results)
    )


def test_strong_known_process_suggests_context_not_a_pid_or_unseen_event():
    events, _ = chain()
    parent, unseen = events[2:]
    result = hints([parent], [parent.event_id])
    query = result["queries"][0]
    assert query["tool"] == "get_process_context"
    assert query["arguments"] == {
        "process_entity_id": parent.process.entity_id,
        "depth": 1,
        "limit": 20,
    }
    assert unseen.event_id not in str(result) and unseen.process.entity_id not in str(result)
    assert result["seed_count"] == 1 and result["new_evidence_count"] == 0
    parent.process.identity_basis = "pid_only"
    assert all(
        q["tool"] != "get_process_context" for q in hints([parent], [parent.event_id])["queries"]
    )


def test_completed_same_query_is_not_suggested_and_new_tool_has_priority():
    events, _ = chain()
    process = events[3]
    action = {
        "kind": "tool",
        "name": "get_process_context",
        "status": "completed",
        "args_payload": {
            "process_entity_id": process.process.entity_id,
            "depth": 1,
            "limit": 20,
            "cursor": None,
        },
    }
    result = hints(events, [e.event_id for e in events], actions=[action])
    assert result["queries"][0]["tool"] == "get_asset_timeline"
    assert not any(
        q["tool"] == "get_process_context"
        and q["arguments"]["process_entity_id"] == process.process.entity_id
        for q in result["queries"]
    )


def test_open_gap_search_and_completed_seed_reads_do_not_count_as_new_evidence():
    events, _ = chain()
    login = events[1]
    result = hints(
        [login],
        [login.event_id],
        [login.event_id],
        gaps=[{"code": "session_process", "asset_id": str(login.asset_id)}],
    )
    assert {k: result["queries"][0][k] for k in ("tool", "arguments")} == {
        "tool": "search_events",
        "arguments": {"types": ["host.process"], "asset_id": str(login.asset_id), "limit": 20},
    }
    assert result["new_evidence_count"] == 0
    outside = events[3]
    result = hints([login, outside], [login.event_id], [outside.event_id])
    assert result["new_evidence_count"] == 1


def test_continuation_points_to_original_args_without_duplicating_or_mutating_cursor():
    events, _ = chain()
    result = {
        "name": "search_events",
        "arguments": {"types": ["host.process"], "limit": 1},
        "next_cursor": "opaque-bound-cursor",
        "coverage": {"matched": 5},
        "truncated": True,
        "warnings": ["partial"],
        "evidence_ids": [events[2].event_id],
    }
    before = deepcopy(result)
    value = hints(events[:3], [e.event_id for e in events[:3]], results=[result])
    assert value["continue_result"] == 0 and result == before
    assert "opaque-bound-cursor" not in str(value)
    result["next_cursor"] = None
    assert (
        hints(events[:3], [e.event_id for e in events[:3]], results=[result])["continue_result"]
        is None
    )


def test_planning_advice_does_not_enter_draft_or_mutate_original_context():
    import json

    from packages.agent.model import CompatibleModel
    from packages.config import Settings

    context = {"facts": [], "retrieval": {"queries": [{"tool": "search_events"}]}}
    before = deepcopy(context)
    client = CompatibleModel(Settings(_env_file=None))
    draft = json.loads(json.loads(client.request("draft", context, 100))["messages"][1]["content"])
    assert "retrieval" not in draft["untrusted_context"] and context == before


def test_query_suggestions_cover_distinct_useful_tools_within_small_context():
    events, _ = chain()
    queries = hints(events, [e.event_id for e in events])["queries"]
    assert len(queries) == 2 and len({q["tool"] for q in queries}) == 2


def test_wire_retrieved_ids_only_repeat_visible_facts_with_explicit_truncation():
    from packages.agent.context_wire import wire_context

    context = {
        "facts": [{"event_id": "a" * 64}],
        "retrieved_event_ids": ["a" * 64, "b" * 64],
        "tool_results": [{"evidence_ids": ["b" * 64], "next_cursor": "continue"}],
    }
    before = deepcopy(context)
    result = wire_context(context)
    assert result["retrieved_event_ids"] == ["a" * 64]
    assert result["retrieved_ids_truncated"] is True
    assert result["tool_results"] == context["tool_results"] and context == before


def test_plan_keeps_open_targets_while_supported_details_remain_in_draft():
    import json

    from packages.agent.model import CompatibleModel
    from packages.config import Settings

    ctx = {
        "facts": [],
        "investigation": {
            "hypotheses": [
                {"status": "supported", "supporting_event_ids": ["a" * 64]},
                {"status": "open", "supporting_event_ids": ["b" * 64]},
                {"status": "weakened", "counter_event_ids": ["c" * 64]},
            ],
            "gaps": [],
            "truncated": False,
        },
    }
    client = CompatibleModel(Settings(_env_file=None))

    def content(kind):
        return json.loads(json.loads(client.request(kind, ctx, 100))["messages"][1]["content"])[
            "untrusted_context"
        ]

    plan = content("plan")["investigation"]
    assert [h["status"] for h in plan["hypotheses"]] == ["open", "weakened"]
    assert plan["supported_hypotheses_omitted"] == 1 and plan["truncated"]
    assert content("draft")["investigation"] == ctx["investigation"]


def test_plan_omits_identity_details_but_draft_retains_them_and_quality_is_kept():
    from packages.agent.context_wire import wire_context

    fact = {
        "event_id": "a" * 64,
        "asset_id": "known-asset",
        "event_time": "t",
        "sensor": {"type": "linux_audit"},
        "host": {"boot_id": "boot"},
        "user": {"entity_id": "account-hmac"},
        "process": {"entity_id": "strong-id"},
        "time_quality": {"uncertainty_ms": 0},
        "quality_flags": ["uncertain"],
    }
    context = {"facts": [fact]}
    plan = wire_context(context, plan_fact_limit=1)
    assert all(k not in plan["facts"][0] for k in ("sensor", "host", "user"))
    assert plan["fact_identity_details_omitted"]
    assert plan["facts"][0]["process"] == fact["process"]
    assert plan["facts"][0]["time_quality"] == fact["time_quality"]
    assert plan["facts"][0]["quality_flags"] == fact["quality_flags"]
    assert wire_context(context)["facts"] == [fact]


def test_accidental_whole_snapshot_input_cannot_supply_unseen_query_anchors():
    events, _ = chain()
    seed = events[1]
    result = hints(events, [seed.event_id])
    assert all(q["tool"] != "get_process_context" for q in result["queries"])
    assert events[3].event_id not in str(result)
    assert events[3].process.entity_id not in str(result)
    assert hints(events, [])["queries"] == []
