"""Wire compaction preserves authority, unknowns and usable evidence references."""

import json
import re
from copy import deepcopy

from packages.agent.model import CompatibleModel
from packages.config import Settings


def test_wire_context_compacts_seed_ids_and_nulls_without_mutation_or_scope_loss():
    visible, hidden = "a" * 64, "b" * 64
    context = {
        "scope": {"workspace_id": "w", "snapshot_id": "s", "start": "t0", "end": "t1"},
        "facts": [
            {
                "event_id": visible,
                "auth": {"outcome": "failure", "reason": None},
                "network": {"bytes_out": 0},
                "conflict": False,
                "label": "",
            }
        ],
        "seed_event_ids": [visible, hidden],
        "seed_ids_truncated": False,
        "retrieved_event_ids": [hidden],
        "tool_results": [
            {
                "arguments": {"cursor": None, "limit": 1},
                "next_cursor": "opaque",
                "coverage": {"complete": False},
                "warnings": ["missing socket"],
                "evidence_ids": [hidden],
                "truncated": True,
            }
        ],
        "budget": {"max_input_tokens": 12000},
        "budget_used": {"input_tokens": 3000},
    }
    before = deepcopy(context)
    request = CompatibleModel(Settings(_env_file=None)).request("plan", context, 768)
    wire = json.loads(json.loads(request)["messages"][1]["content"])["untrusted_context"]
    assert context == before
    assert wire["seed_event_ids"] == [visible]
    assert wire["seed_ids_truncated"] is True
    assert wire["fact_nulls_omitted"] is True
    assert "reason" not in wire["facts"][0]["auth"]
    assert wire["facts"][0]["network"]["bytes_out"] == 0
    assert wire["facts"][0]["conflict"] is False and wire["facts"][0]["label"] == ""
    assert wire["retrieved_event_ids"] == [] and wire["retrieved_ids_truncated"]
    for key in ("scope", "tool_results", "budget", "budget_used"):
        assert wire[key] == before[key]


def test_only_schema_annotations_are_removed_not_title_fields_or_defaults():
    from packages.agent.context_wire import compact_schema

    schema = {
        "title": "Container",
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "title": {"title": "Title", "type": "string", "default": "keep this"},
            "value": {"default": {"title": "literal"}, "type": "object"},
        },
        "required": ["title"],
    }
    assert compact_schema(schema) == {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "title": {"type": "string", "default": "keep this"},
            "value": {"default": {"title": "literal"}, "type": "object"},
        },
        "required": ["title"],
    }
    assert schema["title"] == "Container"


def test_tool_wire_schema_keeps_enums_required_fields_limits_and_no_extras():
    body = json.loads(CompatibleModel(Settings(_env_file=None)).request("plan", {}, 100))
    tools = json.loads(body["messages"][1]["content"])["allowed_tools"]
    evidence = tools["get_event_evidence"]
    assert "title" not in evidence
    assert evidence["additionalProperties"] is False
    assert evidence["required"] == ["event_ids"]
    assert evidence["properties"]["event_ids"]["minItems"] == 1
    assert evidence["properties"]["event_ids"]["maxItems"] == 10
    pattern = evidence["properties"]["event_ids"]["items"]["pattern"]
    assert re.fullmatch(pattern, "a" * 64)
    assert not re.fullmatch(pattern, "g" * 64)
    search = tools["search_events"]
    assert search["properties"]["limit"]["minimum"] == 1
    assert search["properties"]["limit"]["maximum"] == 100
    assert search["properties"]["limit"]["default"] == 20
    assert "auth.login" in search["properties"]["types"]["items"]["enum"]


def test_nonvisible_seed_is_marked_truncated_and_tool_continuation_is_retained():
    context = {
        "facts": [],
        "seed_event_ids": ["a" * 64],
        "seed_ids_truncated": False,
        "tool_results": [
            {
                "arguments": {"cursor": "original-cursor"},
                "next_cursor": "next-cursor",
                "coverage": {"rows": 1},
                "warnings": ["partial"],
                "truncated": True,
            }
        ],
    }
    body = json.loads(CompatibleModel(Settings(_env_file=None)).request("plan", context, 100))
    wire = json.loads(body["messages"][1]["content"])["untrusted_context"]
    assert wire["seed_event_ids"] == [] and wire["seed_ids_truncated"]
    assert wire["tool_results"] == context["tool_results"]


def test_plan_prioritizes_retrieved_and_diverse_facts_while_draft_keeps_details():
    facts = [
        {"event_id": "a" * 64, "event_type": "auth.login", "auth": {"outcome": "failure"}},
        {"event_id": "b" * 64, "event_type": "auth.login", "auth": {"outcome": "success"}},
        {"event_id": "c" * 64, "event_type": "host.process", "process": {"pid": 7}},
    ]
    context = {"facts": facts, "retrieved_event_ids": ["c" * 64]}
    client = CompatibleModel(Settings(_env_file=None, model_plan_fact_limit=2))

    def content(kind):
        return json.loads(json.loads(client.request(kind, context, 768))["messages"][1]["content"])[
            "untrusted_context"
        ]

    plan = content("plan")
    assert [f["event_id"] for f in plan["facts"]] == ["c" * 64, "a" * 64]
    assert plan["facts_truncated"] is True
    assert content("draft")["facts"] == facts
    assert context["facts"] == facts


def test_plan_fact_limit_is_bounded_and_part_of_resume_identity():
    import pytest

    from packages.agent.state import config_version

    for value in (0, 7):
        with pytest.raises(ValueError):
            Settings(_env_file=None, model_plan_fact_limit=value)
    assert config_version(Settings(_env_file=None, model_plan_fact_limit=1)) != config_version(
        Settings(_env_file=None, model_plan_fact_limit=2)
    )


def test_wire_omits_internal_assessment_keys_but_keeps_status_and_evidence():
    context = {
        "run_id": "internal-run",
        "incident_id": "required-path-argument",
        "scope": {"snapshot_id": "bound-snapshot"},
        "investigation": {
            "hypotheses": [
                {
                    "hypothesis_id": "internal-hypothesis",
                    "rule_id": "R02",
                    "status": "open",
                    "supporting_event_ids": ["a" * 64],
                }
            ],
            "gaps": [
                {"gap_id": "internal-gap", "code": "process_socket_binding", "asset_id": "asset"}
            ],
            "truncated": False,
        },
    }
    request = CompatibleModel(Settings(_env_file=None)).request("draft", context, 768)
    wire = json.loads(json.loads(request)["messages"][1]["content"])["untrusted_context"]
    assert "run_id" not in wire
    assert wire["incident_id"] == context["incident_id"] and wire["scope"] == context["scope"]
    assert wire["investigation"]["hypotheses"] == [
        {"rule_id": "R02", "status": "open", "supporting_event_ids": ["a" * 64]}
    ]
    assert wire["investigation"]["gaps"] == [
        {"code": "process_socket_binding", "asset_id": "asset"}
    ]
    assert context["run_id"] == "internal-run"
