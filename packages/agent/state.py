import json
from datetime import UTC, datetime

from sqlalchemy import select

from packages.contracts.agent import BudgetUsed
from packages.contracts.models import AgentBudget
from packages.storage import schema_v5 as t
from packages.storage.service import digest, now


def config_version(settings) -> str:
    from packages.agent.cache import pipeline_version
    from packages.knowledge.catalog import identity

    return digest(
        json.dumps(
            [
                settings.model_provider,
                settings.model_name,
                settings.model_base_url,
                settings.model_timeout_seconds,
                settings.model_output_tokens_per_call,
                settings.model_test_stub,
                settings.model_thinking,
                settings.model_plan_fact_limit,
                str(settings.model_input_usd_per_million),
                str(settings.model_output_usd_per_million),
                settings.model_price_version,
                settings.agent_max_cost_microusd,
                pipeline_version(),
                identity(settings.knowledge_enabled),
            ]
        ).encode()
    )


def initialize(conn, workspace: str, run_id: str, mode: str, budget: AgentBudget, settings) -> None:
    from packages.agent.assessment import policy
    from packages.knowledge.catalog import identity

    assessment_config = policy().model_dump(mode="json")
    budget = budget.model_copy(
        update={
            "max_cost_microusd": min(
                budget.max_cost_microusd
                if budget.max_cost_microusd is not None
                else settings.agent_max_cost_microusd,
                settings.agent_max_cost_microusd,
            )
        }
    )
    payload = {
        "knowledge_version": identity(settings.knowledge_enabled),
        "assessment_config": assessment_config,
        "assessment_config_hash": digest(json.dumps(assessment_config, sort_keys=True).encode()),
        "assessment_before": None,
        "assessment_current": None,
        "assessment_changes": [],
        "query_stop_reason": None,
        "requested_mode": mode,
        "budget": budget.model_dump(),
        "used": BudgetUsed().model_dump(),
        "model_config_version": config_version(settings),
        "model_metadata": {
            "provider": settings.model_provider,
            "name": settings.model_name or "disabled",
            "test_stub": settings.model_test_stub,
            "thinking": settings.model_thinking,
            "plan_fact_limit": settings.model_plan_fact_limit,
            "price_version": settings.model_price_version,
        },
        "agent_version": "bounded_agent@2.0.0",
        "prompt_version": "evidence_agent@2.3.0",
        "started_at": None,
        "planning_rounds": 0,
        "retrieved": [],
        "no_new": 0,
        "next_seq": 1,
        "pending_action": None,
        "pending_tool": None,
        "repair_count": 0,
        "draft": None,
        "validated_claims": [],
        "rejected": [],
        "stop_reason": None,
        "report_mode": "deterministic_fallback",
        "cache_hits": 0,
    }
    conn.execute(
        t.agent_states.insert().values(
            workspace_id=workspace,
            id=run_id,
            phase="queued",
            version=0,
            payload=payload,
            updated_at=now(),
        )
    )
    conn.execute(
        t.agent_transitions.insert().values(
            workspace_id=workspace,
            run_id=run_id,
            version=0,
            phase="queued",
            reason="CREATED",
            occurred_at=now(),
            budget_used=payload["used"],
        )
    )


def checkpoint(
    conn, workspace: str, run_id: str, expected: int, phase: str, payload: dict, reason: str
) -> int:
    version = expected + 1
    result = conn.execute(
        t.agent_states.update()
        .where(
            t.agent_states.c.workspace_id == workspace,
            t.agent_states.c.id == run_id,
            t.agent_states.c.version == expected,
        )
        .values(phase=phase, version=version, payload=payload, updated_at=now())
    )
    if result.rowcount != 1:
        raise RuntimeError("Agent state version changed")
    conn.execute(
        t.agent_transitions.insert().values(
            workspace_id=workspace,
            run_id=run_id,
            version=version,
            phase=phase,
            reason=reason[:100],
            occurred_at=now(),
            budget_used=payload["used"],
        )
    )
    return version


def external_terminal(conn, workspace: str, run_id: str, phase: str) -> None:
    row = (
        conn.execute(
            select(t.agent_states).where(
                t.agent_states.c.workspace_id == workspace, t.agent_states.c.id == run_id
            )
        )
        .mappings()
        .first()
    )
    if row is not None:
        payload = dict(row["payload"])
        payload["stop_reason"] = phase.upper()
        checkpoint(conn, workspace, run_id, row["version"], phase, payload, phase.upper())
        conn.execute(
            t.agent_actions.update()
            .where(
                t.agent_actions.c.workspace_id == workspace,
                t.agent_actions.c.run_id == run_id,
                t.agent_actions.c.status == "reserved",
            )
            .values(status="abandoned", error_code=phase.upper(), ended_at=now())
        )


def elapsed(payload: dict) -> float:
    return (
        0
        if not payload["started_at"]
        else max(
            0, (datetime.now(UTC) - datetime.fromisoformat(payload["started_at"])).total_seconds()
        )
    )
