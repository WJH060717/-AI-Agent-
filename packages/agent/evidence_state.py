"""Checkpoint-sized, deterministic investigation comparison helpers."""

import json

from packages.agent.assessment import AssessmentPolicy, assess, changes_between, policy
from packages.contracts.models import InvestigationAssessment, InvestigationComparison
from packages.storage.service import digest


def initialize_analysis(payload: dict, tools, findings: list) -> None:
    if payload.get("assessment_before") is not None:
        return
    if "assessment_config" not in payload:
        payload["assessment_config"] = policy().model_dump(mode="json")
    frozen = payload["assessment_config"]
    payload.setdefault(
        "assessment_config_hash", digest(json.dumps(frozen, sort_keys=True).encode())
    )
    initial = assess(
        tools.events,
        tools.scope,
        findings,
        set(tools.membership["evidence_ids"]),
        AssessmentPolicy.model_validate(frozen),
    ).model_dump(mode="json")
    payload["assessment_before"] = initial
    payload["assessment_current"] = initial
    payload.setdefault("assessment_changes", [])


def update_analysis(payload: dict, tools, findings: list, action_seq: int) -> None:
    initialize_analysis(payload, tools, findings)
    previous = InvestigationAssessment.model_validate(payload["assessment_current"])
    current = assess(
        tools.events,
        tools.scope,
        findings,
        set(tools.membership["evidence_ids"]) | set(payload["retrieved"]),
        AssessmentPolicy.model_validate(payload["assessment_config"]),
    )
    changes = [c.model_dump(mode="json") for c in changes_between(previous, current, action_seq)]
    payload["assessment_changes"] = (payload["assessment_changes"] + changes)[:40]
    payload["assessment_current"] = current.model_dump(mode="json")


def compact_context(payload: dict) -> dict:
    current = payload.get("assessment_current") or {"hypotheses": [], "gaps": []}
    hypotheses = [
        {k: h[k] for k in ("hypothesis_id", "rule_id", "kind", "status")}
        for h in current["hypotheses"]
    ]
    for compact, full in zip(hypotheses, current["hypotheses"], strict=True):
        compact["counter_event_ids"] = [r["event_id"] for r in full["contradicting_refs"][:2]]
        compact["supporting_event_ids"] = [r["event_id"] for r in full["supporting_refs"][:2]]
    gaps = [
        {k: g[k] for k in ("gap_id", "code", "asset_id")}
        for g in current["gaps"]
        if g["actionable"] and g["status"] == "open"
    ]
    return {
        "hypotheses": hypotheses[:3],
        "gaps": gaps[:4],
        "truncated": len(hypotheses) > 3 or len(gaps) > 4 or current.get("truncated", False),
        "context_only_warning": (
            "normal process observations weaken purpose hypotheses; no socket attribution"
        ),
    }


def all_actionable_resolved(payload: dict) -> bool:
    current = payload.get("assessment_current") or {"gaps": []}
    actionable = [g for g in current["gaps"] if g["actionable"]]
    return (
        bool(actionable)
        and all(g["status"] == "resolved" for g in actionable)
        and not current.get("truncated", False)
    )


def comparison(payload: dict) -> InvestigationComparison | None:
    if payload.get("assessment_before") is None:
        return None
    return InvestigationComparison(
        config_hash=payload["assessment_config_hash"],
        before=payload["assessment_before"],
        after=payload["assessment_current"],
        changes=payload.get("assessment_changes", []),
        stop_reason=payload.get("stop_reason")
        or payload.get("query_stop_reason")
        or "NO_QUERY_REASON_RECORDED",
    )
