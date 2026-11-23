"""Compact model-only representations; never mutate stored evidence or authority metadata."""

from copy import deepcopy
from typing import Any


def compact_schema(schema: Any) -> Any:
    """Remove annotation titles, preserving property names and literal default/enum values."""
    if isinstance(schema, list):
        return [compact_schema(item) for item in schema]
    if not isinstance(schema, dict):
        return schema
    result = {}
    for name, value in schema.items():
        if name == "title":
            continue
        if name in {"properties", "$defs", "definitions", "patternProperties"}:
            result[name] = {key: compact_schema(item) for key, item in value.items()}
        elif name in {"default", "enum", "const", "examples"}:
            result[name] = deepcopy(value)
        else:
            result[name] = compact_schema(value)
    return result


def _omit_null_properties(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _omit_null_properties(item) for key, item in value.items() if item is not None}
    if isinstance(value, list):
        return [_omit_null_properties(item) for item in value]
    return value


def wire_context(context: dict, *, plan_fact_limit: int | None = None) -> dict:
    result = deepcopy(context)
    # Internal row keys are not tool arguments or evidence references. Scope stays verbatim.
    result.pop("run_id", None)
    investigation = result.get("investigation", {})
    for hypothesis in investigation.get("hypotheses", []):
        hypothesis.pop("hypothesis_id", None)
    for gap in investigation.get("gaps", []):
        gap.pop("gap_id", None)
    if plan_fact_limit is not None and "hypotheses" in investigation:
        hypotheses = investigation["hypotheses"]
        investigation["hypotheses"] = [h for h in hypotheses if h.get("status") != "supported"]
        omitted = len(hypotheses) - len(investigation["hypotheses"])
        if omitted:
            investigation["supported_hypotheses_omitted"] = omitted
            investigation["truncated"] = True
    if "facts" in result:
        if plan_fact_limit is not None:
            facts = result["facts"]
            retrieved = set(result.get("retrieved_event_ids", []))
            ranked = sorted(facts, key=lambda fact: fact.get("event_id") not in retrieved)
            selected, seen_types = [], set()
            for fact in ranked:
                kind = fact.get("event_type")
                if kind not in seen_types:
                    selected.append(fact)
                    seen_types.add(kind)
                if len(selected) >= plan_fact_limit:
                    break
            for fact in ranked:
                if len(selected) >= plan_fact_limit:
                    break
                if fact not in selected:
                    selected.append(fact)
            result["facts"] = selected
            result["facts_truncated"] = bool(
                result.get("facts_truncated") or len(selected) < len(facts)
            )
            for fact in result["facts"]:
                for key in ("sensor", "host", "user"):
                    fact.pop(key, None)
            result["fact_identity_details_omitted"] = True
        result["facts"] = [_omit_null_properties(fact) for fact in result["facts"]]
        result["fact_nulls_omitted"] = True
    if "seed_event_ids" in result:
        visible = {fact.get("event_id") for fact in result.get("facts", [])}
        seeds = result["seed_event_ids"]
        result["seed_event_ids"] = [event_id for event_id in seeds if event_id in visible]
        result["seed_ids_truncated"] = bool(
            result.get("seed_ids_truncated") or len(result["seed_event_ids"]) != len(seeds)
        )
    if "retrieved_event_ids" in result:
        visible = {fact.get("event_id") for fact in result.get("facts", [])}
        retrieved = result["retrieved_event_ids"]
        result["retrieved_event_ids"] = [eid for eid in retrieved if eid in visible]
        result["retrieved_ids_truncated"] = bool(
            result.get("retrieved_ids_truncated")
            or len(result["retrieved_event_ids"]) != len(retrieved)
        )
    return result
