"""Advisory bounded queries derived only from already-known evidence, never hidden answers."""

import json

from packages.contracts.agent import TOOL_SCHEMAS
from packages.contracts.models import NormalizedEvent
from packages.detection.common import strong_process

DISCOVERY_TOOLS = frozenset({"search_events", "get_process_context", "get_asset_timeline"})


def _query_key(tool: str, arguments: dict) -> tuple[str, str]:
    args = TOOL_SCHEMAS[tool].model_validate(arguments).model_dump(mode="json", exclude={"cursor"})
    return tool, json.dumps(args, sort_keys=True)


def planning_hints(
    known_events: list[NormalizedEvent],
    seed_ids: set[str],
    retrieved_ids: set[str],
    actions: list[dict],
    investigation: dict,
    tool_results: list[dict],
) -> dict:
    # Defend against accidentally passing the whole snapshot. No unseen values enter hints.
    known = [e for e in known_events if e.event_id in seed_ids | retrieved_ids]
    known.sort(key=lambda e: (e.event_time, e.event_id), reverse=True)
    known.sort(key=lambda e: e.event_id not in retrieved_ids - seed_ids)
    assets = dict.fromkeys(
        str(asset)
        for e in known
        for asset in [
            e.asset_id,
            *[
                ep.asset_id
                for ep in (e.src, e.dst)
                if ep and ep.resolution_quality == "inventory_interval"
            ],
        ]
        if asset
    )
    completed = [a for a in actions if a["kind"] == "tool" and a["status"] == "completed"]
    used_tools = {a["name"] for a in completed}
    used_queries = {_query_key(a["name"], a["args_payload"]) for a in completed}
    queries = []

    def add(tool: str, arguments: dict, gap: dict | None = None) -> None:
        key = _query_key(tool, arguments)
        if key not in used_queries:
            queries.append(
                {
                    "tool": tool,
                    "arguments": arguments,
                    "gap_id": gap.get("gap_id") if gap else None,
                    "expected_evidence": (
                        gap.get("code", "snapshot_context") if gap else "snapshot_context"
                    ),
                    "selection_reason": "Resolve known gap"
                    if gap
                    else "Inspect known entity context",
                }
            )
            used_queries.add(key)

    for gap in investigation.get("gaps", []):
        asset = str(gap.get("asset_id"))
        types = {
            "session_process": ["host.process"],
            "normal_process_context": ["host.process"],
            "destination_authentication": ["auth.login"],
        }.get(gap["code"])
        if asset in assets and types:
            add("search_events", {"types": types, "asset_id": asset, "limit": 20}, gap)
    for event in known:
        if strong_process(event):
            add(
                "get_process_context",
                {
                    "process_entity_id": event.process.entity_id,
                    "depth": 1,
                    "limit": 20,
                },
            )
    for asset in assets:
        add("get_asset_timeline", {"asset_id": asset, "limit": 20})
    for event in known:
        if event.event_type == "network.packet" and event.src:
            add(
                "search_events",
                {
                    "types": ["network.packet"],
                    "field_filter": [{"field": "src.ip", "op": "eq", "value": str(event.src.ip)}],
                    "limit": 20,
                },
            )
    queries.sort(key=lambda q: (q["gap_id"] is None, q["tool"] in used_tools))
    distinct = {}
    for query in queries:
        distinct.setdefault(query["tool"], query)
    # Only the latest page of each exact query can offer a continuation.
    latest = {}
    for index, result in enumerate(tool_results):
        if result["name"] in DISCOVERY_TOOLS:
            arguments = (
                TOOL_SCHEMAS[result["name"]]
                .model_validate(result["arguments"])
                .model_dump(mode="json", exclude={"cursor", "limit"})
            )
            latest[(result["name"], json.dumps(arguments, sort_keys=True))] = index
    continuation = next(
        (
            index
            for index in reversed(list(latest.values()))
            if tool_results[index].get("next_cursor")
        ),
        None,
    )
    return {
        "seed_count": len(seed_ids),
        "new_evidence_count": len({e.event_id for e in known} - seed_ids),
        "queries": list(distinct.values())[:2],
        "continue_result": continuation,
    }
