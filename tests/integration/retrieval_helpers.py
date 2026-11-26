"""Local protocol decisions consume only request context; never query a hidden answer source."""

from copy import deepcopy


def retrieval_decision(kind: str, context: dict, page_limit: int | None = None) -> dict:
    if kind == "plan":
        hints = context.get("retrieval", {})
        continuation = hints.get("continue_result")
        if continuation is not None:
            result = context["tool_results"][continuation]
            query = {"tool": result["name"], "arguments": deepcopy(result["arguments"])}
            query["arguments"]["cursor"] = result["next_cursor"]
        elif hints.get("queries"):
            query = deepcopy(hints["queries"][0])
            if page_limit is not None and not context.get("tool_results"):
                query["arguments"]["limit"] = page_limit
        else:
            return {"action": "draft", "reason_summary": "No bounded query suggestion"}
        return {
            "action": "call_tool",
            "tool": query["tool"],
            "arguments": query["arguments"],
            "reason_summary": "Inspect suggested bounded evidence",
            "expected_evidence": "Snapshot observations; empty is not absence",
        }
    claims = []
    for event in context.get("facts", []):
        if (
            event.get("event_type") == "network.connection"
            and event.get("src")
            and event.get("dst")
        ):
            claims.append(
                {
                    "kind": "observed",
                    "statement": "Observed connection only",
                    "fact_predicate": {
                        "name": "connection_seen",
                        "values": {"src_ip": event["src"]["ip"], "dst_ip": event["dst"]["ip"]},
                    },
                    "evidence_ids": [event["event_id"]],
                }
            )
            break
    return {
        "claims": claims,
        "alternatives": ["Authorized activity is possible"],
        "gaps": ["Socket ownership and operator authorization remain unknown"],
    }
