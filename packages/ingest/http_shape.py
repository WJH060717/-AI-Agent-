"""Safe header/query structure only; neither client identity nor token equality."""

import re
from urllib.parse import parse_qsl, urlsplit

from packages.contracts.protocols import HTTPClientShape


def client_shape(record: dict) -> HTTPClientShape:
    agent = record.get("user_agent")
    kind = "unknown"
    if isinstance(agent, str) and 0 < len(agent) <= 2048 and agent.isprintable():
        kind = "browser_compatible" if agent.startswith(("Mozilla/", "Opera/", "OPR/")) else "other"
    uri = record.get("uri")
    if not isinstance(uri, str):
        return HTTPClientShape(user_agent_class=kind, query_status="unavailable")
    try:
        query = urlsplit(uri).query
        if re.search(r"%(?![a-fA-F0-9]{2})", query):
            raise ValueError("invalid percent encoding")
        fields = parse_qsl(query, keep_blank_values=True, errors="strict", max_num_fields=64)
    except ValueError:
        return HTTPClientShape(user_agent_class=kind, query_status="unavailable")
    opaque = sum(
        len(value) % 2 == 0 and bool(re.fullmatch(r"[a-fA-F0-9]{32,128}", value))
        for _, value in fields
    )
    return HTTPClientShape(
        user_agent_class=kind,
        query_status="parsed",
        query_field_count=len(fields),
        opaque_hex_count=opaque,
    )
