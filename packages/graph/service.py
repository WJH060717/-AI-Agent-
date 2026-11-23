"""D2 observation projection. Communication is not proof of attack or causality."""

import hashlib

from packages.contracts.models import EvidenceRef, GraphEdge, InvestigationScope, NormalizedEvent


def checked_events(
    events: list[NormalizedEvent], scope: InvestigationScope
) -> list[NormalizedEvent]:
    for event in events:
        if event.workspace_id != scope.workspace_id or event.dataset_id != scope.dataset_id:
            raise ValueError("graph event is outside investigation scope")
        if not scope.start <= event.event_time < scope.end:
            raise ValueError("graph event is outside time window")
    return sorted(events, key=lambda e: (e.event_time, e.event_id))


def connection_graph(events: list[NormalizedEvent], scope: InvestigationScope) -> dict:
    events = checked_events(events, scope)
    nodes: dict[str, dict] = {}
    edges: list[GraphEdge] = []
    truncated = len(events) > 500
    for event in events[:500]:
        if event.event_type != "network.connection" or event.src is None or event.dst is None:
            continue
        ids = []
        additions = {}
        for endpoint in (event.src, event.dst):
            key = f"endpoint:{event.sensor.observation_domain}:{endpoint.ip}:{endpoint.port}"
            additions[key] = {"entity_id": key, "type": "Endpoint", "label": str(endpoint.ip)}
            ids.append(key)
        if len(nodes.keys() | additions.keys()) > 500:
            truncated = True
            continue
        nodes.update(additions)
        edges.append(
            GraphEdge(
                edge_id=hashlib.sha256((event.event_id + ":communication").encode()).hexdigest(),
                snapshot_id=scope.snapshot_id,
                source=ids[0],
                target=ids[1],
                relation="communicated_with",
                kind="observed",
                evidence_refs=[
                    EvidenceRef(
                        event_id=event.event_id,
                        fragments=event.source_locators,
                        fields_used=["src.ip", "dst.ip", "network.transport"],
                    )
                ],
                method="connection_projection",
                method_version="1.0.0",
                score=1.0,
                explanation="Observed connection only; does not establish malicious intent",
            )
        )
    return {"nodes": list(nodes.values()), "edges": edges, "truncated": truncated}


def evidence_graph(events: list[NormalizedEvent], scope: InvestigationScope) -> dict:
    from packages.ingest.identity import precedes

    events = checked_events(events, scope)
    graph = connection_graph(events, scope)
    events = events[:500]
    truncated = graph["truncated"]
    nodes = {n["entity_id"]: n for n in graph["nodes"]}
    edges = graph["edges"]
    processes = {}
    for event in events:
        if event.process and event.process.entity_id:
            processes.setdefault(event.process.entity_id, []).append(event)
    sessions = {}

    def node(key, kind, label):
        nonlocal truncated
        if key not in nodes and len(nodes) >= 500:
            truncated = True
            return
        nodes[key] = {"entity_id": key, "type": kind, "label": label}

    def edge(source, target, relation, evidence, kind="observed"):
        nonlocal truncated
        if len(edges) >= 1000 or source not in nodes or target not in nodes:
            truncated = True
            return
        references = [
            EvidenceRef(
                event_id=e.event_id,
                fragments=e.source_locators,
                fields_used=["host", "user", "process", "event_time"],
            )
            for e in evidence
        ]
        eid = hashlib.sha256(
            (relation + source + target + str([e.event_id for e in evidence])).encode()
        ).hexdigest()
        edges.append(
            GraphEdge(
                edge_id=eid,
                snapshot_id=scope.snapshot_id,
                source=source,
                target=target,
                relation=relation,
                kind=kind,
                evidence_refs=references,
                method="identity_time_constraints",
                method_version="1.1.0",
                score=1.0,
                explanation="Tuple/time candidate, not causality"
                if kind == "inferred"
                else "Explicit identity/lifecycle evidence, not malicious intent",
            )
        )

    for event in events:
        if event.host:
            node("host:" + str(event.host.asset_id), "Host", "host-" + str(event.host.asset_id)[:8])
        if event.process and event.process.entity_id:
            node(
                event.process.entity_id,
                "Process",
                f"pid {event.process.pid} · {event.process.entity_id[-6:]}",
            )
        if (
            event.auth
            and event.auth.outcome == "success"
            and event.user
            and event.user.entity_id
            and event.user.session_id
            and event.host
            and event.host.boot_id
        ):
            node(event.user.entity_id, "User", event.user.name_redacted or "account")
            node(event.user.session_id, "Session", "session-" + event.user.session_id[-8:])
            edge(event.user.entity_id, event.user.session_id, "authenticated", [event])
            sessions.setdefault(event.user.session_id, []).append(event)
    for event in events:
        if not event.process or not event.process.entity_id or not event.host:
            continue
        for parent in processes.get(event.process.parent_entity_id, []):
            if (
                parent.host == event.host
                and parent.process.action == "create"
                and event.process.action == "create"
                and precedes(parent, event)
            ):
                edge(parent.process.entity_id, event.process.entity_id, "spawned", [parent, event])
        if event.user:
            for auth in sessions.get(event.user.session_id, []):
                if (
                    auth.host == event.host
                    and auth.user.entity_id == event.user.entity_id
                    and precedes(auth, event)
                ):
                    edge(
                        auth.user.session_id,
                        event.process.entity_id,
                        "associated_process",
                        [auth, event],
                    )
    for network in events:
        if (
            network.event_type != "network.connection"
            or not network.src
            or not network.dst
            or not network.dst.asset_id
        ):
            continue
        for auth in events:
            if (
                auth.event_type != "auth.login"
                or not auth.src
                or not auth.dst
                or not auth.host
                or auth.asset_id != network.dst.asset_id
                or auth.dst.asset_id != auth.asset_id
                or auth.sensor.observation_domain != network.sensor.observation_domain
                or auth.src.ip != network.src.ip
                or auth.dst.ip != network.dst.ip
                or auth.src.port is None
                or auth.src.port != network.src.port
                or auth.dst.port is None
                or auth.dst.port != network.dst.port
                or not network.network
                or network.network.transport != "tcp"
            ):
                continue
            uncertainty = (
                network.time_quality.uncertainty_ms + auth.time_quality.uncertainty_ms
            ) / 1000
            delta = (auth.event_time - network.event_time).total_seconds()
            if uncertainty > 8 or delta < -uncertainty or abs(delta) > min(2 + uncertainty, 10):
                continue
            connection_id, auth_id = "connection:" + network.event_id, "event:" + auth.event_id
            node(connection_id, "Connection", "conn-" + network.event_id[:8])
            node(auth_id, "Event", "auth-" + auth.event_id[:8])
            edge(connection_id, auth_id, "corresponds_to", [network, auth], "inferred")
    return {"nodes": list(nodes.values()), "edges": edges, "truncated": truncated}
