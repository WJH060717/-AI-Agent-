"""D2 observation projection. Communication is not proof of attack or causality."""

import hashlib
from collections import defaultdict

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
    def add_node(key, kind, label):
        nonlocal truncated
        if key not in nodes and len(nodes) >= 500:
            truncated = True
            return False
        nodes[key] = {"entity_id": key, "type": kind, "label": label}
        return True

    def add_relation(
        source, target, relation, evidence, kind, method, version, explanation, limits
    ):
        nonlocal truncated
        if len(edges) >= 1000 or source not in nodes or target not in nodes:
            truncated = True
            return
        ordered = sorted(evidence, key=lambda e: (e.event_time, e.event_id))
        edges.append(
            GraphEdge(
                edge_id=hashlib.sha256(
                    (relation + source + target + str([e.event_id for e in ordered])).encode()
                ).hexdigest(),
                snapshot_id=scope.snapshot_id,
                source=source,
                target=target,
                relation=relation,
                kind=kind,
                evidence_refs=[
                    EvidenceRef(
                        event_id=e.event_id,
                        fragments=e.source_locators,
                        fields_used=["event_time", "src", "dst", "packet", "dns", "arp"],
                    )
                    for e in ordered[:20]
                ],
                method=method,
                method_version=version,
                score=1.0,
                observation_domain=ordered[0].sensor.observation_domain,
                valid_from=ordered[0].event_time,
                valid_to=ordered[-1].event_time,
                limitations=limits,
                explanation=explanation,
            )
        )

    packets = [e for e in events[:500] if e.event_type == "network.packet"]
    dns_groups = defaultdict(list)
    for event in packets:
        packet = event.packet
        dns = getattr(packet, "dns_message", None)
        if dns is None:
            continue
        dns_groups[
            (event.sensor.observation_domain, dns.transaction_id, dns.question_sha256)
        ].append(event)
    for records in dns_groups.values():
        queries = [
            event
            for event in records
            if event.packet.dns_message.message_type in {"query", "query_context"}
        ]
        responses = [
            event for event in records if event.packet.dns_message.message_type == "response"
        ]
        if not queries or not responses:
            continue
        query, response = queries[0], responses[0]
        question = response.packet.dns_message.question_sha256
        answer = response.packet.dns_message.answer_set_sha256
        qkey, akey = "dns-question:" + question, "dns-answer:" + answer
        if add_node(qkey, "DnsTransaction", "DNS " + question[:8]) and add_node(
            akey, "DnsAnswer", "answer " + answer[:8]
        ):
            add_relation(
                qkey,
                akey,
                "resolved_to",
                [query, response],
                "inferred",
                "dns_transaction_projection",
                "1.0.0",
                "Same transaction/question response pairing; cache/domain context still required",
                ["同一事务号只证明观测配对，不证明应答可信或未被伪造。"],
            )
    arp_groups = defaultdict(list)
    for event in packets:
        mac = getattr(event.packet, "sender_mac", None)
        if not mac or event.src is None:
            continue
        arp_groups[(event.sensor.observation_domain, str(event.src.ip))].append(event)
    for (domain, address), records in arp_groups.items():
        macs = {event.packet.sender_mac for event in records}
        if len(macs) < 2:
            continue
        address_key = f"arp-address:{domain}:{address}"
        if not add_node(address_key, "ArpAddress", address):
            continue
        for mac in sorted(macs):
            claim_key = f"arp-claim:{domain}:{address}:{mac}"
            evidence = [event for event in records if event.packet.sender_mac == mac]
            if add_node(claim_key, "ArpClaim", mac):
                add_relation(
                    address_key,
                    claim_key,
                    "address_claimed_by",
                    evidence,
                    "observed",
                    "arp_claim_projection",
                    "1.0.0",
                    "Conflicting ARP sender claims; not proof of forwarding or MITM",
                    ["单一观测域内的冲突声明；租约/HA 仍可解释，转发需独立证据。"],
                )
    scan_groups = defaultdict(list)
    for event in packets:
        packet = event.packet
        flags = getattr(packet, "tcp_flags", None)
        if (
            getattr(packet, "protocol_number", None) != 6
            or flags is None
            or not flags & 0x02
            or flags & 0x10
            or event.src is None
            or event.dst is None
            or event.dst.port is None
        ):
            continue
        scan_groups[
            (event.sensor.observation_domain, str(event.src.ip), str(event.dst.ip))
        ].append(event)
    for (domain, source_ip, target_ip), records in scan_groups.items():
        ports = {event.dst.port for event in records}
        if len(ports) < 20:
            continue
        skey, tkey = f"scan-source:{domain}:{source_ip}", f"scan-target:{domain}:{target_ip}"
        if add_node(skey, "ScanSource", source_ip) and add_node(
            tkey, "ScanTarget", target_ip
        ):
            add_relation(
                skey,
                tkey,
                "scanned",
                records,
                "inferred",
                "tcp_syn_port_projection",
                "1.0.0",
                "20+ distinct TCP SYN destination ports in the bounded packet scope",
                ["仅为包级扫描形态，授权、成功率和其他扫描类型未知。"],
            )
    return {"nodes": list(nodes.values()), "edges": edges, "truncated": truncated}


def socket_matches_connection(socket_event: NormalizedEvent, network: NormalizedEvent) -> bool:
    """Conservative host-socket to connection candidate match.

    The local endpoint must have the same inventory asset as the collector host,
    the observation domain and transport must match, and the connection start
    must fall inside the socket observation uncertainty window.
    """
    if (
        socket_event.socket is None
        or not socket_event.process
        or not socket_event.process.entity_id
        or not socket_event.host
        or not socket_event.src
        or not socket_event.dst
        or not socket_event.network
        or network.event_type != "network.connection"
        or not network.src
        or not network.dst
        or not network.network
    ):
        return False
    if (
        socket_event.sensor.observation_domain != network.sensor.observation_domain
        or socket_event.network.transport != network.network.transport
    ):
        return False
    if socket_event.socket.role == "client":
        local, remote = network.src, network.dst
    else:
        local, remote = network.dst, network.src
    if (
        local.asset_id != socket_event.asset_id
        or local.ip != socket_event.src.ip
        or local.port != socket_event.src.port
        or remote.ip != socket_event.dst.ip
        or remote.port != socket_event.dst.port
    ):
        return False
    uncertainty = (
        socket_event.time_quality.uncertainty_ms + network.time_quality.uncertainty_ms
    ) / 1000
    delta = (network.event_time - socket_event.event_time).total_seconds()
    return -uncertainty <= delta <= 2 + uncertainty


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
                fields_used=[
                    "host",
                    "user",
                    "process",
                    "socket",
                    "src",
                    "dst",
                    "network.transport",
                    "event_time",
                ],
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
    for socket_event in events:
        if (
            socket_event.socket is None
            or not socket_event.process
            or not socket_event.process.entity_id
            or not socket_event.host
        ):
            continue
        socket_id = "socket:" + socket_event.event_id
        node(socket_id, "Socket", "socket-" + socket_event.event_id[:8])
        for process_event in processes.get(socket_event.process.entity_id, []):
            if process_event.event_id == socket_event.event_id:
                continue
            if process_event.host != socket_event.host:
                continue
            if precedes(process_event, socket_event):
                edge(
                    socket_event.process.entity_id,
                    socket_id,
                    "opened",
                    [process_event, socket_event],
                    "observed",
                )
        for network in events:
            if not socket_matches_connection(socket_event, network):
                continue
            connection_id = "connection:" + network.event_id
            node(connection_id, "Connection", "conn-" + network.event_id[:8])
            edge(socket_id, connection_id, "opened", [socket_event, network], "inferred")
    return {"nodes": list(nodes.values()), "edges": edges, "truncated": truncated}
