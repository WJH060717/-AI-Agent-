"""Evidence-backed event paths. Heuristic support is neither probability nor attribution."""

import hashlib
import json
from collections import defaultdict
from ipaddress import ip_address

from packages.contracts.models import (
    CandidateOrigin,
    EventPathEdge,
    EvidenceRef,
    InvestigationScope,
    NormalizedEvent,
    PathAnalysis,
    PathBreakpoint,
    PathCandidate,
    PathScore,
)
from packages.graph.service import evidence_graph, socket_matches_connection
from packages.ingest.identity import precedes


def identifier(value: list) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def analyze_paths(
    events: list[NormalizedEvent], scope: InvestigationScope, seed_ids: set[str]
) -> PathAnalysis:
    events = sorted(events, key=lambda e: (e.event_time, e.event_id))
    by_id = {e.event_id: e for e in events}
    if len(events) > 500 or len(by_id) != len(events):
        raise ValueError("path scope exceeds event limit or repeats event IDs")
    if not seed_ids or not seed_ids.issubset(by_id):
        raise ValueError("path seed outside snapshot")
    for event in events:
        if (
            event.workspace_id != scope.workspace_id
            or event.dataset_id != scope.dataset_id
            or not scope.start <= event.event_time < scope.end
        ):
            raise ValueError("path event outside scope")
    graph = evidence_graph(events, scope)
    proofs = defaultdict(list)
    for edge in graph["edges"]:
        refs = edge.evidence_refs
        if any(
            ref.event_id not in by_id or ref.fragments != by_id[ref.event_id].source_locators
            for ref in refs
        ):
            raise ValueError("path proof outside scope")
        if len(refs) == 2:
            proofs[(edge.relation, frozenset(ref.event_id for ref in refs))].append(edge.edge_id)
    links, gaps = {}, {}

    def refs_for(members):
        return [
            EvidenceRef(
                event_id=e.event_id,
                fragments=e.source_locators,
                fields_used=[
                    "event_time",
                    "time_quality",
                    "host",
                    "user",
                    "process",
                    "socket",
                    "src",
                    "dst",
                ],
            )
            for e in members
        ]

    def gap(a, b, reason, explanation):
        key = (a.event_id if a else None, b.event_id if b else None, reason)
        gaps[key] = PathBreakpoint(
            from_event_id=key[0],
            to_event_id=key[1],
            reason=reason,
            evidence_refs=refs_for([e for e in (a, b) if e]),
            explanation=explanation,
        )

    def add(a, b, relation, kind="observed", max_gap=1800):
        if not precedes(a, b, max_gap):
            reason = (
                "reversed_time"
                if b.event_time < a.event_time
                else "order_uncertain_or_out_of_window"
            )
            gap(a, b, reason, "时间区间无法确认严格先后或超过允许窗口；此跳不进入路径")
            return
        if any(
            flag in e.quality_flags
            for e in (a, b)
            for flag in ("identity_ambiguous", "parent_identity_conflict", "partial_audit")
        ):
            gap(a, b, "identity_conflict", "身份有冲突或证据不完整；不连强路径")
            return
        proof = sorted(proofs[(relation, frozenset((a.event_id, b.event_id)))])
        if not proof:
            gap(a, b, "no_supported_link", "缺少可复核的实体关系证据")
            return
        worst_gap = (b.event_time - a.event_time).total_seconds() + (
            a.time_quality.uncertainty_ms + b.time_quality.uncertainty_ms
        ) / 1000
        components = PathScore(
            identity=0.7 if kind == "inferred" else 1,
            time=max(0, 1 - worst_gap / max_gap),
            relation_support=0.6 if kind == "inferred" else 1,
            penalties=0.2 if a.time_quality.uncertainty_ms or b.time_quality.uncertainty_ms else 0,
        )
        score = round(
            max(
                0,
                min(
                    1,
                    0.4 * components.identity
                    + 0.25 * components.time
                    + 0.2 * components.relation_support
                    - components.penalties,
                ),
            ),
            6,
        )
        eid = identifier([str(scope.snapshot_id), a.event_id, b.event_id, relation])
        links[eid] = EventPathEdge(
            edge_id=eid,
            from_event_id=a.event_id,
            to_event_id=b.event_id,
            entity_edge_ids=proof,
            relation=relation,
            kind=kind,
            evidence_refs=refs_for([a, b]),
            components=components,
            score=score,
            explanation="严格时间有序的五元组/资产候选，非攻击因果"
            if kind == "inferred"
            else "显式会话或生命周期关系，非恶意行为证明",
        )

    auths = [
        e
        for e in events
        if e.auth
        and e.auth.outcome == "success"
        and e.host
        and e.host.boot_id
        and e.user
        and e.user.entity_id
    ]
    processes = [e for e in events if e.process and e.host]
    for child in processes:
        if not child.process.entity_id or child.process.boot_id != child.host.boot_id:
            gap(None, child, "weak_process", "缺少一致的强进程身份、boot或出生依据")
            for login in auths:
                if (
                    login.host.asset_id == child.host.asset_id
                    and login.sensor.observation_domain == child.sensor.observation_domain
                ):
                    gap(login, child, "weak_process", "该主机上下文缺少一致的强进程/boot；不连路径")
            continue
        for login in auths:
            if (
                login.host != child.host
                or not child.user
                or login.user.entity_id != child.user.entity_id
            ):
                continue
            if not login.user.session_id or not child.user.session_id:
                gap(login, child, "missing_session", "无显式共同会话；同主机或账号不足以补此跳")
            elif login.user.session_id == child.user.session_id:
                add(login, child, "associated_process")
        for parent in processes:
            if (
                parent.process.entity_id
                and parent.process.entity_id == child.process.parent_entity_id
                and parent.host == child.host
                and parent.process.boot_id == parent.host.boot_id
                and parent.process.action == child.process.action == "create"
            ):
                add(parent, child, "spawned")
    bound_pairs: set[tuple[str, str]] = set()
    for socket_event in [e for e in events if e.socket and e.process and e.host]:
        entity = socket_event.process.entity_id
        if not entity:
            continue
        for process_event in processes:
            if (
                process_event.process.entity_id == entity
                and process_event.host == socket_event.host
                and process_event.event_id != socket_event.event_id
            ):
                add(process_event, socket_event, "opened")
        for network in events:
            if not socket_matches_connection(socket_event, network):
                continue
            before = len(links)
            add(socket_event, network, "opened", "inferred")
            if len(links) > before:
                bound_pairs.add((entity, network.event_id))
    for network in events:
        if (
            not network.network
            or network.event_type != "network.connection"
            or not network.src
            or not network.dst
        ):
            continue
        for login in auths:
            if (
                not login.src
                or not login.dst
                or login.host.asset_id != login.asset_id
                or login.sensor.observation_domain != network.sensor.observation_domain
                or login.dst.asset_id != login.asset_id
                or network.dst.asset_id != login.asset_id
                or network.src.ip != login.src.ip
                or network.dst.ip != login.dst.ip
                or network.src.port is None
                or network.src.port != login.src.port
                or network.dst.port is None
                or network.dst.port != login.dst.port
                or network.network.transport != "tcp"
            ):
                continue
            uncertainty = (
                network.time_quality.uncertainty_ms + login.time_quality.uncertainty_ms
            ) / 1000
            add(network, login, "corresponds_to", "inferred", min(2 + uncertainty, 10))
        for process in processes:
            if (
                network.src.asset_id == process.host.asset_id
                and process.event_time < network.event_time
                and process.sensor.observation_domain == network.sensor.observation_domain
            ):
                entity = process.process.entity_id
                if entity and (entity, network.event_id) in bound_pairs:
                    continue
                gap(
                    process,
                    network,
                    "missing_socket_binding",
                    "缺少进程到socket直接绑定，不能归给最近进程",
                )
    # Failed auth and disjoint evidence do not become paths by sharing a host or IP.
    adjacency, neighbours = defaultdict(list), defaultdict(set)
    for link in links.values():
        adjacency[link.from_event_id].append(link)
        neighbours[link.from_event_id].add(link.to_event_id)
        neighbours[link.to_event_id].add(link.from_event_id)
    relevant, pending = set(seed_ids), list(sorted(seed_ids))
    while pending:
        for other in sorted(neighbours[pending.pop()]):
            if other not in relevant:
                relevant.add(other)
                pending.append(other)
    links = {key: link for key, link in links.items() if link.from_event_id in relevant}
    if len(links) > 1000:
        raise ValueError("path edge scope exceeds limit")
    targets = {link.to_event_id for link in links.values()}
    roots = sorted(relevant - targets, key=lambda eid: (by_id[eid].event_time, eid))
    origins = []
    origin_targets = set()
    for root in roots:
        event = by_id[root]
        if not adjacency[root]:
            gap(event, None, "no_supported_link", "当前种子没有可追证的下一跳，证据不足")
        target_asset = event.asset_id or (event.dst.asset_id if event.dst else None)
        target = (
            event.sensor.observation_domain,
            str(target_asset)
            if target_asset
            else str(event.dst.ip)
            if event.dst
            else str(event.src.ip)
            if event.src
            else root,
        )
        if target in origin_targets:
            continue
        origin_targets.add(target)
        classification = "earliest_observed"
        if event.src and event.src.asset_id or event.host and event.event_type == "host.process":
            classification = "internal_start_candidate"
        elif event.src and ip_address(event.src.ip).is_global:
            classification = "external_entry_candidate"
        origins.append(
            CandidateOrigin(
                origin_id=identifier([str(scope.snapshot_id), root]),
                event_id=root,
                asset_id=target_asset,
                classification=classification,
                left_censored=True,
                evidence_refs=refs_for([event]),
                explanation="当前有界观测中的起点候选；无完整采集覆盖声明，之前活动及真实操作者未知",
            )
        )

    def path_score(edge_ids):
        scores = [links[eid].score for eid in edge_ids]
        return round(0.6 * min(scores) + 0.4 * sum(scores) / len(scores), 6) if scores else 0

    def rank(state):
        nodes, edges = state
        return (-path_score(edges), tuple(nodes), tuple(edges))

    beam = [([root], []) for root in roots if adjacency[root]]
    truncated = graph["truncated"] or len(beam) > 20
    beam = sorted(beam, key=rank)[:20]
    finished = []
    for depth in range(7):
        expanded = []
        for nodes, edge_ids in beam:
            following = sorted(adjacency[nodes[-1]], key=lambda e: e.edge_id)
            if not following or depth == 6:
                if edge_ids and seed_ids.intersection(nodes):
                    finished.append((nodes, edge_ids))
                if following and depth == 6:
                    truncated = True
                continue
            for edge in following:
                if edge.edge_id in links and edge.to_event_id not in nodes:
                    expanded.append((nodes + [edge.to_event_id], edge_ids + [edge.edge_id]))
        truncated |= len(expanded) > 20
        beam = sorted(expanded, key=rank)[:20]
        if not beam:
            break
    finished.sort(key=rank)
    candidates = []
    for nodes, edges in finished[:23]:
        score = path_score(edges)
        observed = sum(links[eid].kind == "observed" for eid in edges)
        candidates.append(
            PathCandidate(
                path_id=identifier([str(scope.snapshot_id), nodes, edges]),
                event_ids=nodes,
                edge_ids=edges,
                score=score,
                support_level="high" if score >= 0.8 else "medium" if score >= 0.5 else "low",
                observed_steps=observed,
                inferred_steps=len(edges) - observed,
                missing_steps=0,
                coverage=1,
                difference_event_ids=sorted(set(nodes) ^ set(finished[0][0])),
            )
        )
    selected_gaps = [
        gap for gap in gaps.values() if gap.from_event_id in relevant or gap.to_event_id in relevant
    ]
    selected_gaps.sort(key=lambda g: (g.from_event_id or "", g.to_event_id or "", g.reason))
    return PathAnalysis(
        scope=scope,
        status="candidates" if candidates else "insufficient_evidence",
        origins=origins,
        paths=candidates[:3],
        alternatives=candidates[3:],
        links=sorted(links.values(), key=lambda e: e.edge_id),
        breakpoints=selected_gaps[:1000],
        truncated=truncated or len(selected_gaps) > 1000 or len(finished) > 23,
        searched_paths=len(finished),
        limitations=[
            "候选路径表达记录关系与有约束推断，不证明恶意、完整攻击链或真实操作者身份",
            "分数为启发式支持度，未作为概率校准；无独立通道声明时旁证项为0",
            "coverage只覆盖所选链条内已连接的跳；窗口前活动和未观测跳数未知",
            "仅在显式主机socket绑定且域、资产、五元组和时间均一致时连接进程与连接；其余保留断点。",
        ],
    )
