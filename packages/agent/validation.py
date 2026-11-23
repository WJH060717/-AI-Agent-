"""Finite factual predicates. Model prose never becomes an observed fact by having an ID."""

from packages.contracts.agent import ReportDraft
from packages.contracts.models import Claim, EvidenceRef, NormalizedEvent, PacketObservation


class DraftError(ValueError):
    pass


def _connection_fields(
    event: NormalizedEvent, transport: str | None
) -> dict[str, str | int | None]:
    return {
        "src_ip": str(event.src.ip) if event.src and event.src.ip is not None else None,
        "dst_ip": str(event.dst.ip) if event.dst and event.dst.ip is not None else None,
        "dst_port": event.dst.port if event.dst else None,
        "transport": transport,
    }


def validate_draft(
    draft: ReportDraft,
    events: list,
    allowed_ids: set[str],
    findings: list,
    paths,
    allowed_knowledge_refs: set[str] | None = None,
) -> list[Claim]:
    by_id = {e.event_id: e for e in events}
    output = []
    for i, proposal in enumerate(draft.claims):
        if not set(proposal.knowledge_refs).issubset(allowed_knowledge_refs or set()):
            raise DraftError("DRAFT_KNOWLEDGE_REFERENCE_OUT_OF_SCOPE")
        ids = set(proposal.evidence_ids)
        if not ids.issubset(allowed_ids) or not ids.issubset(by_id):
            raise DraftError("DRAFT_REFERENCE_OUT_OF_SCOPE")
        if any(not by_id[eid].source_locators for eid in ids):
            raise DraftError("DRAFT_REFERENCE_UNAVAILABLE")
        refs = [
            EvidenceRef(
                event_id=eid,
                fragments=by_id[eid].source_locators,
                fields_used=[],
            )
            for eid in sorted(ids)
        ]
        predicate = proposal.fact_predicate
        if proposal.kind != "observed":
            # Free language has not been proved by these finite predicates.
            if any(
                term in proposal.statement.lower()
                for term in ("真实攻击者", "操作者是", "attacker is")
            ):
                raise DraftError("DRAFT_ATTRIBUTION_UNSUPPORTED")
            output.append(
                Claim(
                    claim_id=f"agent-note-{i}",
                    kind="unknown",
                    statement="模型提出的解释未由有限谓词验证，结论未知。",
                    evidence_refs=refs,
                    knowledge_refs=proposal.knowledge_refs,
                    limitations=["模型自由文本待人工复核，不属于已验证事实"],
                )
            )
            continue
        if not predicate or not ids:
            raise DraftError("DRAFT_FACT_WITHOUT_SUPPORT")
        members = [by_id[eid] for eid in sorted(ids)]
        values = predicate.values
        text = None
        fields = []
        # bool is an int subclass in Python: equality alone cannot establish a typed fact.
        if not values or any(
            type(value) is not (int if key == "dst_port" else str) for key, value in values.items()
        ):
            raise DraftError("DRAFT_PREDICATE_MISMATCH")
        if (
            predicate.name == "auth_outcome"
            and set(values).issubset({"outcome", "asset_id"})
            and "outcome" in values
        ):
            if all(
                e.auth
                and e.auth.outcome == values["outcome"]
                and (
                    "asset_id" not in values
                    or (e.asset_id is not None and str(e.asset_id) == values["asset_id"])
                )
                for e in members
            ):
                fields = ["auth.outcome"] + (["asset_id"] if "asset_id" in values else [])
                text = f"所引认证记录的结果为 {values['outcome']}。"
        elif predicate.name == "connection_seen" and set(values).issubset(
            {"src_ip", "dst_ip", "dst_port", "transport"}
        ):
            if any(event.event_type != "network.connection" for event in members):
                for event in members:
                    if event.event_type != "network.packet" or not isinstance(
                        event.packet, PacketObservation
                    ):
                        raise DraftError("DRAFT_CONNECTION_EVIDENCE_MISMATCH")
                    transport = {1: "icmp", 6: "tcp", 17: "udp"}.get(event.packet.protocol_number)
                    packet_fields = _connection_fields(event, transport)
                    if any(packet_fields[key] != value for key, value in values.items()):
                        raise DraftError("DRAFT_CONNECTION_EVIDENCE_MISMATCH")
                output.append(
                    Claim(
                        claim_id=f"agent-note-{i}",
                        kind="unknown",
                        statement="所引抓包记录仅支持包级观测，连接状态未知。",
                        evidence_refs=refs,
                        knowledge_refs=proposal.knowledge_refs,
                        limitations=["确认连接观测需要字段匹配的连接记录。"],
                    )
                )
                continue
            if all(
                e.src
                and e.dst
                and e.network
                and values.items() <= _connection_fields(e, e.network.transport).items()
                for e in members
            ):
                fields = [
                    {
                        "src_ip": "src.ip",
                        "dst_ip": "dst.ip",
                        "dst_port": "dst.port",
                        "transport": "network.transport",
                    }[key]
                    for key in sorted(values)
                ]
                text = "所引网络记录包含匹配的端点连接观测。"
        elif predicate.name == "process_parent" and set(values) == {
            "parent_entity_id",
            "child_entity_id",
        }:
            for link in paths.links:
                if link.relation != "spawned" or not {
                    link.from_event_id,
                    link.to_event_id,
                }.issubset(ids):
                    continue
                parent, child = by_id[link.from_event_id], by_id[link.to_event_id]
                if (
                    parent.process.entity_id == values["parent_entity_id"]
                    and child.process.entity_id == values["child_entity_id"]
                ):
                    fields = ["event_time", "host", "process"]
                    text = "所引生命周期记录支持明确的强父子进程关系。"
        elif predicate.name == "periodicity_observed" and set(values) == {"finding_id"}:
            match = next(
                (
                    f
                    for f in findings
                    if f["id"] == values["finding_id"]
                    and f["rule_id"] == "R05"
                    and set(f["evidence_ids"]).issubset(ids)
                ),
                None,
            )
            if match:
                fields = ["event_time", "time_quality", "sensor", "src", "dst", "network.transport"]
                stats = match["statistics"]
                text = (
                    f"所引记录含{stats['count']}次连接、"
                    f"{stats.get('qualifying_window_count', 1)}个达标窗口合并，"
                    f"整体间隔CV={stats['cv']:.4f}；整体统计不代表单窗阈值。"
                    "监控心跳也可符合，不能据此认定C2。"
                )
        elif predicate.name == "rule_triggered" and set(values) == {"rule_id", "finding_id"}:
            if any(
                f["id"] == values["finding_id"]
                and f["rule_id"] == values["rule_id"]
                and set(f["evidence_ids"]).issubset(ids)
                for f in findings
            ):
                fields = ["event_time", "sensor"]
                text = f"固定版本 {values['rule_id']} 在所引证据上触发。"
        elif predicate.name == "path_candidate" and set(values) == {"path_id"}:
            if any(
                p.path_id == values["path_id"] and set(p.event_ids).issubset(ids)
                for p in paths.paths
            ):
                fields = ["event_time", "host", "process", "src", "dst", "auth", "user"]
                text = "当前快照中存在该有证据支撑的候选路径，不证明完整攻击因果。"
        if text is None:
            raise DraftError("DRAFT_PREDICATE_MISMATCH")
        for ref in refs:
            ref.fields_used = fields
        output.append(
            Claim(
                claim_id=f"agent-fact-{i}",
                kind="observed",
                statement=text,
                fact_predicate=predicate,
                evidence_refs=refs,
                knowledge_refs=proposal.knowledge_refs,
                support_level="high",
                limitations=["程序验证有限谓词，不证明恶意或真实操作者身份"],
            )
        )
    return output
