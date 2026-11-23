"""Finite, evidence-bound gap updates. Context-only alternatives never prove flow ownership."""

from datetime import timedelta
from pathlib import Path

from pydantic import Field

from packages.contracts.models import (
    Contract,
    EvidenceRef,
    InvestigationAssessment,
    InvestigationChange,
    InvestigationGap,
    InvestigationHypothesis,
    InvestigationScope,
    NormalizedEvent,
)
from packages.detection.common import strong_process
from packages.detection.r04 import R04Config, detect_remote_access
from packages.graph.paths import analyze_paths


class AssessmentPolicy(Contract):
    version: str
    context_window_seconds: int = Field(ge=0, le=300)
    monitoring_executables: list[str] = Field(max_length=20)
    backup_executables: list[str] = Field(max_length=20)
    max_hypotheses: int = Field(ge=1, le=20)


def policy() -> AssessmentPolicy:
    return AssessmentPolicy.model_validate_json(
        (Path(__file__).resolve().parents[2] / "rules/investigation.json").read_bytes()
    )


def assess(
    events: list[NormalizedEvent],
    scope: InvestigationScope,
    findings: list[dict],
    known_ids: set[str],
    config: AssessmentPolicy,
) -> InvestigationAssessment:
    by_id = {
        e.event_id: e
        for e in events
        if e.workspace_id == scope.workspace_id
        and e.dataset_id == scope.dataset_id
        and scope.start <= e.event_time < scope.end
    }
    if not known_ids.issubset(by_id):
        raise ValueError("ASSESSMENT_EVIDENCE_OUT_OF_SCOPE")
    known = [by_id[eid] for eid in sorted(known_ids)]

    def refs(ids):
        return [
            EvidenceRef(
                event_id=eid,
                fragments=by_id[eid].source_locators,
                fields_used=["event_time", "asset_id", "host", "user", "process", "network"],
            )
            for eid in sorted(set(ids))
            if eid in known_ids
        ][:20]

    hypotheses, gaps = [], []
    truncated = False
    selected = [
        f
        for f in sorted(findings, key=lambda f: f["id"])
        if f["rule_id"] in {"R02", "R04", "R05", "R06"}
    ]
    for f in selected[: config.max_hypotheses]:
        hid = "hyp-" + f["id"]
        seed = [eid for eid in f["evidence_ids"] if eid in known_ids]
        if not seed:
            continue
        source = by_id[seed[0]]
        supporting, counter = [], []
        limitations = []
        asset = None
        status = "open"
        gap_specs = []

        def gap(
            code,
            resolved=False,
            actionable=True,
            explanation="",
            evidence=(),
            hid=hid,
            target=gap_specs,
        ):
            target.append(
                dict(
                    gap_id=hid + ":" + code,
                    hypothesis_id=hid,
                    code=code,
                    status="resolved" if resolved else "open" if actionable else "unavailable",
                    actionable=actionable,
                    explanation=explanation,
                    evidence_refs=refs(evidence),
                )
            )

        if f["rule_id"] == "R02":
            anchor = by_id.get(f.get("success_id"))
            asset = anchor.asset_id if anchor else None
            kind, statement, observation = (
                "session_process_link",
                "成功认证能否关联到明确会话进程？",
                "原规则记录了认证失败后成功。",
            )
            paths = analyze_paths(known, scope, set(seed))
            supporting = sorted(
                {
                    eid
                    for link in paths.links
                    if link.relation == "associated_process"
                    and link.from_event_id == f.get("success_id")
                    for eid in (link.from_event_id, link.to_event_id)
                }
            )
            status = "supported" if supporting else "open"
            gap(
                "session_process",
                bool(supporting),
                explanation="需要同Host/boot/账号/显式session且严格先后的进程记录。",
                evidence=supporting,
            )
            limitations = ["会话关联不证明恶意用途或真实操作者身份。"]
        elif f["rule_id"] == "R04":
            asset = f.get("target_asset_id")
            kind, statement, observation = (
                "remote_authentication",
                "跨主机管理连接后是否有匹配的远端成功认证？",
                "原规则仅提供资产级访问上下文。",
            )
            seeds = f.get("supporting_findings", [])
            available = [s for s in seeds if set(s["evidence_ids"]).issubset(known_ids)]
            matches = detect_remote_access(
                known, str(scope.session_id), available, R04Config.model_validate(f["config"])
            )
            matching = [
                item
                for item in matches
                if item["kind"] == "remote_access_candidate"
                and item["network_id"] == f["network_id"]
            ]
            supporting = sorted(
                {eid for item in matching for eid in (item["network_id"], item["success_id"])}
            )
            status = "supported" if supporting else "open"
            gap(
                "destination_authentication",
                bool(supporting),
                explanation="查询缺失认证；空结果不能证明没有登录。",
                evidence=supporting,
            )
            gap(
                "process_socket_binding",
                actionable=False,
                explanation="缺少进程socket绑定，不能确认连接发起进程。",
            )
            limitations = ["匹配认证也不证明成功横向移动。"]
        else:
            periodic = f["rule_id"] == "R05"
            asset = (
                source.src.asset_id
                if source.src and source.src.resolution_quality == "inventory_interval"
                else None
            )
            kind = "unexplained_periodicity" if periodic else "unexplained_outbound"
            statement = (
                "周期连接的恶意用途假设尚待排查。"
                if periodic
                else "出站流量的恶意用途假设尚待排查。"
            )
            stats = f["statistics"]
            observation = (
                (
                    f"{stats['count']}次连接、"
                    f"{stats.get('qualifying_window_count', 1)}个达标窗口合并；"
                    f"整体间隔CV={stats['cv']:.4f}，整体误差上界={stats['cv_upper']:.4f}，不代表单窗阈值。"
                )
                if periodic
                else (
                    f"连接起始窗口出站计数{stats['bytes_out']}字节；"
                    f"基线窗口{stats['baseline_windows']}个，p95={stats['p95_bytes']}。"
                )
            )
            first, last = (
                min(by_id[eid].event_time for eid in seed),
                max(by_id[eid].event_time for eid in seed),
            )
            start, end = (
                first - timedelta(seconds=config.context_window_seconds),
                last + timedelta(seconds=config.context_window_seconds),
            )
            executables = config.monitoring_executables if periodic else config.backup_executables
            counter = [
                e.event_id
                for e in known
                if asset
                and e.asset_id == asset
                and strong_process(e)
                and e.sensor.observation_domain == source.sensor.observation_domain
                and e.process.executable in executables
                and start <= e.event_time - timedelta(milliseconds=e.time_quality.uncertainty_ms)
                and e.event_time + timedelta(milliseconds=e.time_quality.uncertainty_ms) < end
            ]
            status = "weakened" if counter else "open"
            gap(
                "normal_process_context",
                bool(counter),
                actionable=bool(asset),
                explanation="同资产同窗的配置内监控/备份进程只是正常替代解释线索。",
                evidence=counter,
            )
            gap(
                "process_socket_binding",
                actionable=False,
                explanation="未采集socket绑定，不证明该进程产生这些连接。",
            )
            gap(
                "authorized_operations",
                actionable=False,
                explanation="进程可执行文件名不等于运维授权或可信程序身份。",
            )
            if not periodic:
                gap(
                    "transferred_content",
                    actionable=False,
                    explanation="字节计数不能证明传输了敏感内容。",
                )
                if stats["p95_bytes"] is None:
                    gap(
                        "normal_baseline",
                        actionable=False,
                        explanation="冻结基线不足，本调查不能回填或学习基线。",
                    )
            limitations = [
                "反向线索仅context_only，不证明进程与流量归属，也不证明没有攻击。",
                "可执行文件名及遥测真实性仍需人工复核。",
            ]
        gaps.extend(InvestigationGap(asset_id=asset, **values) for values in gap_specs)
        hypotheses.append(
            InvestigationHypothesis(
                hypothesis_id=hid,
                finding_id=f["id"],
                rule_id=f["rule_id"],
                kind=kind,
                status=status,
                statement=statement,
                observation=observation,
                supporting_refs=refs(supporting),
                contradicting_refs=refs(counter),
                counterevidence_kind="context_only" if counter else "none",
                limitations=limitations,
            )
        )
    if len(selected) > config.max_hypotheses:
        truncated = True
    return InvestigationAssessment(
        known_evidence_ids=sorted(known_ids), hypotheses=hypotheses, gaps=gaps, truncated=truncated
    )


def changes_between(
    before: InvestigationAssessment, after: InvestigationAssessment, action_seq: int
) -> list[InvestigationChange]:
    previous = {h.hypothesis_id: h for h in before.hypotheses}
    result = []
    for h in after.hypotheses:
        old = previous.get(h.hypothesis_id)
        if old and old.status != h.status:
            old_ids = {r.event_id for r in old.supporting_refs + old.contradicting_refs}
            refs = [
                r for r in h.supporting_refs + h.contradicting_refs if r.event_id not in old_ids
            ][:20]
            result.append(
                InvestigationChange(
                    action_seq=action_seq,
                    hypothesis_id=h.hypothesis_id,
                    before_status=old.status,
                    after_status=h.status,
                    evidence_refs=refs,
                    reason="发现同窗正常进程上下文，恶意用途解释被削弱；不证明流量归属。"
                    if h.status == "weakened"
                    else "工具补回支持明确身份/时间关系的证据。",
                )
            )
    return result
