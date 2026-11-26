"""Finite, registered investigation strategies for packet-derived findings.

Only the seed finding and events already returned by tools are inputs. The
registry is intentionally small: it states what would support or weaken each
hypothesis, which fields are missing, and where the bounded query stops.
"""

from dataclasses import dataclass, field

from packages.contracts.models import NormalizedEvent
from packages.detection.common import strong_process


@dataclass(frozen=True)
class StrategySpec:
    strategy_id: str
    rule_ids: frozenset[str]
    hypothesis_kind: str
    statement: str
    normal_explanation: str
    missing_fields: tuple[str, ...]
    tools: tuple[str, ...]
    stop_condition: str


@dataclass
class StrategyResult:
    strategy_id: str
    status: str
    hypothesis_kind: str
    statement: str
    observation: str
    supporting: list[str] = field(default_factory=list)
    counter: list[str] = field(default_factory=list)
    gaps: list[dict] = field(default_factory=list)
    queries: list[dict] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    normal_explanation: str = ""


SCAN = StrategySpec(
    strategy_id="scan_activity@1.0.0",
    rule_ids=frozenset({"R01", "R24", "R25", "R26", "R27", "R30"}),
    hypothesis_kind="scan_activity",
    statement="这是否为未授权的端口/主机/指纹探测，而非授权资产盘点？",
    normal_explanation="授权扫描、资产盘点、监控探活和 HA 探测也可产生相似形态。",
    missing_fields=("扫描授权范围", "发起资产和进程", "目标资产用途"),
    tools=("search_events", "get_asset_timeline", "get_process_context"),
    stop_condition="授权/发起方证据不足时保留未知，不把扫描行为升级为入侵成功。",
)
DNS = StrategySpec(
    strategy_id="dns_answer_conflict@1.0.0",
    rule_ids=frozenset({"R29"}),
    hypothesis_kind="dns_answer_conflict",
    statement="同一 DNS 事务是否出现了超出缓存/分域解释的冲突答复？",
    normal_explanation="DNS 缓存、分域解析、负载均衡和应答重放都可产生差异。",
    missing_fields=("resolver 与缓存上下文", "查询侧和应答侧观测域", "TTL/分域配置"),
    tools=("search_events", "get_event_evidence"),
    stop_condition="只有单一应答或缺少同一事务上下文时保留未知，不宣称 DNS 欺骗成功。",
)
ARP = StrategySpec(
    strategy_id="arp_mapping_conflict@1.0.0",
    rule_ids=frozenset({"R28"}),
    hypothesis_kind="arp_mapping_conflict",
    statement="同一二层域是否出现相互冲突的 ARP 地址声明？",
    normal_explanation="DHCP 租约切换、HA 接管、网卡更换和虚拟化迁移也可产生冲突。",
    missing_fields=("交换机/ARP 表", "租约与 HA 状态", "冲突时间窗和二层域"),
    tools=("search_events", "get_event_evidence"),
    stop_condition="只有单一声明或缺少二层域上下文时保留未知，不宣称中间人转发。",
)

REGISTRY = {spec.strategy_id: spec for spec in (SCAN, DNS, ARP)}
RULE_INDEX = {rule: spec for spec in REGISTRY.values() for rule in spec.rule_ids}


def strategy_for(finding: dict) -> StrategySpec | None:
    return RULE_INDEX.get(finding.get("rule_id"))


def _dns_conflicts(events: list[NormalizedEvent]) -> tuple[list[str], list[str]]:
    groups = {}
    for event in events:
        if (
            event.event_type != "network.packet"
            or event.packet is None
            or getattr(event.packet, "dns_message", None) is None
        ):
            continue
        dns = event.packet.dns_message
        if dns.message_type != "response":
            continue
        groups.setdefault(dns.question_sha256, []).append(event)
    supporting, counter = [], []
    for responses in groups.values():
        answers = {r.packet.dns_message.answer_set_sha256 for r in responses}
        ids = [r.event_id for r in responses]
        if len(answers) >= 2:
            supporting.extend(ids)
        else:
            counter.extend(ids)
    return sorted(set(supporting)), sorted(set(counter))


def _arp_conflicts(events: list[NormalizedEvent]) -> tuple[list[str], list[str]]:
    groups = {}
    for event in events:
        if event.event_type != "network.packet" or event.src is None:
            continue
        packet = event.packet
        mac = getattr(packet, "sender_mac", None)
        if not mac:
            continue
        groups.setdefault(str(event.src.ip), []).append((event, mac))
    supporting, counter = [], []
    for records in groups.values():
        macs = {mac for _, mac in records}
        ids = [event.event_id for event, _ in records]
        if len(macs) >= 2:
            supporting.extend(ids)
        else:
            counter.extend(ids)
    return sorted(set(supporting)), sorted(set(counter))


def evaluate(
    finding: dict, events: list[NormalizedEvent], known_ids: set[str]
) -> StrategyResult | None:
    spec = strategy_for(finding)
    if spec is None:
        return None
    known = [event for event in events if event.event_id in known_ids]
    seed = [eid for eid in finding.get("evidence_ids", []) if eid in known_ids]
    if not seed:
        return None
    supporting = list(seed)
    counter: list[str] = []
    if spec is SCAN:
        # A strong process observation on the same asset is a possible
        # authorized-scanner explanation, not proof of authorization.
        for event in known:
            if strong_process(event) and event.asset_id:
                counter.append(event.event_id)
        observation = (
            f"种子记录了 {len(seed)} 条探测证据；已知集合中有 {len(counter)} 条强进程观测，"
            "但 executable 名称不等于授权。"
        )
        status = "open"
        gaps = [
            dict(
                code="scan_authorization",
                status="open",
                actionable=True,
                explanation="需要授权范围、发起资产/进程或扫描器登记；空结果不证明未授权。",
            )
        ]
        queries = [
            {
                "tool": "get_asset_timeline",
                "arguments": {"asset_id": str(known[0].asset_id), "limit": 20},
                "expected_evidence": "scan_authorization",
            }
        ] if known[0].asset_id else []
    elif spec is DNS:
        conflicts, single = _dns_conflicts(known)
        supporting = sorted(set(seed) | set(conflicts))
        counter = single
        status = "supported" if conflicts and seed else "open"
        observation = (
            f"已知集合中 {len(conflicts)} 条答复与同事务其他答复冲突；"
            f"{len(single)} 条仅为单一声明。"
        )
        gaps = [
            dict(
                code="dns_resolver_context",
                status="resolved" if conflicts else "open",
                actionable=True,
                explanation="需要 resolver、缓存、TTL 和分域上下文；冲突本身不等于欺骗成功。",
            )
        ]
        queries = []
    else:
        conflicts, single = _arp_conflicts(known)
        supporting = sorted(set(seed) | set(conflicts))
        counter = single
        status = "supported" if conflicts and seed else "open"
        observation = (
            f"已知集合中 {len(conflicts)} 条 ARP 声明参与冲突；{len(single)} 条为单一声明。"
        )
        gaps = [
            dict(
                code="arp_lease_context",
                status="resolved" if conflicts else "open",
                actionable=True,
                explanation="需要租约、HA 和二层域上下文；冲突不证明中间人转发。",
            )
        ]
        queries = []
    if supporting and status == "open":
        status = "open"
    return StrategyResult(
        strategy_id=spec.strategy_id,
        status=status,
        hypothesis_kind=spec.hypothesis_kind,
        statement=spec.statement,
        observation=observation,
        supporting=supporting,
        counter=counter,
        gaps=gaps,
        queries=queries,
        limitations=[
            spec.normal_explanation,
            spec.stop_condition,
            "策略只使用种子和已完成工具返回，不读取隐藏答案或测试标签。",
        ],
        normal_explanation=spec.normal_explanation,
    )


def validate(result: StrategyResult, known_ids: set[str]) -> None:
    if result.status not in {"open", "supported", "weakened"}:
        raise ValueError("STRATEGY_STATUS_INVALID")
    if not set(result.supporting) <= known_ids or not set(result.counter) <= known_ids:
        raise ValueError("STRATEGY_EVIDENCE_OUTSIDE_KNOWN")
    if result.status == "supported" and not result.supporting:
        raise ValueError("STRATEGY_SUPPORTED_WITHOUT_EVIDENCE")
    for gap in result.gaps:
        if gap["code"] not in {"scan_authorization", "dns_resolver_context", "arp_lease_context"}:
            raise ValueError("STRATEGY_GAP_UNREGISTERED")