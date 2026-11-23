import hashlib
import json

from packages.contracts.models import FloodBehavior, FloodObservation, FloodSupport, NormalizedEvent
from packages.detection.limits import checkpoint

DOS_DDOS_FAMILY = "DoS/DDoS"


def merged_dos_subtype(legacy_subtype: str) -> str:
    family, behavior = legacy_subtype.split("-", 1)
    if family not in {"DoS", "DDoS"} or not behavior:
        raise ValueError("expected a DoS or DDoS behavior label")
    return f"{DOS_DDOS_FAMILY}-{behavior}"


def finding(
    rule, events: list[NormalizedEvent], session: str, key: list, kind: str, **extra
) -> dict:
    ordered = sorted(
        {e.event_id: e for e in events}.values(), key=lambda e: (e.event_time, e.event_id)
    )
    checkpoint(references=len(ordered))
    first = ordered[0]
    group = [
        str(first.workspace_id),
        str(first.dataset_id),
        session,
        first.sensor.observation_domain,
        *key,
    ]
    config = rule.model_dump(mode="json")
    base = hashlib.sha256(
        json.dumps([group, rule.id, rule.version, kind], sort_keys=True).encode()
    ).hexdigest()
    ids = [e.event_id for e in ordered]
    identity = hashlib.sha256(json.dumps([base, ids, config], sort_keys=True).encode()).hexdigest()
    return {
        "id": identity,
        "base_key": base,
        "rule_id": rule.id,
        "rule_version": rule.version,
        "config": config,
        "kind": kind,
        "group_key": group,
        "evidence_ids": ids,
        "start_time": ordered[0].event_time.isoformat(timespec="microseconds"),
        "end_time": ordered[-1].event_time.isoformat(timespec="microseconds"),
        "severity": "medium",
        **extra,
    }


def observe_flood(
    events: list[NormalizedEvent], behavior: FloodBehavior, support: FloodSupport
) -> dict:
    return FloodObservation(
        behavior=behavior,
        observed_source_ip_count=len({event.src.ip for event in events if event.src is not None}),
        campaign_scope="unknown",
        support=support,
    ).model_dump(mode="json")


def strong_process(event: NormalizedEvent) -> bool:
    return bool(
        event.host
        and event.asset_id == event.host.asset_id
        and event.host.boot_id
        and event.process
        and event.process.entity_id
        and event.process.boot_id == event.host.boot_id
        and event.process.identity_basis in {"lifecycle_record", "verified_proc"}
        and not {"partial_audit", "identity_ambiguous", "parent_identity_conflict"}.intersection(
            event.quality_flags
        )
    )


def title(rule_id: str) -> str:
    return {
        "R01": "R01 扫描候选",
        "R02": "R02 认证失败后成功候选",
        "R03": "R03 异常父子进程候选",
        "R04": "R04 跨主机访问候选",
        "R05": "R05 周期连接候选",
        "R06": "R06 出站量候选",
        "R07": "R07 可执行文件请求候选",
        "R08": "R08 疑似C&C回连候选",
        "R09": "R09 多Host疑似C&C回连候选",
        "R10": "R10 非文本HTTP查询候选",
        "R11": "R11 混合编码HTTP查询候选",
        "R12": "R12 ACK 分片突发候选",
        "R13": "R13 UDP 分片突发候选",
        "R14": "R14 ICMP 分片突发候选",
        "R15": "R15 PSH+ACK 洪泛候选",
        "R16": "R16 RST+FIN 洪泛候选",
        "R17": "R17 同址 SYN 洪泛候选",
        "R18": "R18 SYN 洪泛候选",
        "R19": "R19 零标志 TCP 洪泛候选",
        "R20": "R20 UDP 洪泛候选",
        "R21": "R21 ICMP Echo 洪泛候选",
        "R22": "R22 HTTP 请求洪泛候选",
        "R23": "R23 SlowLoris 慢头部候选",
        "R24": "R24 TCP 目的端口扫描候选",
        "R25": "R25 ICMP Echo 地址扫描候选",
        "R26": "R26 批量 ARP 查询观测（子类型未知）",
        "R27": "R27 GRE 封装突发观测（子类型未知）",
        "R28": "R28 ARP 映射冲突观测（子类型未知）",
        "R29": "R29 DNS 答复差异观测（子类型未知）",
        "R30": "R30 操作系统指纹探测候选",
    }[rule_id]
