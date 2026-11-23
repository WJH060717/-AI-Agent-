"""Project reproduced findings into the bounded behavior and trace report."""

from packages.contracts.models import BehaviorAssessment, EvidenceRef, NormalizedEvent, PathAnalysis
from packages.detection.common import strong_process

BEHAVIOR_BY_RULE = {
    "R02": ("brute_force_suspected", "疑似暴力破解"),
    "R24": ("port_scan", "端口扫描行为"),
    "R26": ("host_discovery_suspected", "疑似主机发现"),
    "R28": ("arp_spoofing_suspected", "疑似 ARP 欺骗"),
    "R29": ("dns_spoofing_suspected", "疑似 DNS 欺骗"),
    "R30": ("os_fingerprint_probe", "操作系统指纹探测"),
}
GRE_LABELS = {
    "ip": ("gre_ip_flood", "GRE 直接 IP 封装洪泛"),
    "ethernet": ("gre_ethernet_flood", "GRE 以太网封装洪泛"),
}


def assess_behaviors(
    findings: list[dict],
    events: list[NormalizedEvent],
    refs: list[EvidenceRef],
    paths: PathAnalysis,
    stop_reason: str | None,
) -> list[BehaviorAssessment]:
    by_id = {event.event_id: event for event in events}
    evidence = {ref.event_id: ref for ref in refs}
    observed_auth_links = {}
    for link in paths.links:
        if (
            link.kind == "observed"
            and link.relation == "associated_process"
            and strong_process(by_id[link.to_event_id])
        ):
            observed_auth_links.setdefault(link.from_event_id, []).append(link)

    assessments = []
    for finding in findings:
        rule = finding["rule_id"]
        entry = BEHAVIOR_BY_RULE.get(rule)
        limitations = list(finding.get("limitations", []))
        if rule == "R27":
            entry = GRE_LABELS.get(finding.get("gre_encapsulation"))
        if (
            rule == "R20"
            and finding.get("attack_subtype") == "DoS/DDoS-UDP_Flood"
            and (finding.get("flood_observation") or {}).get("support") == "flood_candidate"
        ):
            entry = ("direct_udp_flood", "直接 UDP 洪泛")
        if entry is None:
            continue
        if rule in {"R20", "R27"}:
            limitations.append("未独立确认恶意软件家族，Mirai 家族未知。")
        if rule == "R02":
            limitations.append("仅依据重复认证失败及后续认证记录，字典使用与授权情况未知。")
        if rule == "R24":
            limitations.append("探测授权情况未知。")

        ids = finding.get("contributing_evidence_ids", finding["evidence_ids"])
        sources = [by_id[event_id] for event_id in ids]
        auth_links = observed_auth_links.get(finding.get("success_id"), []) if rule == "R02" else []
        origin_ips = (
            {str(event.src.ip) for event in sources if event.src and event.src.ip}
            if rule not in {"R28", "R29"}
            else set()
        )
        clue = "证据可定位到所列观测记录。"
        if origin_ips:
            clue += f"贡献记录中可见 {len(origin_ips)} 个源地址，地址的发起设备归属待核。"
        scope = "发起设备、进程或实际路径"
        reason = "现有证据未把该行为绑定到发起设备、进程或独立路径记录。"
        trace_refs = []
        status = "unsuccessful"
        if auth_links:
            scope = "已观察到的目标认证会话至目标进程"
            reason = "同资产、启动实例及会话的强关联支持所列路径。发起侧溯源未成功，操作者未知。"
            trace_refs = list(
                {ref.event_id: ref for link in auth_links for ref in link.evidence_refs}.values()
            )
            status = "successful"
            if paths.truncated:
                reason += " 图覆盖受裁剪，仅确认这里列出的关联。"
        if stop_reason:
            reason += f" 调查提前停止，原因 {stop_reason}。"
        assessments.append(
            BehaviorAssessment(
                finding_id=finding["id"],
                behavior=entry[0],
                label=entry[1],
                rule_id=rule,
                rule_version=finding["rule_version"],
                start_time=min(event.event_time for event in sources),
                end_time=max(event.event_time for event in sources),
                observation_domains=sorted({event.sensor.observation_domain for event in sources}),
                sensor_instances=sorted({event.sensor.instance_id for event in sources}),
                evidence_refs=[evidence[event_id] for event_id in ids],
                limitations=limitations,
                trace_status=status,
                trace_scope=scope,
                trace_clue=clue,
                trace_reason=reason,
                trace_evidence_refs=trace_refs,
            )
        )
    return assessments
