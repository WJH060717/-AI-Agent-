from packages.contracts.context import EgressBaseline
from packages.detection.fragmentation import (
    FRAGMENT_RULES,
    FragmentRule,
    detect_fragmentation,
    load_fragment_rules,
)
from packages.detection.freeze import load_frozen_rules
from packages.detection.freeze_cc import load_cc_rule
from packages.detection.freeze_encoding import load_encoding_rule
from packages.detection.freeze_endpoint import load_endpoint_rule
from packages.detection.freeze_http import load_http_rule
from packages.detection.freeze_nontext import load_nontext_rule
from packages.detection.gre_bursts import (
    GRE_BURST_RULE,
    GreBurstRule,
    detect_gre_bursts,
    load_gre_burst_rule,
)
from packages.detection.http_packets import (
    HTTP_PACKET_RULES,
    detect_http_packets,
    http_packet_config,
    load_http_packet_rules,
)
from packages.detection.limits import checkpoint
from packages.detection.os_fingerprint import (
    OS_FINGERPRINT_RULE,
    OsFingerprintRule,
    detect_os_fingerprints,
    load_os_fingerprint_rule,
)
from packages.detection.packet_bursts import BURST_RULES, BurstRule, detect_bursts, load_burst_rules
from packages.detection.packet_conflicts import (
    ARP_CONFLICT_RULE,
    DNS_DIFFERENCE_RULE,
    ArpConflictRule,
    DnsDifferenceRule,
    detect_arp_conflicts,
    detect_dns_differences,
    detect_packet_conflicts,
)
from packages.detection.packet_recon import (
    HOST_DISCOVERY_RULE,
    PING_SWEEP_RULE,
    PORT_SCAN_RULE,
    HostDiscoveryRule,
    PingSweepRule,
    PortScanRule,
    detect_host_discovery,
    detect_ping_sweeps,
    detect_port_scans,
    load_host_discovery_rule,
    load_ping_sweep_rule,
    load_port_scan_rule,
)
from packages.detection.r01 import R01Config, detect_scans
from packages.detection.r02 import R02Config, detect_auth_sequence
from packages.detection.r03 import R03Config, detect_process_anomalies
from packages.detection.r04 import R04Config, detect_remote_access
from packages.detection.r05 import R05Config, detect_periodic
from packages.detection.r06 import R06Config, detect_egress
from packages.detection.r07 import R07Config, detect_http_requests
from packages.detection.r08 import R08Config, detect_callbacks
from packages.detection.r09 import R09Config
from packages.detection.r10 import R10Config, detect_nontext_queries
from packages.detection.r11 import R11Config, detect_mixed_encoding


def detect_all(
    events, session_id: str, baselines: list[EgressBaseline] | None = None
) -> list[dict]:
    checkpoint(len(events))
    packets = [event for event in events if event.event_type == "network.packet"]
    events = [event for event in events if event.event_type != "network.packet"]
    configs = load_frozen_rules()
    http_rule = load_http_rule()
    cc_rule = load_cc_rule()
    endpoint_rule = load_endpoint_rule()
    nontext_rule = load_nontext_rule()
    base = (
        detect_scans(events, session_id, configs["R01"])
        + detect_auth_sequence(events, session_id, configs["R02"])
        + detect_process_anomalies(events, session_id, configs["R03"])
    )
    return (
        base
        + detect_remote_access(events, session_id, base, configs["R04"])
        + detect_periodic(events, session_id, configs["R05"])
        + detect_egress(events, session_id, configs["R06"], baselines=baselines)
        + detect_http_requests(events, session_id, http_rule)
        + detect_callbacks(events, session_id, cc_rule)
        + detect_callbacks(events, session_id, endpoint_rule)
        + detect_nontext_queries(events, session_id, nontext_rule)
        + detect_mixed_encoding(events, session_id, load_encoding_rule())
        + (detect_fragmentation(packets, session_id, load_fragment_rules()) if packets else [])
        + (detect_bursts(packets, session_id, load_burst_rules()) if packets else [])
        + (detect_gre_bursts(packets, session_id, load_gre_burst_rule()) if packets else [])
        + (detect_packet_conflicts(packets, session_id) if packets else [])
        + (
            detect_os_fingerprints(packets, session_id, load_os_fingerprint_rule())
            if packets else []
        )
        + (detect_http_packets(packets, session_id, load_http_packet_rules()) if packets else [])
        + (detect_port_scans(packets, session_id, load_port_scan_rule()) if packets else [])
        + (detect_ping_sweeps(packets, session_id, load_ping_sweep_rule()) if packets else [])
        + (
            detect_host_discovery(packets, session_id, load_host_discovery_rule())
            if packets else []
        )
    )


def reproduce(events, session_id: str, finding: dict) -> list[dict]:
    if finding["rule_id"] == OS_FINGERPRINT_RULE:
        rule = OsFingerprintRule.model_validate(finding["config"])
        if rule.version != finding["rule_version"]:
            raise ValueError("historical OS fingerprint rule identity mismatch")
        return detect_os_fingerprints(events, session_id, rule)
    if finding["rule_id"] == ARP_CONFLICT_RULE:
        rule = ArpConflictRule.model_validate(finding["config"])
        if rule.version != finding["rule_version"]:
            raise ValueError("historical ARP rule identity mismatch")
        return detect_arp_conflicts(events, session_id, rule)
    if finding["rule_id"] == DNS_DIFFERENCE_RULE:
        rule = DnsDifferenceRule.model_validate(finding["config"])
        if rule.version != finding["rule_version"]:
            raise ValueError("historical DNS rule identity mismatch")
        return detect_dns_differences(events, session_id, rule)
    if finding["rule_id"] == GRE_BURST_RULE:
        rule = GreBurstRule.model_validate(finding["config"])
        if rule.version != finding["rule_version"]:
            raise ValueError("historical GRE rule identity mismatch")
        return detect_gre_bursts(events, session_id, rule)
    if finding["rule_id"] == HOST_DISCOVERY_RULE:
        rule = HostDiscoveryRule.model_validate(finding["config"])
        if rule.version != finding["rule_version"]:
            raise ValueError("historical host discovery rule identity mismatch")
        return detect_host_discovery(events, session_id, rule)
    if finding["rule_id"] == PING_SWEEP_RULE:
        rule = PingSweepRule.model_validate(finding["config"])
        if rule.version != finding["rule_version"]:
            raise ValueError("historical ping sweep rule identity mismatch")
        return detect_ping_sweeps(events, session_id, rule)
    if finding["rule_id"] == PORT_SCAN_RULE:
        rule = PortScanRule.model_validate(finding["config"])
        if rule.version != finding["rule_version"]:
            raise ValueError("historical port scan rule identity mismatch")
        return detect_port_scans(events, session_id, rule)
    if finding["rule_id"] in HTTP_PACKET_RULES:
        config = http_packet_config(finding["config"])
        if (config.id, config.version) != (finding["rule_id"], finding["rule_version"]):
            raise ValueError("historical HTTP packet rule identity mismatch")
        return detect_http_packets(events, session_id, {config.id: config})
    if finding["rule_id"] in BURST_RULES:
        config = BurstRule.model_validate(finding["config"])
        if config.id != finding["rule_id"] or config.version != finding["rule_version"]:
            raise ValueError("historical burst rule identity mismatch")
        return detect_bursts(events, session_id, {config.id: config})
    if finding["rule_id"] in FRAGMENT_RULES:
        config = FragmentRule.model_validate(finding["config"])
        if config.id != finding["rule_id"] or config.version != finding["rule_version"]:
            raise ValueError("historical fragment rule identity mismatch")
        return detect_fragmentation(events, session_id, {config.id: config})
    if finding["rule_id"] == "R11":
        return detect_mixed_encoding(
            events, session_id, R11Config.model_validate(finding["config"])
        )
    if finding["rule_id"] == "R10":
        return detect_nontext_queries(
            events, session_id, R10Config.model_validate(finding["config"])
        )
    if finding["rule_id"] == "R09":
        return detect_callbacks(events, session_id, R09Config.model_validate(finding["config"]))
    if finding["rule_id"] == "R08":
        return detect_callbacks(events, session_id, R08Config.model_validate(finding["config"]))
    if finding["rule_id"] == "R07":
        return detect_http_requests(events, session_id, R07Config.model_validate(finding["config"]))
    if finding["rule_id"] == "R01":
        return detect_scans(events, session_id, R01Config.model_validate(finding["config"]))
    if finding["rule_id"] == "R02":
        return detect_auth_sequence(events, session_id, R02Config.model_validate(finding["config"]))
    if finding["rule_id"] == "R03":
        return detect_process_anomalies(
            events, session_id, R03Config.model_validate(finding["config"])
        )
    if finding["rule_id"] == "R04":
        sources = []
        for seed in finding["supporting_findings"]:
            subset = [e for e in events if e.event_id in seed["evidence_ids"]]
            sources.extend(f for f in reproduce(subset, session_id, seed) if f["id"] == seed["id"])
        return detect_remote_access(
            events, session_id, sources, R04Config.model_validate(finding["config"])
        )
    if finding["rule_id"] == "R05":
        return detect_periodic(events, session_id, R05Config.model_validate(finding["config"]))
    if finding["rule_id"] == "R06":
        reference = finding.get("baseline")
        return detect_egress(
            events,
            session_id,
            R06Config.model_validate(finding["config"]),
            [EgressBaseline.model_validate(reference)] if reference else [],
        )
    raise ValueError("unsupported rule version")
