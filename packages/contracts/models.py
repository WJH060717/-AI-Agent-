"""D1 structural contracts. Runtime authorization/support verification comes later."""

import hashlib
import json
from datetime import UTC
from typing import Annotated, Any, ClassVar, Literal, Self
from uuid import UUID

from pydantic import (
    AfterValidator,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    StrictBool,
    StrictInt,
    StrictStr,
    model_validator,
)

from packages.contracts.protocols import DNSObservation, HTTPObservation

Digest = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
Text = Annotated[str, Field(min_length=1, max_length=4096)]
NonNegative = Annotated[StrictInt, Field(ge=0)]
Port = Annotated[StrictInt, Field(ge=0, le=65535)]
Timestamp = Annotated[AwareDatetime, AfterValidator(lambda value: value.astimezone(UTC))]


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_default=True)


FloodBehavior = Literal["HTTP_Flood", "SYN_Flood", "TCP_Flood", "UDP_Flood"]
FloodSupport = Literal["flood_candidate", "request_burst_only"]


class FloodObservation(Contract):
    behavior: FloodBehavior
    observed_source_ip_count: Annotated[StrictInt, Field(ge=1)]
    campaign_scope: Literal["unknown"]
    support: FloodSupport


class PcapRecordRange(Contract):
    byte_start: Annotated[StrictInt, Field(ge=24)]
    byte_end: Annotated[StrictInt, Field(le=32 * 1024 * 1024)]

    @model_validator(mode="after")
    def validate_length(self) -> Self:
        if self.byte_end - self.byte_start < 16:
            raise ValueError("PCAP range must include a record header")
        return self


class SourceLocator(Contract):
    object_id: UUID
    record_start: Annotated[StrictInt, Field(ge=1)]
    record_end: Annotated[StrictInt, Field(ge=1)]
    raw_sha256: Digest
    pcap: PcapRecordRange | None = Field(default=None, exclude_if=lambda value: value is None)

    @model_validator(mode="after")
    def ordered_range(self) -> Self:
        if self.record_end < self.record_start:
            raise ValueError("record_end must be >= record_start")
        if self.pcap is not None and self.record_start != self.record_end:
            raise ValueError("PCAP locator must identify one physical record")
        return self


class EvidenceRef(Contract):
    event_id: Digest
    fragments: Annotated[list[SourceLocator], Field(min_length=1)]
    fields_used: list[Text] = Field(default_factory=list)


class TimeQuality(Contract):
    original: Text
    timezone: Text
    offset_ms: StrictInt
    uncertainty_ms: NonNegative
    basis: Text


class Sensor(Contract):
    sensor_id: Text
    type: Literal["pcap", "zeek", "suricata", "linux_auth", "linux_audit", "sysmon"]
    instance_id: Text
    observation_domain: Text


class Endpoint(Contract):
    ip: IPvAnyAddress
    port: Port | None = None
    asset_id: UUID | None = None
    resolution_quality: Literal["unknown", "inventory_interval", "ambiguous"] = "unknown"


class Network(Contract):
    transport: Literal["tcp", "udp", "icmp", "icmpv6", "other"]
    uid: Text | None = None
    flow_id: Text | None = None  # source integers normalized to strings by adapters
    community_id: Text | None = None
    duration_ms: Annotated[float, Field(ge=0, allow_inf_nan=False)] | None = None
    bytes_out: NonNegative | None = None
    bytes_in: NonNegative | None = None


class Process(Contract):
    pid: NonNegative
    action: Literal["create", "exec", "observe"]
    entity_id: Text | None = None
    parent_entity_id: Text | None = None
    boot_id: Text | None = None
    start_time: Timestamp | None = None
    start_ticks: NonNegative | None = None
    identity_basis: Literal["pid_only", "lifecycle_record", "verified_proc", "process_guid"]
    executable: Text | None = None
    command_redacted: Text | None = None

    @model_validator(mode="after")
    def strong_identity(self) -> Self:
        if self.entity_id or self.parent_entity_id:
            if self.identity_basis == "pid_only":
                raise ValueError("PID-only observation cannot claim strong entity identity")
            if self.identity_basis != "process_guid" and (
                not self.boot_id or (self.start_time is None and self.start_ticks is None)
            ):
                raise ValueError("strong Linux identity requires boot and process birth marker")
        return self


class User(Contract):
    entity_id: Text | None = None
    name_redacted: Text | None = None
    realm: Text | None = None
    session_id: Text | None = None


class Auth(Contract):
    outcome: Literal["success", "failure", "unknown"]
    method: Text
    service: Text


class Alert(Contract):
    rule_id: Text
    signature: Text | None = None
    native_severity: NonNegative | None = None
    category: Text | None = None


class HostIdentity(Contract):
    asset_id: UUID
    boot_id: Text | None = None


Octet = Annotated[StrictInt, Field(ge=0, le=255)]


class HttpSegmentObservation(Contract):
    sequence: Annotated[StrictInt, Field(ge=0, le=4294967295)]
    request_start: StrictBool
    text_prefix: StrictBool
    header_transitions: tuple[
        Literal[0, 1, 2, 3, 4],
        Literal[0, 1, 2, 3, 4],
        Literal[0, 1, 2, 3, 4],
        Literal[0, 1, 2, 3, 4],
    ]


GreEncapsulation = Literal["ip", "ethernet"]


class DnsDatagramObservation(Contract):
    message_type: Literal["query", "query_context", "response"]
    transaction_id: Annotated[StrictInt, Field(ge=0, le=65535)]
    question_sha256: Digest
    qtype: Literal[1, 28]
    answer_set_sha256: Digest | None = Field(default=None, exclude_if=lambda value: value is None)

    @model_validator(mode="after")
    def check_answer(self) -> Self:
        if (self.message_type == "response") != (self.answer_set_sha256 is not None):
            raise ValueError("only successful direct DNS responses have an answer set")
        return self


class OsProbeObservation(Contract):
    role: Literal["udp_request", "icmp_quote", "tcp_request", "tcp_response"]
    correlation_sha256: Digest


class PacketObservation(Contract):
    protocol_number: Octet
    captured_length: NonNegative
    wire_length: NonNegative
    capture_precision: Literal["microsecond"] = "microsecond"
    ip_id: Annotated[StrictInt, Field(ge=0, le=65535)]
    fragment_offset_bytes: Annotated[StrictInt, Field(ge=0, le=65528, multiple_of=8)]
    more_fragments: StrictBool
    tcp_flags: Annotated[StrictInt, Field(ge=0, le=511)] | None = None
    tcp_payload_bytes_captured: NonNegative | None = None
    icmp_type: Octet | None = None
    icmp_code: Octet | None = None
    icmp_echo_header_complete: StrictBool | None = Field(
        default=None, exclude_if=lambda value: value is None
    )

    gre_encapsulation: GreEncapsulation | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
    http_segment: HttpSegmentObservation | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
    dns_message: DnsDatagramObservation | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
    os_probe: OsProbeObservation | None = Field(
        default=None, exclude_if=lambda value: value is None
    )

    @model_validator(mode="after")
    def check_fields(self) -> Self:
        if self.gre_encapsulation is not None and (
            self.protocol_number != 47
            or self.fragment_offset_bytes
            or self.more_fragments
            or self.captured_length != self.wire_length
        ):
            raise ValueError("GRE observation requires a complete nonfragmented IPv4 packet")
        if self.http_segment is not None and (
            self.protocol_number != 6
            or self.fragment_offset_bytes
            or self.more_fragments
            or not self.tcp_payload_bytes_captured
            or self.captured_length != self.wire_length
        ):
            raise ValueError("HTTP segment observation requires complete nonfragmented TCP data")
        if self.dns_message is not None and (
            self.protocol_number != 17 or self.fragment_offset_bytes or self.more_fragments
            or self.captured_length != self.wire_length
        ):
            raise ValueError("DNS observation requires complete nonfragmented UDP data")
        if self.os_probe is not None:
            protocol = {"udp_request": 17, "icmp_quote": 1, "tcp_request": 6, "tcp_response": 6}
            if (
                self.protocol_number != protocol[self.os_probe.role]
                or self.fragment_offset_bytes or self.more_fragments
                or self.captured_length != self.wire_length or self.dns_message is not None
            ):
                raise ValueError("fingerprint observation requires a complete corresponding packet")
            if self.os_probe.role == "icmp_quote" and (self.icmp_type, self.icmp_code) != (3, 3):
                raise ValueError("fingerprint quote requires the recorded ICMP error type")
            if self.os_probe.role == "tcp_request" and (
                self.tcp_flags != 2 or self.tcp_payload_bytes_captured != 0
            ):
                raise ValueError("fingerprint TCP request requires a SYN without payload")
            if self.os_probe.role == "tcp_response" and self.tcp_flags not in {18, 20}:
                raise ValueError("fingerprint TCP response requires a paired acknowledgement")
        tcp = self.tcp_flags is not None or self.tcp_payload_bytes_captured is not None
        icmp = self.icmp_type is not None or self.icmp_code is not None
        if self.icmp_echo_header_complete is not None and (
            self.icmp_type not in (0, 8) or self.icmp_code != 0
        ):
            raise ValueError("Echo completeness needs an observed Echo header")
        if self.captured_length > self.wire_length:
            raise ValueError("captured length exceeds wire length")
        if (
            (tcp and self.protocol_number != 6)
            or (icmp and self.protocol_number != 1)
            or (self.fragment_offset_bytes and (tcp or icmp))
        ):
            raise ValueError("transport fields do not belong to this packet")
        return self


class ArpSenderObservation(Contract):
    protocol_number: ClassVar[None] = None
    sender_mac: Annotated[str, Field(pattern=r"^[a-f0-9]{12}$")]
    captured_length: NonNegative
    wire_length: NonNegative

    @model_validator(mode="after")
    def check_frame(self) -> Self:
        if self.captured_length != self.wire_length or self.captured_length < 42:
            raise ValueError("ARP requires a complete Ethernet frame")
        if self.sender_mac == "000000000000" or int(self.sender_mac[:2], 16) & 1:
            raise ValueError("ARP sender requires a unicast Ethernet address")
        return self


class ArpRequestObservation(ArpSenderObservation):
    arp_operation: Literal[1]


class ArpReplyObservation(ArpSenderObservation):
    arp_operation: Literal[2]


class NormalizedEvent(Contract):
    schema_version: Literal["1.0", "1.1", "1.2", "1.3", "1.4", "1.5", "1.6", "1.7", "1.8", "1.9"]
    event_id: Digest
    workspace_id: UUID
    dataset_id: UUID
    event_type: Literal[
        "network.connection",
        "network.dns",
        "network.http",
        "network.packet",
        "host.process",
        "auth.login",
        "security.alert",
        "file.write",
    ]
    event_time: Timestamp
    ingested_at: Timestamp
    time_quality: TimeQuality
    sensor: Sensor
    source_locators: Annotated[list[SourceLocator], Field(min_length=1)]
    parser_version: Text
    asset_id: UUID | None = None
    host: HostIdentity | None = None
    src: Endpoint | None = None
    dst: Endpoint | None = None
    network: Network | None = None
    http: HTTPObservation | None = None
    packet: PacketObservation | ArpRequestObservation | ArpReplyObservation | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
    dns: DNSObservation | None = None
    process: Process | None = None
    user: User | None = None
    auth: Auth | None = None
    alert: Alert | None = None
    quality_flags: list[Text] = Field(default_factory=list)
    extensions: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def payload_required(self) -> Self:
        if self.schema_version in {"1.7", "1.8", "1.9"} and self.event_type != "network.packet":
            raise ValueError("packet schema version is reserved for network.packet")
        if self.event_type == "network.packet":
            dns_message = (
                self.packet.dns_message if isinstance(self.packet, PacketObservation) else None
            )
            packet_version = "1.6"
            if isinstance(self.packet, ArpRequestObservation):
                packet_version = "1.7"
            elif isinstance(self.packet, ArpReplyObservation) or dns_message is not None:
                packet_version = "1.8"
            elif isinstance(self.packet, PacketObservation) and self.packet.os_probe is not None:
                packet_version = "1.9"
            if (
                self.schema_version != packet_version
                or self.sensor.type != "pcap"
                or self.packet is None
                or self.src is None
                or self.dst is None
                or any(endpoint.ip.version != 4 for endpoint in (self.src, self.dst))
                or any(
                    value is not None
                    for value in (
                        self.network,
                        self.http,
                        self.dns,
                        self.process,
                        self.user,
                        self.auth,
                        self.alert,
                        self.host,
                    )
                )
                or bool(self.extensions)
                or len(self.source_locators) != 1
                or self.source_locators[0].pcap is None
            ):
                raise ValueError("missing or conflicting PCAP packet payload")
            if dns_message is not None:
                client, resolver = (
                    (self.dst, self.src) if dns_message.message_type == "response"
                    else (self.src, self.dst)
                )
                if not client.port or client.port == 53 or resolver.port != 53:
                    raise ValueError("DNS observation direction must match UDP endpoints")
            if (
                self.packet.protocol_number not in (6, 17)
                or self.packet.fragment_offset_bytes
            ) and any(endpoint.port is not None for endpoint in (self.src, self.dst)):
                raise ValueError("transport ports do not belong to this packet")
        elif self.packet is not None or any(ref.pcap is not None for ref in self.source_locators):
            raise ValueError("PCAP packet payload is reserved for network.packet")
        required = {
            "network.http": self.schema_version in {"1.2", "1.3", "1.4", "1.5"}
            and self.http is not None
            and self.src is not None
            and self.dst is not None
            and self.network is not None,
            "network.dns": self.schema_version not in {"1.2", "1.3", "1.4", "1.5"}
            or (
                self.dns is not None
                and self.src is not None
                and self.dst is not None
                and self.network is not None
            ),
            "network.connection": self.src is not None
            and self.dst is not None
            and self.network is not None,
            "host.process": self.process is not None,
            "auth.login": self.auth is not None
            and (self.dst is not None or self.asset_id is not None),
            "security.alert": self.alert is not None,
        }
        if not required.get(self.event_type, True):
            raise ValueError(f"missing required payload for {self.event_type}")
        if (
            self.process
            and (self.process.entity_id or self.process.parent_entity_id)
            and not self.asset_id
        ):
            raise ValueError("strong process identity requires a host asset")
        if (
            self.process
            and self.process.identity_basis == "process_guid"
            and self.sensor.type != "sysmon"
        ):
            raise ValueError("process_guid identity is reserved for Sysmon telemetry")
        if len(json.dumps(self.extensions, ensure_ascii=False).encode()) > 16384:
            raise ValueError("extensions exceeds 16 KiB")
        return self


def stable_event_id(
    workspace_id: UUID,
    dataset_id: UUID,
    sensor_id: str,
    locators: list[SourceLocator],
    *,
    native_record_id: str | None = None,
    instance_id: str | None = None,
) -> str:
    """Canonical ID independent of random storage object IDs, stable within a dataset."""
    if not locators:
        raise ValueError("at least one source locator required")
    if native_record_id is not None:
        if not native_record_id or not instance_id:
            raise ValueError("native identity requires nonempty ID and sensor instance")
        source: Any = {"instance_id": instance_id, "native_record_id": native_record_id}
    else:
        source = sorted({(p.raw_sha256, p.record_start, p.record_end) for p in locators})
    canonical = json.dumps(
        [str(workspace_id), str(dataset_id), sensor_id, source],
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class InvestigationScope(Contract):
    workspace_id: UUID
    dataset_id: UUID
    session_id: UUID
    snapshot_id: UUID
    start: Timestamp
    end: Timestamp

    @model_validator(mode="after")
    def time_window(self) -> Self:
        if not 0 < (self.end - self.start).total_seconds() <= 1800:
            raise ValueError("snapshot window must be positive and <= 30 minutes")
        return self


class GraphEdge(Contract):
    edge_id: Text
    snapshot_id: UUID
    source: Text
    target: Text
    relation: Literal[
        "spawned",
        "authenticated",
        "opened",
        "communicated_with",
        "associated_process",
        "corresponds_to",
        "suggests",
        "precedes",
    ]
    kind: Literal["observed", "inferred", "derived"]
    evidence_refs: Annotated[list[EvidenceRef], Field(min_length=1)]
    method: Text
    method_version: Text
    score: Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]
    contradicting_refs: list[EvidenceRef] = Field(default_factory=list)
    explanation: Text | None = None


class FactPredicate(Contract):
    name: Literal[
        "connection_seen",
        "auth_outcome",
        "process_parent",
        "rule_triggered",
        "path_candidate",
        "periodicity_observed",
    ]
    values: dict[str, StrictStr | StrictInt | StrictBool]


class Claim(Contract):
    claim_id: Text
    kind: Literal["observed", "inferred", "unknown"]
    statement: Text
    fact_predicate: FactPredicate | None = None
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)
    knowledge_refs: list[Text] = Field(default_factory=list)
    support_level: Literal["high", "medium", "low", "unknown"] = "unknown"
    limitations: list[Text] = Field(default_factory=list)

    @model_validator(mode="after")
    def observed_requires_support(self) -> Self:
        if self.kind == "observed" and (not self.evidence_refs or self.fact_predicate is None):
            raise ValueError("observed claims require event evidence and a checkable predicate")
        return self


class PathScore(Contract):
    identity: float = Field(ge=0, le=1)
    time: float = Field(ge=0, le=1)
    relation_support: float = Field(ge=0, le=1)
    independent_corroboration: float = Field(default=0, ge=0, le=1)
    penalties: float = Field(default=0, ge=0, le=1)


class EventPathEdge(Contract):
    edge_id: Digest
    from_event_id: Digest
    to_event_id: Digest
    entity_edge_ids: list[Text] = Field(min_length=1)
    relation: Literal["associated_process", "spawned", "corresponds_to"]
    kind: Literal["observed", "inferred"]
    evidence_refs: list[EvidenceRef] = Field(min_length=2, max_length=2)
    score: float = Field(ge=0, le=1)
    components: PathScore
    explanation: Text


class CandidateOrigin(Contract):
    origin_id: Digest
    event_id: Digest
    asset_id: UUID | None = None
    classification: Literal[
        "external_entry_candidate", "internal_start_candidate", "earliest_observed"
    ]
    left_censored: bool
    evidence_refs: list[EvidenceRef] = Field(min_length=1)
    explanation: Text


class PathCandidate(Contract):
    path_id: Digest
    event_ids: list[Digest] = Field(min_length=2, max_length=7)
    edge_ids: list[Digest] = Field(min_length=1, max_length=6)
    score: float = Field(ge=0, le=1)
    support_level: Literal["high", "medium", "low"]
    observed_steps: int = Field(ge=0)
    inferred_steps: int = Field(ge=0)
    missing_steps: int = Field(ge=0)
    coverage: float = Field(ge=0, le=1)
    difference_event_ids: list[Digest] = Field(default_factory=list)


class PathBreakpoint(Contract):
    from_event_id: Digest | None = None
    to_event_id: Digest | None = None
    reason: Text
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)
    explanation: Text


class PathAnalysis(Contract):
    scope: InvestigationScope
    status: Literal["candidates", "insufficient_evidence"]
    origins: list[CandidateOrigin]
    paths: list[PathCandidate]
    alternatives: list[PathCandidate]
    links: list[EventPathEdge]
    breakpoints: list[PathBreakpoint]
    truncated: bool
    searched_paths: int = Field(ge=0)
    method_version: Text = "event_paths@1.0.0"
    limitations: list[Text]


class InvestigationGap(Contract):
    gap_id: Text
    hypothesis_id: Text
    code: Literal[
        "session_process",
        "destination_authentication",
        "normal_process_context",
        "process_socket_binding",
        "normal_baseline",
        "transferred_content",
        "authorized_operations",
    ]
    asset_id: UUID | None = None
    status: Literal["open", "resolved", "unavailable"]
    actionable: bool
    explanation: Text
    evidence_refs: list[EvidenceRef] = Field(default_factory=list, max_length=20)


class InvestigationHypothesis(Contract):
    hypothesis_id: Text
    finding_id: Digest
    rule_id: Text
    kind: Literal[
        "session_process_link",
        "remote_authentication",
        "unexplained_periodicity",
        "unexplained_outbound",
    ]
    status: Literal["open", "supported", "weakened"]
    statement: Text
    observation: Text
    supporting_refs: list[EvidenceRef] = Field(default_factory=list, max_length=20)
    contradicting_refs: list[EvidenceRef] = Field(default_factory=list, max_length=20)
    counterevidence_kind: Literal["none", "context_only"] = "none"
    limitations: list[Text] = Field(default_factory=list, max_length=10)


class InvestigationAssessment(Contract):
    known_evidence_ids: list[Digest] = Field(max_length=250)
    hypotheses: list[InvestigationHypothesis] = Field(max_length=20)
    gaps: list[InvestigationGap] = Field(max_length=100)
    truncated: bool = False


class InvestigationChange(Contract):
    action_seq: int = Field(ge=1)
    hypothesis_id: Text
    before_status: Literal["open", "supported", "weakened"]
    after_status: Literal["open", "supported", "weakened"]
    reason: Text
    evidence_refs: list[EvidenceRef] = Field(max_length=20)


class InvestigationComparison(Contract):
    method_version: Text = "bounded_assessment@1.0.0"
    config_hash: Digest
    before: InvestigationAssessment
    after: InvestigationAssessment
    changes: list[InvestigationChange] = Field(default_factory=list, max_length=40)
    stop_reason: Text


class ClaimValidation(Contract):
    method_version: Literal["finite_predicates@2.0.0"] = "finite_predicates@2.0.0"
    integrity: Literal["verified"] = "verified"
    validated_observed: int = Field(ge=0)
    unknown_claims: int = Field(ge=0)
    rejected_codes: list[Annotated[str, Field(pattern=r"^DRAFT_[A-Z_]+$", max_length=100)]] = Field(
        default_factory=list, max_length=2
    )
    repair_attempts: int = Field(ge=0, le=1)
    stop_reason: Text | None = None


class BehaviorAssessment(Contract):
    finding_id: Digest
    behavior: Text
    label: Text
    rule_id: Text
    rule_version: Text
    start_time: Timestamp
    end_time: Timestamp
    observation_domains: list[Text] = Field(min_length=1)
    sensor_instances: list[Text] = Field(min_length=1)
    evidence_refs: list[EvidenceRef] = Field(min_length=1)
    limitations: list[Text] = Field(default_factory=list)
    trace_status: Literal["successful", "unsuccessful"]
    trace_scope: Text
    trace_clue: Text
    trace_reason: Text
    trace_evidence_refs: list[EvidenceRef] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_trace_evidence(self) -> Self:
        if self.trace_status == "successful" and len({
            ref.event_id for ref in self.trace_evidence_refs
        }) < 2:
            raise ValueError("successful tracing requires two linked references")
        return self


class Report(Contract):
    report_id: UUID
    run_id: UUID
    snapshot_id: UUID
    mode: Literal["live", "cached", "deterministic_fallback"]
    generated_at: Timestamp
    summary: Text
    claims: list[Claim]
    timeline: list[Digest] = Field(default_factory=list)
    candidate_origins: list[Text] = Field(default_factory=list)
    paths: list[Text] = Field(default_factory=list)
    path_analysis: PathAnalysis | None = None
    investigation_analysis: InvestigationComparison | None = None
    claim_validation: ClaimValidation | None = None
    behavior_assessments: list[BehaviorAssessment] | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
    affected_assets: list[UUID] = Field(default_factory=list)
    hypotheses: list[Text] = Field(default_factory=list)
    alternatives: list[Text] = Field(default_factory=list)
    gaps: list[Text] = Field(default_factory=list)
    recommendations: list[Text] = Field(default_factory=list)
    provenance: dict[str, str]
    validation: Literal["pending", "passed", "partial", "rejected"] = "pending"


class AgentBudget(Contract):
    max_cost_microusd: Annotated[StrictInt, Field(ge=0, le=100_000_000)] | None = None
    max_tool_calls: Annotated[StrictInt, Field(ge=0, le=6)] = 6
    max_model_calls: Annotated[StrictInt, Field(ge=0, le=4)] = 4
    max_input_tokens: Annotated[StrictInt, Field(ge=0, le=12000)] = 12000
    max_output_tokens: Annotated[StrictInt, Field(ge=0, le=3000)] = 3000
    model_wait_seconds: Annotated[StrictInt, Field(ge=0, le=60)] = 60
    timeout_seconds: Annotated[StrictInt, Field(ge=1, le=90)] = 90


class ToolDecision(Contract):
    action: Literal["call_tool"]
    tool: Literal[
        "search_events",
        "get_event_evidence",
        "get_process_context",
        "get_asset_timeline",
        "get_candidate_paths",
        "get_technique_context",
    ]
    arguments: dict[str, Any]
    reason_summary: Text
    expected_evidence: Text


class ContractBundle(Contract):
    event: NormalizedEvent
    evidence: EvidenceRef
    edge: GraphEdge
    claim: Claim
    report: Report
    scope: InvestigationScope
    budget: AgentBudget
    decision: ToolDecision
