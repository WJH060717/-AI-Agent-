from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import Field

from packages.contracts.agent import BudgetUsed
from packages.contracts.context import DatasetContext
from packages.contracts.evidence import EvidenceResponse
from packages.contracts.models import (
    AgentBudget,
    Contract,
    FloodObservation,
    GraphEdge,
    NormalizedEvent,
    PipelineProgress,
    Report,
)
from packages.contracts.replay import ReplayCreate, ReplayStatus
from packages.contracts.reports import (
    ReportExport,
    ReportPage,
    ReviewCreate,
    ReviewPage,
    ReviewRecord,
    RuntimeConfiguration,
)


class DatasetCreate(Contract):
    name: str = Field(min_length=1, max_length=200)
    provenance_type: Literal["synthetic", "real_capture", "replayed", "derived"]


class DatasetResponse(DatasetCreate):
    dataset_id: UUID
    default_session_id: UUID


class DatasetPage(Contract):
    items: list[DatasetResponse]
    next_cursor: str | None
    request_id: str


class ImportResponse(Contract):
    batch_id: UUID
    job_id: UUID


class EventPage(Contract):
    items: list[NormalizedEvent]
    next_cursor: str | None
    request_id: str
    packet_evidence_scope: str | None = Field(default=None, exclude_if=lambda value: value is None)


class CaptureFailure(Contract):
    byte_offset: int
    record: int | None


class ImportStatus(Contract):
    id: UUID
    dataset_id: UUID
    session_id: UUID
    status: Literal["queued", "running", "succeeded", "partial", "failed", "cancelled"]
    accepted: int
    duplicate: int
    quarantined: int
    error_code: str | None
    raw_records: int = 0
    aggregated_records: int = 0
    skipped: int | None = Field(default=None, exclude_if=lambda value: value is None)
    packet_issue_counts: dict[str, int] | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
    packet_quality_counts: dict[str, int] | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
    capture_failure: CaptureFailure | None = Field(
        default=None, exclude_if=lambda value: value is None
    )


class ApiBundle(Contract):
    replay_create: ReplayCreate
    replay_status: ReplayStatus
    dataset: DatasetResponse
    dataset_page: DatasetPage
    import_response: ImportResponse
    import_status: ImportStatus
    events: EventPage
    investigation: InvestigationCreate
    run: RunResponse
    graph: GraphResponse
    report: Report
    evidence: EvidenceResponse
    incident_page: IncidentPage
    run_status: RunStatus
    dataset_context: DatasetContext
    context_response: ContextResponse
    agent_actions: AgentActionPage
    agent_transitions: AgentTransitionPage
    review_create: ReviewCreate
    review: ReviewRecord
    reviews: ReviewPage
    report_history: ReportPage
    report_export: ReportExport
    runtime_config: RuntimeConfiguration


class InvestigationCreate(Contract):
    mode: Literal["auto", "live", "deterministic"] = "auto"
    budget: AgentBudget | None = None


class RunResponse(Contract):
    run_id: UUID
    snapshot_id: UUID
    job_id: UUID
    state: str


class GraphNode(Contract):
    entity_id: str
    type: Literal["Endpoint", "Host", "Process", "User", "Session", "Connection", "Event"]
    label: str


class GraphResponse(Contract):
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    truncated: bool
    next_cursor: str | None = None
    total_nodes: int = 0
    total_edges: int = 0


class IncidentSummary(Contract):
    workspace_id: UUID
    id: UUID
    dataset_id: UUID
    session_id: UUID
    finding_id: str | None
    title: str
    attack_subtype: str | None = Field(default=None, exclude_if=lambda value: value is None)
    flood_observation: FloodObservation | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
    start_time: str
    end_time: str
    created_at: str
    finding_ids: list[str] = Field(default_factory=list)
    aggregation_reasons: list[AggregationReason] = Field(default_factory=list)


class AggregationReason(Contract):
    finding_ids: list[str]
    shared_entities: list[str]
    method: Literal["strong_entity_and_overlap"]


class IncidentPage(Contract):
    items: list[IncidentSummary]
    next_cursor: str | None
    request_id: str
    warnings: list[str] = Field(default_factory=list)


class RunStatus(Contract):
    pipeline_progress: PipelineProgress | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
    id: UUID
    incident_id: UUID
    snapshot_id: UUID
    job_id: UUID
    state: Literal["queued", "running", "completed", "failed", "cancelled", "partial"]
    report_id: UUID | None
    phase: str = "legacy"
    state_version: int = 0
    budget_used: BudgetUsed = Field(default_factory=BudgetUsed)
    budget: AgentBudget = Field(default_factory=AgentBudget)
    requested_mode: str = "auto"
    retrieved_count: int = 0
    cache_hits: int = 0
    stop_reason: str | None = None
    query_stop_reason: str | None = None


class ContextResponse(Contract):
    dataset_id: UUID
    context_hash: str


class AgentActionSummary(Contract):
    seq: int
    kind: Literal["model", "tool"]
    name: str
    status: str
    args_hash: str
    args_payload: dict | None
    result_digest: str | None
    request_id: str | None
    usage: dict | None
    error_code: str | None
    new_evidence_count: int
    evidence_ids: list[str] = Field(default_factory=list)
    cache_hit: int = 0
    reason_summary: str = ""
    started_at: str
    ended_at: str | None


class AgentActionPage(Contract):
    items: list[AgentActionSummary]
    next_cursor: str | None
    request_id: str


class AgentTransition(Contract):
    version: int
    phase: str
    reason: str
    occurred_at: str
    budget_used: BudgetUsed


class AgentTransitionPage(Contract):
    items: list[AgentTransition]
    next_cursor: str | None
    request_id: str


ApiBundle.model_rebuild()
