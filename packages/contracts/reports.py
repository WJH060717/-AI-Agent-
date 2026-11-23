from typing import Literal
from uuid import UUID

from pydantic import Field

from packages.contracts.evidence import EvidenceResponse
from packages.contracts.models import Contract, Digest, InvestigationScope, Report, Timestamp


class ReviewCreate(Contract):
    claim_id: str = Field(min_length=1, max_length=200)
    decision: Literal["accepted", "rejected", "needs_more_evidence"]
    comment: str = Field(min_length=1, max_length=2000, pattern=r"\S")


class ReviewRecord(ReviewCreate):
    review_id: UUID
    report_id: UUID
    actor_id: Digest
    created_at: Timestamp


class ReviewPage(Contract):
    items: list[ReviewRecord]
    next_cursor: str | None
    request_id: str


class ReportSummary(Contract):
    report_id: UUID
    run_id: UUID
    snapshot_id: UUID
    generated_at: Timestamp
    mode: str
    validation: str


class ReportPage(Contract):
    items: list[ReportSummary]
    next_cursor: str | None
    request_id: str


class ExportSnapshot(Contract):
    scope: InvestigationScope
    event_ids: list[Digest]


class ReportExport(Contract):
    format_version: Literal["1.0.0"] = "1.0.0"
    exported_at: Timestamp
    report: Report
    snapshot: ExportSnapshot
    run_state: Literal["completed", "partial"]
    evidence: list[EvidenceResponse]
    reviews: list[ReviewRecord]
    limitations: list[str]


class RuntimeConfiguration(Contract):
    model_provider: Literal["disabled", "compatible"]
    model_test_stub: bool
    model_config_hash: Digest
    currency: Literal["USD"] = "USD"
    agent_max_cost_microusd: int
    pricing_configured: bool
    price_version: str
    report_export_max_lines: int
    report_export_max_bytes: int
    read_requests_per_minute: int
    write_requests_per_minute: int
