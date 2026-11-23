"""Strict model-controlled arguments; scope and budget are never model arguments."""

from typing import Literal
from uuid import UUID

from pydantic import Field, StrictInt

from packages.contracts.models import Contract, Digest, FactPredicate, Timestamp


class FieldFilter(Contract):
    field: Literal[
        "event_type",
        "asset_id",
        "src.ip",
        "dst.ip",
        "user.entity_id",
        "process.entity_id",
        "auth.outcome",
    ]
    op: Literal["eq", "in"]
    value: str | list[str]


class PageArgs(Contract):
    limit: StrictInt = Field(default=20, ge=1, le=100)
    cursor: str | None = Field(default=None, max_length=4096)


class SearchArgs(PageArgs):
    types: list[
        Literal[
            "network.connection",
            "auth.login",
            "host.process",
            "security.alert",
            "network.dns",
            "network.http",
            "file.write",
        ]
    ] = Field(default_factory=list, max_length=7)
    asset_id: UUID | None = None
    start: Timestamp | None = None
    end: Timestamp | None = None
    field_filter: list[FieldFilter] = Field(default_factory=list, max_length=5)


class EvidenceArgs(Contract):
    event_ids: list[Digest] = Field(min_length=1, max_length=10)
    fields: list[
        Literal["event_time", "src", "dst", "process", "user", "auth", "source_locators"]
    ] = Field(default_factory=list, max_length=7)
    cursor: str | None = Field(default=None, max_length=4096)


class ProcessArgs(PageArgs):
    process_entity_id: str = Field(pattern=r"^process:[0-9a-f-]{36}$", max_length=44)
    depth: StrictInt = Field(default=1, ge=0, le=2)


class TimelineArgs(PageArgs):
    asset_id: UUID
    start: Timestamp | None = None
    end: Timestamp | None = None


class PathsArgs(Contract):
    incident_id: UUID
    top_k: StrictInt = Field(default=3, ge=1, le=3)


class TechniqueArgs(Contract):
    technique_ids: list[str] = Field(min_length=1, max_length=5)


TOOL_SCHEMAS = {
    "search_events": SearchArgs,
    "get_event_evidence": EvidenceArgs,
    "get_process_context": ProcessArgs,
    "get_asset_timeline": TimelineArgs,
    "get_candidate_paths": PathsArgs,
    "get_technique_context": TechniqueArgs,
}


class ToolResult(Contract):
    tool_call_id: str
    status: Literal["ok", "empty", "error", "timeout"]
    data: dict
    evidence_ids: list[Digest] = Field(default_factory=list)
    truncated: bool = False
    next_cursor: str | None = None
    coverage: dict
    warnings: list[str] = Field(default_factory=list)
    elapsed_ms: int = Field(default=0, ge=0)


class RequestedTool(Contract):
    action: Literal["call_tool"]
    tool: str = Field(min_length=1, max_length=80)
    arguments: dict
    reason_summary: str = Field(max_length=500)
    expected_evidence: str = Field(max_length=500)


class DraftDecision(Contract):
    action: Literal["draft"]
    reason_summary: str = Field(max_length=500)


class DraftClaim(Contract):
    knowledge_refs: list[str] = Field(default_factory=list, max_length=5)
    kind: Literal["observed", "inferred", "unknown"]
    statement: str = Field(default="", max_length=1000)
    fact_predicate: FactPredicate | None = None
    evidence_ids: list[Digest] = Field(default_factory=list, max_length=100)


class ReportDraft(Contract):
    claims: list[DraftClaim] = Field(default_factory=list, max_length=20)
    alternatives: list[str] = Field(default_factory=list, max_length=5)
    gaps: list[str] = Field(default_factory=list, max_length=10)


class BudgetUsed(Contract):
    cost_microusd: int = Field(default=0, ge=0)
    actual_cost_microusd: int = Field(default=0, ge=0)
    tool_calls: int = Field(default=0, ge=0)
    model_calls: int = Field(default=0, ge=0)
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    model_wait_ms: int = Field(default=0, ge=0)
