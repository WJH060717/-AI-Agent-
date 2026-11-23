"""Offline evaluation contracts. Never import these into API, worker or Agent packages."""

from typing import Literal, Self

from pydantic import AwareDatetime, Field, model_validator

from eval.inventory import InputObject
from packages.contracts.models import AgentBudget, Contract

Group = Literal["B0", "B1", "B2", "B3"]


class SourceInput(Contract):
    source_type: Literal["zeek", "suricata", "linux_auth", "linux_audit"]
    sensor_id: str = Field(min_length=1, max_length=100)
    object: InputObject


class RunInput(Contract):
    run_id: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,80}$")
    scenario_id: Literal["S1", "S2", "S3"]
    provenance_type: Literal["synthetic", "real_capture", "replayed", "derived"] = "synthetic"
    context: InputObject | None = None
    sources: list[SourceInput] = Field(min_length=1, max_length=20)


class EvaluationConfig(Contract):
    version: Literal["d11-evaluation@1.0.0"]
    profile: Literal["engineering", "formal"]
    model_mode: Literal["disabled", "protocol_stub", "configured"] = "disabled"
    inventory_freeze: InputObject | None = None
    repeats: int = Field(default=1, ge=1, le=3)
    groups: list[Group] = Field(default_factory=lambda: ["B0", "B1", "B2", "B3"])
    budget: AgentBudget = Field(default_factory=AgentBudget)
    runs: list[RunInput] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def complete_groups(self) -> Self:
        if sorted(self.groups) != ["B0", "B1", "B2", "B3"]:
            raise ValueError("EVALUATION_GROUPS_INCOMPLETE")
        if len({r.run_id for r in self.runs}) != len(self.runs):
            raise ValueError("DUPLICATE_EVALUATION_RUN")
        if self.profile == "formal" and (self.repeats != 3 or self.model_mode != "configured"):
            raise ValueError("FORMAL_NEEDS_THREE_REPEATS_AND_CONFIGURED_MODEL")
        return self


class Activity(Contract):
    id: str = Field(min_length=1, max_length=200)
    rule_id: Literal["R01", "R02", "R03", "R04", "R05", "R06"]
    asset_id: str | None
    start: AwareDatetime
    end: AwareDatetime
    observable: bool = True

    @model_validator(mode="after")
    def interval(self) -> Self:
        if self.end < self.start:
            raise ValueError("REVERSED_ACTIVITY_INTERVAL")
        return self


class Step(Contract):
    id: str = Field(min_length=1)
    observable: bool
    event_ids: list[str] = Field(default_factory=list)
    # Stable raw hash/record ranges allow labels to survive isolated workspace IDs.
    locations: list[dict] = Field(default_factory=list)


class TruthEdge(Contract):
    from_step: str
    to_step: str
    relation: str
    observable: bool


class EdgePrediction(Contract):
    from_event_id: str
    to_event_id: str
    relation: str


class Execution(Contract):
    run_id: str
    scenario_id: str = "unspecified"
    group: Group
    repeat: int = Field(ge=0, le=2)
    status: Literal["completed", "partial", "failed", "blocked"]
    elapsed_ms: float = Field(ge=0, allow_inf_nan=False)
    mode: str = "unavailable"
    error: str | None = None
    detections: list[Activity] = Field(default_factory=list)
    graph_edges: list[EdgePrediction] = Field(default_factory=list)
    origins: list[str] = Field(default_factory=list)
    events: list[dict] = Field(default_factory=list)
    reports: list[dict] = Field(default_factory=list)
    usage: dict[str, int] = Field(default_factory=dict)
    investigations: list[dict] = Field(default_factory=list)
    references_total: int = Field(default=0, ge=0)
    references_valid: int = Field(default=0, ge=0)
    observed_validated: int = Field(default=0, ge=0)
    rejected_claims: int = Field(default=0, ge=0)
    before_after: list[dict] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def valid_references(self) -> Self:
        if self.references_valid > self.references_total:
            raise ValueError("INVALID_REFERENCE_COUNTS")
        return self
