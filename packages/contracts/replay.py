from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field, StrictInt

from packages.contracts.models import Contract


class ReplayCreate(Contract):
    source_session_id: UUID
    rate_eps: Annotated[StrictInt, Field(ge=1, le=1000)] = 50


class ReplayStatus(Contract):
    job_id: UUID
    dataset_id: UUID
    session_id: UUID
    source_session_id: UUID
    input_mode: Literal["replay"] = "replay"
    state: Literal["queued", "running", "completed", "partial", "failed", "cancelled"]
    source_high_water: int
    total_events: int
    published_events: int
    rate_eps: int
    detection_status: Literal["pending", "complete", "partial"]
    warnings: list[str] = Field(default_factory=list)
