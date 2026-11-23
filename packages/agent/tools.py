"""D2 trusted read-only boundary; not an LLM dispatcher or completed Agent."""

from dataclasses import dataclass

from packages.contracts.models import InvestigationScope, NormalizedEvent
from packages.storage.service import Actor, DataService, DomainError


@dataclass(frozen=True)
class ReadOnlyTools:
    service: DataService
    actor: Actor
    scope: InvestigationScope
    allowed_event_ids: frozenset[str]

    def get_event_evidence(self, event_id: str) -> NormalizedEvent:
        if (
            str(self.scope.workspace_id) != self.actor.workspace_id
            or event_id not in self.allowed_event_ids
        ):
            raise DomainError("EVIDENCE_OUT_OF_SCOPE", 404)
        event = NormalizedEvent.model_validate(self.service.get_event(self.actor, event_id))
        if (
            event.dataset_id != self.scope.dataset_id
            or not self.scope.start <= event.event_time < self.scope.end
        ):
            raise DomainError("EVIDENCE_OUT_OF_SCOPE", 404)
        self.service.verify_evidence(self.actor, event_id)
        return event

    def search_events(self, limit: int = 100) -> list[NormalizedEvent]:
        if not 1 <= limit <= 100:
            raise DomainError("INVALID_LIMIT", 422)
        page = self.service.list_events(
            self.actor, str(self.scope.dataset_id), str(self.scope.session_id), 100
        )
        if page["next_cursor"]:
            raise DomainError("D2_SCOPE_TOO_LARGE_NARROW_DATASET", 422)
        result = []
        for item in page["items"]:
            if item["event_id"] in self.allowed_event_ids:
                event = self.get_event_evidence(item["event_id"])
                result.append(event)
                if len(result) == limit:
                    break
        return result
