import json
import secrets

from sqlalchemy import select

from packages.contracts.context import SOURCE_FAMILIES, DatasetContext, source_family
from packages.storage import schema_v3 as t
from packages.storage.service import Actor, DataService, DomainError, digest

DEFAULT_IMPORT_SENSOR = "lab-sensor-01"


class SensorSelectionRequired(DomainError):
    def __init__(self, sensor_ids: list[str]):
        super().__init__("SENSOR_SELECTION_REQUIRED", 422)
        self.sensor_ids = sensor_ids


class ContextService:
    def __init__(self, service: DataService):
        self.service = service

    def configure(self, actor: Actor, dataset_id: str, payload: DatasetContext, key: str) -> dict:
        self.service.require(actor, ("admin",))
        data = payload.model_dump(mode="json")
        # Empty optional D7 reference data must not change a D4-D6 context hash.
        if not data["egress_baselines"]:
            data.pop("egress_baselines")
        checksum = digest(json.dumps(data, sort_keys=True, separators=(",", ":")).encode())
        with self.service.db.engine.begin() as conn:
            conn.execute(
                select(t.workspaces)
                .where(t.workspaces.c.id == actor.workspace_id)
                .with_for_update()
            ).first()
            self.service._get(conn, t.datasets, actor, dataset_id)
            previous = self.service._idem(conn, actor, f"context:{dataset_id}", key, checksum)
            if previous:
                return previous
            existing = (
                conn.execute(
                    select(t.contexts).where(
                        t.contexts.c.workspace_id == actor.workspace_id,
                        t.contexts.c.id == dataset_id,
                    )
                )
                .mappings()
                .first()
            )
            if existing:
                if existing["context_hash"] != checksum:
                    raise DomainError("CONTEXT_IMMUTABLE_USE_NEW_DATASET", 409)
            else:
                started = conn.execute(
                    select(t.batches.c.id)
                    .where(
                        t.batches.c.workspace_id == actor.workspace_id,
                        t.batches.c.dataset_id == dataset_id,
                    )
                    .limit(1)
                ).first()
                if started:
                    raise DomainError("CONTEXT_MUST_PRECEDE_IMPORT", 409)
                conn.execute(
                    t.contexts.insert().values(
                        workspace_id=actor.workspace_id,
                        id=dataset_id,
                        payload=data,
                        context_hash=checksum,
                    )
                )
            secret = conn.execute(
                select(t.private_keys.c.workspace_id).where(
                    t.private_keys.c.workspace_id == actor.workspace_id
                )
            ).first()
            if not secret:
                conn.execute(
                    t.private_keys.insert().values(
                        workspace_id=actor.workspace_id, salt=secrets.token_hex(32)
                    )
                )
            result = {"dataset_id": dataset_id, "context_hash": checksum}
            self.service._remember(conn, actor, f"context:{dataset_id}", key, checksum, result)
            self.service._audit(conn, actor, "context.configure", dataset_id)
            return result

    def _stored_context(self, conn, actor: Actor, dataset_id: str) -> DatasetContext | None:
        payload = conn.execute(
            select(t.contexts.c.payload).where(
                t.contexts.c.workspace_id == actor.workspace_id, t.contexts.c.id == dataset_id
            )
        ).scalar_one_or_none()
        return DatasetContext.model_validate(payload) if payload is not None else None

    def resolve_import_sensor(
        self, conn, actor: Actor, dataset_id: str, source: str, sensor: str | None
    ) -> str:
        if sensor is not None:
            self.parser_metadata(conn, actor, dataset_id, source, sensor)
            return sensor

        family = source_family(source)
        metadata = self._stored_context(conn, actor, dataset_id)
        if metadata is not None:
            candidates = sorted(s.sensor_id for s in metadata.sensors if s.source_type == family)
            if not candidates:
                raise DomainError("SENSOR_CONTEXT_MISMATCH", 422)
        else:
            if source.startswith("linux_"):
                raise DomainError("LINUX_CONTEXT_REQUIRED", 422)
            variants = [key for key, value in SOURCE_FAMILIES.items() if value == family]
            candidates = list(
                conn.execute(
                    select(t.batches.c.sensor_id)
                    .where(
                        t.batches.c.workspace_id == actor.workspace_id,
                        t.batches.c.dataset_id == dataset_id,
                        t.batches.c.source_type.in_([family, *variants]),
                        t.batches.c.status.in_(["queued", "running", "partial", "succeeded"]),
                    )
                    .distinct()
                    .order_by(t.batches.c.sensor_id)
                    .limit(100)
                ).scalars()
            )
        if len(candidates) > 1:
            raise SensorSelectionRequired(candidates)
        return candidates[0] if candidates else DEFAULT_IMPORT_SENSOR

    def parser_metadata(self, conn, actor: Actor, dataset_id: str, source: str, sensor: str):
        metadata = self._stored_context(conn, actor, dataset_id)
        if metadata is None:
            if source.startswith("linux_"):
                raise DomainError("LINUX_CONTEXT_REQUIRED", 422)
            return None, None
        profile = next((s for s in metadata.sensors if s.sensor_id == sensor), None)
        if profile is None or profile.source_type != source_family(source):
            raise DomainError("SENSOR_CONTEXT_MISMATCH", 422)
        salt = conn.execute(
            select(t.private_keys.c.salt).where(t.private_keys.c.workspace_id == actor.workspace_id)
        ).scalar_one()
        return metadata.model_dump(mode="json"), salt
