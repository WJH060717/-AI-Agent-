"""Scoped D2 repositories and import orchestration; no model or evaluation access."""

import hashlib
import json
import os
import secrets
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from sqlalchemy import and_, func, or_, select

from packages.config import Settings
from packages.storage import schema_v4 as t
from packages.storage.database import Database


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_digest(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


@dataclass(frozen=True)
class Actor:
    workspace_id: str
    role: str
    digest: str
    cursor_secret: str | None = field(default=None, repr=False, compare=False)


class DomainError(ValueError):
    def __init__(self, code: str, status: int = 400):
        self.code, self.status = code, status
        super().__init__(code)


class DataService:
    def __init__(self, db: Database, settings: Settings):
        self.db, self.settings = db, settings

    def init_workspace(self, name: str) -> tuple[str, dict[str, str]]:
        workspace = str(uuid4())
        values = {role: secrets.token_urlsafe(32) for role in ("viewer", "analyst", "admin")}
        with self.db.engine.begin() as conn:
            conn.execute(t.workspaces.insert().values(id=workspace, name=name))
            conn.execute(
                t.private_keys.insert().values(workspace_id=workspace, salt=secrets.token_hex(32))
            )
            for role, token in values.items():
                conn.execute(
                    t.tokens.insert().values(
                        workspace_id=workspace, role=role, digest=digest(token.encode())
                    )
                )
        return workspace, values

    def system_actor(self, workspace: str) -> Actor:
        """Trusted CLI identity, not an HTTP credential."""
        with self.db.engine.connect() as conn:
            secret = conn.execute(
                select(t.private_keys.c.salt).where(t.private_keys.c.workspace_id == workspace)
            ).scalar_one()
        return Actor(workspace, "admin", digest(f"local-cli:{workspace}".encode()), secret)

    def authenticate(self, token: str) -> Actor:
        with self.db.engine.connect() as conn:
            row = (
                conn.execute(select(t.tokens).where(t.tokens.c.digest == digest(token.encode())))
                .mappings()
                .first()
            )
            secret = (
                conn.execute(
                    select(t.private_keys.c.salt).where(
                        t.private_keys.c.workspace_id == row["workspace_id"]
                    )
                ).scalar_one()
                if row
                else None
            )
        if row is None:
            raise DomainError("UNAUTHENTICATED", 401)
        return Actor(row["workspace_id"], row["role"], row["digest"], secret)

    @staticmethod
    def require(actor: Actor, roles: tuple[str, ...]) -> None:
        if actor.role not in roles:
            raise DomainError("FORBIDDEN", 403)

    @staticmethod
    def scoped(table, actor: Actor, object_id: str):
        return and_(table.c.workspace_id == actor.workspace_id, table.c.id == object_id)

    def _get(self, conn, table, actor: Actor, object_id: str):
        row = self._optional(conn, table, actor, object_id)
        if row is None:
            raise DomainError("NOT_FOUND", 404)
        return row

    def _optional(self, conn, table, actor: Actor, object_id: str):
        return (
            conn.execute(select(table).where(self.scoped(table, actor, object_id)))
            .mappings()
            .first()
        )

    def archive_path(self, storage_key: str) -> Path:
        """Resolve a server-owned relative archive key within the trusted raw-store root."""
        key = Path(storage_key)
        if key.is_absolute() or key.drive or ".." in key.parts:
            raise DomainError("EVIDENCE_UNAVAILABLE", 409)
        try:
            root = self.settings.raw_store.resolve()
            path = (root / key).resolve()
            if not path.is_relative_to(root) or not path.is_file():
                raise DomainError("EVIDENCE_UNAVAILABLE", 409)
            return path
        except (OSError, RuntimeError):
            raise DomainError("EVIDENCE_UNAVAILABLE", 409) from None

    def _idem(self, conn, actor: Actor, route: str, key: str, request_hash: str):
        if not key or len(key) > 200:
            raise DomainError("IDEMPOTENCY_KEY_REQUIRED", 422)
        where = and_(
            t.idempotency.c.workspace_id == actor.workspace_id,
            t.idempotency.c.actor == actor.digest,
            t.idempotency.c.route == route,
            t.idempotency.c.key == key,
        )
        row = conn.execute(select(t.idempotency).where(where)).mappings().first()
        if row and row["expires_at"] <= now():
            conn.execute(t.idempotency.delete().where(where))
            row = None
        if row and row["request_hash"] != request_hash:
            raise DomainError("IDEMPOTENCY_CONFLICT", 409)
        return row["response"] if row else None

    def _remember(self, conn, actor: Actor, route: str, key: str, request_hash: str, response):
        conn.execute(
            t.idempotency.insert().values(
                workspace_id=actor.workspace_id,
                actor=actor.digest,
                route=route,
                key=key,
                request_hash=request_hash,
                response=response,
                expires_at=(datetime.now(UTC) + timedelta(hours=24)).isoformat(
                    timespec="microseconds"
                ),
            )
        )

    def _audit(self, conn, actor: Actor, action: str, object_id: str):
        conn.execute(
            t.audit.insert().values(
                id=str(uuid4()),
                workspace_id=actor.workspace_id,
                actor=actor.digest,
                action=action,
                object_id=object_id,
                created_at=now(),
            )
        )

    def create_dataset(self, actor: Actor, payload: dict, key: str) -> dict:
        self.require(actor, ("admin",))
        request_hash = digest(json.dumps(payload, sort_keys=True).encode())
        with self.db.engine.begin() as conn:
            # Serialize mutations in a workspace, including concurrent idempotent requests.
            conn.execute(
                select(t.workspaces)
                .where(t.workspaces.c.id == actor.workspace_id)
                .with_for_update()
            ).first()
            existing = self._idem(conn, actor, "datasets", key, request_hash)
            if existing:
                return existing
            dataset_id, session_id = str(uuid4()), str(uuid4())
            conn.execute(
                t.datasets.insert().values(
                    workspace_id=actor.workspace_id,
                    id=dataset_id,
                    name=payload["name"],
                    provenance_type=payload["provenance_type"],
                    created_at=now(),
                    created_seq=(
                        conn.execute(
                            select(func.max(t.datasets.c.created_seq)).where(
                                t.datasets.c.workspace_id == actor.workspace_id
                            )
                        ).scalar_one()
                        or 0
                    )
                    + 1,
                )
            )
            conn.execute(
                t.sessions.insert().values(
                    workspace_id=actor.workspace_id,
                    id=session_id,
                    dataset_id=dataset_id,
                    mode="import",
                )
            )
            result = {
                "dataset_id": dataset_id,
                "default_session_id": session_id,
                "name": payload["name"],
                "provenance_type": payload["provenance_type"],
            }
            self._remember(conn, actor, "datasets", key, request_hash, result)
            self._audit(conn, actor, "dataset.create", dataset_id)
            return result

    def list_datasets(self, actor: Actor) -> list[dict]:
        page = self.dataset_page(actor, 100)
        if page["next_cursor"]:
            raise DomainError("DATASET_LIST_LIMIT_EXCEEDED", 422)
        return page["items"]

    def dataset_page(self, actor: Actor, limit: int = 50, cursor: str | None = None) -> dict:
        from packages.storage.paging import decode, encode, validate_limit

        validate_limit(limit)
        binding = ["datasets"]
        with self.db.engine.connect() as conn:
            position = decode(actor, binding, cursor) if cursor else None
            if position and (
                len(position) != 3
                or type(position[0]) is not int
                or not all(isinstance(v, str) for v in position[1:])
            ):
                raise DomainError("INVALID_CURSOR", 422)
            highwater = (
                position[0]
                if position
                else (
                    conn.execute(
                        select(func.max(t.datasets.c.created_seq)).where(
                            t.datasets.c.workspace_id == actor.workspace_id
                        )
                    ).scalar_one()
                    or 0
                )
            )
            query = (
                select(t.datasets, t.sessions.c.id.label("default_session_id"))
                .join(
                    t.sessions,
                    and_(
                        t.sessions.c.workspace_id == t.datasets.c.workspace_id,
                        t.sessions.c.dataset_id == t.datasets.c.id,
                        t.sessions.c.mode == "import",
                    ),
                )
                .where(
                    t.datasets.c.workspace_id == actor.workspace_id,
                    t.datasets.c.created_seq <= highwater,
                )
            )
            if position:
                query = query.where(
                    or_(
                        t.datasets.c.created_at > position[1],
                        and_(t.datasets.c.created_at == position[1], t.datasets.c.id > position[2]),
                    )
                )
            rows = (
                conn.execute(
                    query.order_by(t.datasets.c.created_at, t.datasets.c.id).limit(limit + 1)
                )
                .mappings()
                .all()
            )
        return {
            "items": [
                {
                    "dataset_id": row["id"],
                    "default_session_id": row["default_session_id"],
                    "name": row["name"],
                    "provenance_type": row["provenance_type"],
                }
                for row in rows[:limit]
            ],
            "next_cursor": encode(
                actor, binding, [highwater, rows[limit - 1]["created_at"], rows[limit - 1]["id"]]
            )
            if len(rows) > limit
            else None,
        }

    def stage_bytes(
        self,
        actor: Actor,
        dataset: str,
        source: str,
        sensor: str | None,
        timezone: str,
        content: bytes,
        key: str,
    ) -> dict:
        return self.stage_chunks(actor, dataset, source, sensor, timezone, [content], key)

    def stage_chunks(
        self,
        actor: Actor,
        dataset: str,
        source: str,
        sensor: str | None,
        timezone: str,
        chunks: Iterable[bytes],
        key: str,
    ) -> dict:
        from packages.storage.context import ContextService

        self.require(actor, ("admin",))
        if (
            source
            not in (
                "pcap",
                "pcap_http",
                "pcap_packet",
                "zeek",
                "zeek_http",
                "zeek_dns",
                "suricata",
                "linux_auth",
                "linux_audit",
                "linux_socket",
            )
            or (sensor is not None and not 1 <= len(sensor) <= 200)
        ):
            raise DomainError("UNSUPPORTED_SOURCE_OR_SENSOR", 422)
        # D2 requires explicit source timestamps; no guessing of naive timezones.
        if timezone != "UTC":
            raise DomainError("D2_TIMEZONE_MUST_BE_UTC", 422)
        with self.db.engine.connect() as conn:
            self._get(conn, t.datasets, actor, dataset)
        self.settings.staging_store.mkdir(parents=True, exist_ok=True)
        extension = "pcap" if source == "pcap_packet" else "jsonl"
        staging_key = f"{uuid4()}.{extension}"
        path = self.settings.staging_store / staging_key
        upload_limit = self.settings.max_upload_mb * 1024 * 1024
        if source == "pcap_packet":
            from packages.ingest.pcap_packet import MAX_CAPTURE_BYTES

            upload_limit = min(upload_limit, MAX_CAPTURE_BYTES)
        size, hasher = 0, hashlib.sha256()
        keep = False
        try:
            with path.open("xb") as target:
                for chunk in chunks:
                    size += len(chunk)
                    if size > upload_limit:
                        raise DomainError("UPLOAD_TOO_LARGE", 413)
                    target.write(chunk)
                    hasher.update(chunk)
                target.flush()
                os.fsync(target.fileno())
            if not size:
                raise DomainError("EMPTY_UPLOAD", 422)
            sha = hasher.hexdigest()
            request_hash = digest(json.dumps([dataset, source, sensor, timezone, sha]).encode())
            with self.db.engine.begin() as conn:
                conn.execute(
                    select(t.workspaces)
                    .where(t.workspaces.c.id == actor.workspace_id)
                    .with_for_update()
                ).first()
                existing = self._idem(conn, actor, "imports", key, request_hash)
                if existing:
                    return existing
                resolved_sensor = ContextService(self).resolve_import_sensor(
                    conn, actor, dataset, source, sensor
                )
                session_id = conn.execute(
                    select(t.sessions.c.id).where(
                        t.sessions.c.workspace_id == actor.workspace_id,
                        t.sessions.c.dataset_id == dataset,
                        t.sessions.c.mode == "import",
                    )
                ).scalar_one()
                batch_id, job_id = str(uuid4()), str(uuid4())
                conn.execute(
                    t.batches.insert().values(
                        workspace_id=actor.workspace_id,
                        id=batch_id,
                        dataset_id=dataset,
                        session_id=session_id,
                        source_type=source,
                        sensor_id=resolved_sensor,
                        timezone=timezone,
                        staging_key=staging_key,
                        sha256=sha,
                        byte_size=size,
                        status="queued",
                        accepted=0,
                        duplicate=0,
                        quarantined=0,
                    )
                )
                conn.execute(
                    t.jobs.insert().values(
                        id=job_id,
                        workspace_id=actor.workspace_id,
                        batch_id=batch_id,
                        state="queued",
                    )
                )
                result = {"batch_id": batch_id, "job_id": job_id}
                self._remember(conn, actor, "imports", key, request_hash, result)
                self._audit(conn, actor, "import.stage", batch_id)
            keep = True
            return result
        finally:
            if not keep:
                path.unlink(missing_ok=True)  # only this request's random staging file

    def get_batch(self, actor: Actor, batch_id: str) -> dict:
        self.require(actor, ("analyst", "admin"))
        with self.db.engine.connect() as conn:
            row = (
                conn.execute(
                    select(t.batches, t.jobs.c.checkpoint.label("job_checkpoint"))
                    .outerjoin(
                        t.jobs,
                        and_(
                            t.jobs.c.workspace_id == t.batches.c.workspace_id,
                            t.jobs.c.batch_id == t.batches.c.id,
                            t.jobs.c.kind == "import",
                        ),
                    )
                    .where(self.scoped(t.batches, actor, batch_id))
                )
                .mappings()
                .first()
            )
            if row is None:
                raise DomainError("NOT_FOUND", 404)
            result = {
                k: row[k]
                for k in (
                    "id",
                    "dataset_id",
                    "session_id",
                    "status",
                    "accepted",
                    "duplicate",
                    "quarantined",
                    "error_code",
                    "raw_records",
                    "aggregated_records",
                )
            }
            if row["source_type"] == "pcap_packet":
                checkpoint = row["job_checkpoint"] or {}
                packet_state = checkpoint.get("pcap", {})
                result["skipped"] = (
                    row["raw_records"] - row["aggregated_records"] - row["quarantined"]
                )
                result["packet_issue_counts"] = packet_state.get("issues", {})
                result["packet_quality_counts"] = packet_state.get("quality", {})
                failure = checkpoint.get("capture_failure")
                if failure is not None:
                    result["capture_failure"] = failure
            return result

    def process_one(self) -> bool:
        from packages.storage.queue import Queue
        from packages.storage.worker import Worker

        return Worker(self, Queue(self.db, self.settings)).run_one(raise_errors=True)

    def list_events(
        self, actor: Actor, dataset: str, session: str, limit: int, cursor: str | None = None
    ) -> dict:
        from packages.storage.paging import decode, encode, validate_limit

        validate_limit(limit)
        binding = ["events", dataset, session]
        with self.db.engine.connect() as conn:
            self._get(conn, t.datasets, actor, dataset)
            scope = self._get(conn, t.sessions, actor, session)
            if scope["dataset_id"] != dataset:
                raise DomainError("NOT_FOUND", 404)
            query = select(t.events).where(
                t.events.c.workspace_id == actor.workspace_id,
                t.events.c.dataset_id == dataset,
            )
            if cursor:
                position = decode(actor, binding, cursor)
                if (
                    len(position) != 3
                    or type(position[0]) is not int
                    or position[0] < 0
                    or not all(isinstance(v, str) for v in position[1:])
                ):
                    raise DomainError("INVALID_CURSOR", 422)
                highwater, timestamp, event_id = position
                query = query.where(
                    or_(
                        t.events.c.event_time > timestamp,
                        and_(t.events.c.event_time == timestamp, t.events.c.event_id > event_id),
                    )
                )
            else:
                highwater = (
                    conn.execute(
                        select(func.max(t.members.c.publication)).where(
                            t.members.c.workspace_id == actor.workspace_id,
                            t.members.c.session_id == session,
                        )
                    ).scalar_one()
                    or 0
                )
            # Follow the existing ordered event index, checking membership for
            # each candidate. A join made SQLite scan/sort the whole session
            # (including payloads) before returning even a five-event page.
            query = query.where(
                select(t.members.c.event_id)
                .where(
                    t.members.c.workspace_id == t.events.c.workspace_id,
                    t.members.c.event_id == t.events.c.event_id,
                    t.members.c.session_id == session,
                    t.members.c.publication <= highwater,
                )
                .exists()
            )
            rows = (
                conn.execute(
                    query.order_by(t.events.c.event_time, t.events.c.event_id).limit(limit + 1)
                )
                .mappings()
                .all()
            )
        next_cursor = None
        if len(rows) > limit:
            last = rows[limit - 1]
            next_cursor = encode(actor, binding, [highwater, last["event_time"], last["event_id"]])
        items = rows[:limit]
        result = {"items": [r["payload"] for r in items], "next_cursor": next_cursor}
        if any(row["event_type"] == "network.packet" for row in items):
            result["packet_evidence_scope"] = encode(
                actor, ["packet.evidence"], [dataset, session, highwater]
            )
        return result

    def get_event(self, actor: Actor, event_id: str) -> dict:
        with self.db.engine.connect() as conn:
            row = conn.execute(
                select(t.events.c.payload).where(
                    t.events.c.workspace_id == actor.workspace_id,
                    t.events.c.event_id == event_id,
                    or_(
                        t.events.c.event_type != "network.packet",
                        select(t.members.c.event_id)
                        .where(
                            t.members.c.workspace_id == t.events.c.workspace_id,
                            t.members.c.event_id == t.events.c.event_id,
                        )
                        .exists(),
                    ),
                )
            ).first()
        if row is None:
            raise DomainError("NOT_FOUND", 404)
        return row[0]

    def verify_evidence(self, actor: Actor, event_id: str) -> None:
        event = self.get_event(actor, event_id)
        with self.db.engine.connect() as conn:
            for locator in event["source_locators"]:
                obj = self._get(conn, t.objects, actor, locator["object_id"])
                path = self.settings.raw_store / obj["storage_key"]
                if file_digest(path) != locator["raw_sha256"]:
                    raise DomainError("ARCHIVE_INTEGRITY_FAILED", 409)

    def overview(self, actor: Actor, dataset: str, session: str) -> dict:
        from packages.detection.fragmentation import PACKET_SCOPE_LIMIT

        with self.db.engine.connect() as conn:
            self._get(conn, t.datasets, actor, dataset)
            scope = self._get(conn, t.sessions, actor, session)
            if scope["dataset_id"] != dataset:
                raise DomainError("NOT_FOUND", 404)
            total, packets = conn.execute(
                select(
                    func.count(),
                    func.count().filter(t.events.c.event_type == "network.packet"),
                )
                .select_from(t.members)
                .join(
                    t.events,
                    and_(
                        t.events.c.workspace_id == t.members.c.workspace_id,
                        t.events.c.event_id == t.members.c.event_id,
                    ),
                )
                .where(
                    t.members.c.workspace_id == actor.workspace_id,
                    t.members.c.session_id == session,
                )
            ).one()
            replay = None
            if scope["mode"] == "replay":
                from packages.storage.replay import response

                row = (
                    conn.execute(
                        select(t.jobs).where(
                            t.jobs.c.workspace_id == actor.workspace_id,
                            t.jobs.c.kind == "replay",
                            t.jobs.c.payload["session_id"].as_string() == session,
                        )
                    )
                    .mappings()
                    .first()
                )
                if row:
                    replay = response(row)
            incomplete = conn.execute(
                select(t.batches.c.error_code)
                .where(
                    t.batches.c.workspace_id == actor.workspace_id,
                    t.batches.c.dataset_id == dataset,
                    t.batches.c.session_id == session,
                    t.batches.c.status == "partial",
                    t.batches.c.error_code.in_(["RULE_SCOPE_TOO_LARGE", "RULE_RESOURCE_LIMIT"]),
                )
                .limit(1)
            ).first()
        exceeded = (
            total - packets > self.settings.detection_event_limit
            or packets > PACKET_SCOPE_LIMIT
            or incomplete is not None
        )
        return {
            "event_count": total,
            "input_mode": scope["mode"],
            "model_mode": "disabled",
            "detection_status": replay["detection_status"]
            if replay
            else "partial"
            if exceeded
            else "complete",
            "warnings": replay["warnings"]
            if replay
            else [incomplete[0] if incomplete else "RULE_SCOPE_TOO_LARGE"]
            if exceeded
            else [],
        }
