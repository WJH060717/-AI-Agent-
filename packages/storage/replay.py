"""Fixed-watermark visibility replay of existing events, with fenced resumable progress."""

from collections.abc import Callable
from copy import deepcopy
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import and_, func, or_, select

from packages.contracts.replay import ReplayCreate, ReplayStatus
from packages.storage import schema_v6 as t
from packages.storage.queue import Lease, Queue
from packages.storage.service import Actor, DataService, DomainError, digest, now


def response(row: dict) -> dict:
    payload = row["payload"]
    warnings = list(payload["warnings"])
    detection = payload["detection_status"]
    if row["state"] in {"cancelled", "failed"}:
        detection = "partial"
        warnings.append("REPLAY_" + row["state"].upper())
    elif detection == "pending":
        warnings.append("REPLAY_DETECTION_PENDING")
    return ReplayStatus(
        job_id=row["id"],
        state=row["state"],
        detection_status=detection,
        warnings=warnings,
        **{
            key: payload[key]
            for key in (
                "dataset_id",
                "session_id",
                "source_session_id",
                "source_high_water",
                "total_events",
                "published_events",
                "rate_eps",
            )
        },
    ).model_dump(mode="json")


class ReplayService:
    def __init__(self, service: DataService):
        self.service = service

    def create(self, actor: Actor, dataset: str, request: ReplayCreate, key: str) -> dict:
        self.service.require(actor, ("admin", "analyst"))
        route = f"datasets/{dataset}/replays"
        request_hash = digest(request.model_dump_json().encode())
        with self.service.db.engine.begin() as conn:
            # Serializes simultaneous create/idempotency requests on PostgreSQL as well.
            row = conn.execute(
                select(t.datasets.c.id)
                .where(
                    t.datasets.c.workspace_id == actor.workspace_id,
                    t.datasets.c.id == dataset,
                )
                .with_for_update()
            ).first()
            if row is None:
                raise DomainError("NOT_FOUND", 404)
            previous = self.service._idem(conn, actor, route, key, request_hash)
            if previous:
                return previous
            source = self.service._get(conn, t.sessions, actor, str(request.source_session_id))
            if source["dataset_id"] != dataset:
                raise DomainError("NOT_FOUND", 404)
            if source["mode"] != "import":
                raise DomainError("REPLAY_SOURCE_MODE", 422)
            # Source publication is append-only; both watermark and count come from one query.
            total, water = conn.execute(
                select(func.count(), func.max(t.members.c.publication)).where(
                    t.members.c.workspace_id == actor.workspace_id,
                    t.members.c.session_id == source["id"],
                )
            ).one()
            if total == 0:
                raise DomainError("REPLAY_SOURCE_EMPTY", 422)
            if total > self.service.settings.replay_event_limit:
                raise DomainError("REPLAY_SCOPE_TOO_LARGE", 422)
            session, job = str(uuid4()), str(uuid4())
            payload = {
                "version": "replay@1.0.0",
                "dataset_id": dataset,
                "session_id": session,
                "source_session_id": source["id"],
                "source_high_water": water,
                "total_events": total,
                "published_events": 0,
                "rate_eps": request.rate_eps,
                "batch_size": self.service.settings.replay_batch_size,
                "started_at": None,
                "position": None,
                "publication": 0,
                "detection_status": "pending",
                "warnings": [],
            }
            conn.execute(
                t.sessions.insert().values(
                    workspace_id=actor.workspace_id, id=session, dataset_id=dataset, mode="replay"
                )
            )
            conn.execute(
                t.jobs.insert().values(
                    id=job,
                    workspace_id=actor.workspace_id,
                    kind="replay",
                    state="queued",
                    payload=payload,
                    available_at=now(),
                )
            )
            result = response({"id": job, "state": "queued", "payload": payload})
            self.service._audit(conn, actor, "replay.create", session)
            self.service._remember(conn, actor, route, key, request_hash, result)
            return result

    def status(self, actor: Actor, job: str) -> dict:
        with self.service.db.engine.connect() as conn:
            row = self.service._get(conn, t.jobs, actor, job)
            if row["kind"] != "replay":
                raise DomainError("NOT_FOUND", 404)
            return response(row)


class ReplayRunner:
    def __init__(
        self, service: DataService, queue: Queue, *, clock: Callable[[], datetime] | None = None
    ):
        self.service, self.queue = service, queue
        self.clock = clock or (lambda: datetime.now(UTC))

    def step(self, lease: Lease) -> float | None:
        with self.service.db.engine.begin() as conn:
            row = self.queue.guard(conn, lease)
            if row["kind"] != "replay":
                raise DomainError("REPLAY_JOB_REQUIRED", 422)
            payload = deepcopy(row["payload"])
            moment = self.clock()
            if payload["started_at"] is None:
                payload["started_at"] = moment.isoformat()
            elapsed = max(
                0.0, (moment - datetime.fromisoformat(payload["started_at"])).total_seconds()
            )
            due = (
                min(payload["total_events"], int(elapsed * payload["rate_eps"]))
                - payload["published_events"]
            )
            if due <= 0:
                conn.execute(
                    t.jobs.update().where(t.jobs.c.id == lease.job_id).values(payload=payload)
                )
                return min(0.1, 1 / payload["rate_eps"])
            query = select(t.events.c.event_id, t.events.c.event_time).where(
                t.events.c.workspace_id == lease.workspace_id,
                t.events.c.dataset_id == payload["dataset_id"],
                select(t.members.c.event_id)
                .where(
                    t.members.c.workspace_id == lease.workspace_id,
                    t.members.c.session_id == payload["source_session_id"],
                    t.members.c.publication <= payload["source_high_water"],
                    t.members.c.event_id == t.events.c.event_id,
                )
                .exists(),
            )
            position = payload["position"]
            if position:
                query = query.where(
                    or_(
                        t.events.c.event_time > position[0],
                        and_(
                            t.events.c.event_time == position[0], t.events.c.event_id > position[1]
                        ),
                    )
                )
            rows = conn.execute(
                query.order_by(t.events.c.event_time, t.events.c.event_id).limit(
                    min(due, payload["batch_size"])
                )
            ).all()
            if not rows:
                raise DomainError("REPLAY_SOURCE_CHANGED", 409)
            payload["publication"] += 1
            conn.execute(
                t.members.insert(),
                [
                    dict(
                        workspace_id=lease.workspace_id,
                        session_id=payload["session_id"],
                        event_id=r.event_id,
                        publication=payload["publication"],
                    )
                    for r in rows
                ],
            )
            payload["published_events"] += len(rows)
            payload["position"] = [rows[-1].event_time, rows[-1].event_id]
            complete = payload["published_events"] == payload["total_events"]
            if complete:
                from packages.storage.analysis import AnalysisService

                actor = self.service.system_actor(lease.workspace_id)
                try:
                    AnalysisService(self.service).detect(
                        conn, actor, payload["dataset_id"], payload["session_id"]
                    )
                    payload["detection_status"] = "complete"
                except DomainError as exc:
                    if exc.code not in {"RULE_SCOPE_TOO_LARGE", "RULE_RESOURCE_LIMIT"}:
                        raise
                    payload["detection_status"] = "partial"
                    payload["warnings"] = [exc.code]
                payload["finished_at"] = self.clock().isoformat()
            # No visibility or cursor survives a failed lease check/transaction.
            self.queue.guard(conn, lease)
            conn.execute(
                t.jobs.update()
                .where(t.jobs.c.id == lease.job_id)
                .values(payload=payload, cursor_line=payload["published_events"])
            )
            if complete:
                self.queue.finish(
                    conn,
                    lease,
                    "completed" if payload["detection_status"] == "complete" else "partial",
                )
                self.service._audit(conn, actor, "replay.complete", payload["session_id"])
                return None
            return 0.0
