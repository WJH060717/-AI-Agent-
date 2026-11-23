"""Durable queue with lease epochs; all mutations use row locks and fencing."""

import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import and_, or_, select

from packages.config import Settings
from packages.storage import schema_v3 as t
from packages.storage.database import Database
from packages.storage.service import Actor, DomainError


def stamp(at: datetime | None = None) -> str:
    return (at or datetime.now(UTC)).astimezone(UTC).isoformat(timespec="microseconds")


class LeaseLost(RuntimeError):
    pass


@dataclass(frozen=True)
class Lease:
    job_id: str
    workspace_id: str
    worker_id: str
    version: int
    attempt: int
    kind: str
    batch_id: str | None
    payload: dict


class Queue:
    def __init__(self, db: Database, settings: Settings):
        self.db, self.settings = db, settings

    def claim(self, worker_id: str, *, at: datetime | None = None) -> Lease | None:
        moment = at or datetime.now(UTC)
        with self.db.engine.begin() as conn:
            due = or_(
                and_(t.jobs.c.state == "queued", t.jobs.c.available_at <= stamp(moment)),
                and_(
                    t.jobs.c.state == "running",
                    or_(t.jobs.c.lease_until.is_(None), t.jobs.c.lease_until <= stamp(moment)),
                ),
            )
            while True:
                row = (
                    conn.execute(
                        select(t.jobs)
                        .where(due)
                        .order_by(t.jobs.c.available_at, t.jobs.c.id)
                        .with_for_update(skip_locked=True)
                        .limit(1)
                    )
                    .mappings()
                    .first()
                )
                if row is None:
                    return None
                if row["attempt"] >= self.settings.worker_max_attempts:
                    conn.execute(
                        t.jobs.update()
                        .where(t.jobs.c.id == row["id"])
                        .values(
                            state="failed",
                            error_code="ATTEMPTS_EXHAUSTED",
                            lease_until=None,
                            version=row["version"] + 1,
                        )
                    )
                    self._related(conn, row, "failed", "ATTEMPTS_EXHAUSTED")
                    continue
                version = row["version"] + 1
                updated = conn.execute(
                    t.jobs.update()
                    .where(t.jobs.c.id == row["id"], t.jobs.c.version == row["version"])
                    .values(
                        state="running",
                        worker_id=worker_id,
                        version=version,
                        attempt=row["attempt"] + 1,
                        error_code=None,
                        lease_until=stamp(
                            moment + timedelta(seconds=self.settings.worker_lease_seconds)
                        ),
                    )
                )
                if updated.rowcount != 1:
                    return None
                self._related(conn, row, "running", None)
                return Lease(
                    row["id"],
                    row["workspace_id"],
                    worker_id,
                    version,
                    row["attempt"] + 1,
                    row["kind"],
                    row["batch_id"],
                    row["payload"] or {},
                )

    def guard(self, conn, lease: Lease, *, at: datetime | None = None):
        row = (
            conn.execute(select(t.jobs).where(t.jobs.c.id == lease.job_id).with_for_update())
            .mappings()
            .first()
        )
        if (
            row is None
            or row["workspace_id"] != lease.workspace_id
            or row["state"] != "running"
            or (
                row["version"] != lease.version
                or row["worker_id"] != lease.worker_id
                or row["lease_until"] is None
                or row["lease_until"] <= stamp(at)
            )
        ):
            raise LeaseLost("Job ownership or lease is no longer valid")
        return row

    def heartbeat(self, lease: Lease, *, at: datetime | None = None) -> None:
        moment = at or datetime.now(UTC)
        with self.db.engine.begin() as conn:
            self.guard(conn, lease, at=moment)
            conn.execute(
                t.jobs.update()
                .where(t.jobs.c.id == lease.job_id)
                .values(
                    lease_until=stamp(
                        moment + timedelta(seconds=self.settings.worker_lease_seconds)
                    )
                )
            )

    def finish(self, conn, lease: Lease, state: str) -> None:
        self.guard(conn, lease)
        conn.execute(
            t.jobs.update()
            .where(t.jobs.c.id == lease.job_id)
            .values(state=state, lease_until=None, worker_id=None, error_code=None)
        )

    def _related(self, conn, row, state: str, code: str | None):
        if row["kind"] == "import":
            conn.execute(
                t.batches.update()
                .where(
                    t.batches.c.workspace_id == row["workspace_id"],
                    t.batches.c.id == row["batch_id"],
                )
                .values(status=state, error_code=code)
            )
        elif row["kind"] == "investigation" and row["payload"]:
            conn.execute(
                t.runs.update()
                .where(
                    t.runs.c.workspace_id == row["workspace_id"],
                    t.runs.c.id == row["payload"]["run_id"],
                )
                .values(state=state)
            )
            if state in {"failed", "cancelled"}:
                from packages.agent.state import external_terminal

                external_terminal(conn, row["workspace_id"], row["payload"]["run_id"], state)

    def fail(
        self,
        lease: Lease,
        code: str,
        *,
        retryable: bool,
        at: datetime | None = None,
        capture_failure: dict | None = None,
    ) -> None:
        moment = at or datetime.now(UTC)
        with self.db.engine.begin() as conn:
            row = self.guard(conn, lease, at=moment)
            retry = retryable and row["attempt"] < self.settings.worker_max_attempts
            state = "queued" if retry else "failed"
            wait = 2 ** row["attempt"] + secrets.randbelow(1000) / 1000
            details = {}
            if capture_failure is not None:
                details["checkpoint"] = {
                    **(row["checkpoint"] or {}),
                    "capture_failure": capture_failure,
                }
            conn.execute(
                t.jobs.update()
                .where(t.jobs.c.id == lease.job_id)
                .values(
                    state=state,
                    error_code=code,
                    worker_id=None,
                    lease_until=None,
                    available_at=stamp(moment + timedelta(seconds=wait)),
                    **details,
                )
            )
            self._related(conn, row, state, code)

    def status(self, actor: Actor, job_id: str) -> dict:
        with self.db.engine.connect() as conn:
            row = (
                conn.execute(
                    select(t.jobs).where(
                        t.jobs.c.workspace_id == actor.workspace_id, t.jobs.c.id == job_id
                    )
                )
                .mappings()
                .first()
            )
        if row is None:
            raise DomainError("NOT_FOUND", 404)
        return {
            k: row[k]
            for k in (
                "id",
                "kind",
                "state",
                "attempt",
                "version",
                "cursor_line",
                "available_at",
                "lease_until",
                "error_code",
            )
        }

    def cancel(self, actor: Actor, job_id: str) -> None:
        if actor.role not in ("admin", "analyst"):
            raise DomainError("FORBIDDEN", 403)
        with self.db.engine.begin() as conn:
            row = (
                conn.execute(
                    select(t.jobs)
                    .where(t.jobs.c.workspace_id == actor.workspace_id, t.jobs.c.id == job_id)
                    .with_for_update()
                )
                .mappings()
                .first()
            )
            if row is None:
                raise DomainError("NOT_FOUND", 404)
            if actor.role != "admin":
                target = (
                    row["batch_id"]
                    if row["kind"] == "import"
                    else (row["payload"] or {}).get("session_id")
                    if row["kind"] == "replay"
                    else (row["payload"] or {}).get("run_id")
                )
                owner = conn.execute(
                    select(t.audit.c.id).where(
                        t.audit.c.workspace_id == actor.workspace_id,
                        t.audit.c.actor == actor.digest,
                        t.audit.c.object_id == target,
                        t.audit.c.action.in_(
                            ["import.stage", "investigation.create", "replay.create"]
                        ),
                    )
                ).first()
                if owner is None:
                    raise DomainError("FORBIDDEN", 403)
            if row["state"] == "cancelled":
                return
            if row["state"] not in ("queued", "running"):
                raise DomainError("JOB_ALREADY_TERMINAL", 409)
            conn.execute(
                t.jobs.update()
                .where(t.jobs.c.id == job_id)
                .values(
                    state="cancelled",
                    cancel_requested=1,
                    version=row["version"] + 1,
                    worker_id=None,
                    lease_until=None,
                )
            )
            self._related(conn, row, "cancelled", "CANCELLED")
