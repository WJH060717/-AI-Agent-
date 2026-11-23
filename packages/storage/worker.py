"""Continuous bounded worker and resumable import steps."""

import json
import logging
import os
import threading
import time
from collections import Counter
from io import BytesIO
from pathlib import Path
from typing import BinaryIO
from uuid import uuid4

from sqlalchemy import func, literal, select
from sqlalchemy.exc import OperationalError

from packages.ingest.parsers import ParseContext, parse_record
from packages.ingest.pcap_packet import (
    MAX_CAPTURE_BYTES,
    PARSER_VERSION,
    InvalidFrame,
    PcapReadError,
    UnsupportedFrame,
    capture_header,
    packet_event,
    record_at_cursor,
)
from packages.storage import schema_v4 as t
from packages.storage.queue import Lease, LeaseLost, Queue
from packages.storage.service import DataService, DomainError, digest, file_digest, now

logger = logging.getLogger(__name__)


def read_packet_chunk(
    stream: BinaryIO, context: ParseContext, byte_size: int, checkpoint: dict, limit: int
) -> tuple[list, int, int, bool, dict, dict]:
    header = capture_header(stream, byte_size)
    number = checkpoint["cursor_line"]
    offset = checkpoint["cursor_byte"]
    previous = (checkpoint["checkpoint"] or {}).get("pcap", {})
    if offset and previous.get("version") != PARSER_VERSION:
        raise PcapReadError("PCAP_PARSER_VERSION_MISMATCH", offset, number + 1)
    if offset and not 24 <= offset <= byte_size:
        raise PcapReadError("PCAP_INVALID_CHECKPOINT", offset, number + 1)
    if number == 0 and byte_size == 24:
        raise PcapReadError("PCAP_EMPTY_CAPTURE", 24)
    if offset:
        stream.seek(offset)
    issues = Counter(previous.get("issues", {}))
    quality = Counter(previous.get("quality", {}))
    rejected = {}
    records = []
    for _ in range(limit):
        if stream.tell() == byte_size:
            break
        number += 1
        record = record_at_cursor(stream, header, byte_size, number)
        try:
            event = packet_event(record, context)
        except UnsupportedFrame as exc:
            issues[str(exc)] += 1
            continue
        except InvalidFrame as exc:
            event = None
            rejected[number] = str(exc)
            issues[str(exc)] += 1
        else:
            quality.update(event.quality_flags)
        records.append((number, event, 1))
    end = stream.tell()
    state = {"version": PARSER_VERSION, "issues": dict(issues), "quality": dict(quality)}
    return records, number, end, end == byte_size, {"pcap": state}, rejected


def verified_capture(path: Path, size: int, expected_sha256: str, error_code: str) -> bytes:
    if not 0 < size <= MAX_CAPTURE_BYTES:
        raise DomainError(error_code, 409)
    with path.open("rb") as stream:
        data = stream.read(size + 1)
    if len(data) != size or digest(data) != expected_sha256:
        raise DomainError(error_code, 409)
    return data


class ImportRunner:
    def __init__(self, service: DataService, queue: Queue):
        self.service, self.queue = service, queue

    def seal(self, lease: Lease) -> dict:
        actor = self.service.system_actor(lease.workspace_id)
        with self.service.db.engine.begin() as conn:
            self.queue.guard(conn, lease)
            batch = dict(self.service._get(conn, t.batches, actor, lease.batch_id))
            if batch["object_id"]:
                return dict(self.service._get(conn, t.objects, actor, batch["object_id"]))
        staged = self.service.settings.staging_store / batch["staging_key"]
        capture = None
        if batch["source_type"] == "pcap_packet":
            capture = verified_capture(
                staged, batch["byte_size"], batch["sha256"], "STAGING_INTEGRITY_FAILED"
            )
        elif file_digest(staged) != batch["sha256"]:
            raise DomainError("STAGING_INTEGRITY_FAILED", 409)
        with self.service.db.engine.connect() as conn:
            existing = (
                conn.execute(
                    select(t.objects).where(
                        t.objects.c.workspace_id == lease.workspace_id,
                        t.objects.c.sha256 == batch["sha256"],
                        t.objects.c.sensor_id == batch["sensor_id"],
                    )
                )
                .mappings()
                .first()
            )
        if existing:
            obj = dict(existing)
        else:
            object_id = str(uuid4())
            extension = "pcap" if batch["source_type"] == "pcap_packet" else "jsonl"
            key = f"{lease.workspace_id}/{object_id}.{extension}"
            path = self.service.settings.raw_store / key
            path.parent.mkdir(parents=True, exist_ok=True)
            temporary = path.with_suffix(".partial")
            with (
                BytesIO(capture) if capture is not None else staged.open("rb") as source,
                temporary.open("xb") as target,
            ):
                while chunk := source.read(65536):
                    target.write(chunk)
                target.flush()
                os.fsync(target.fileno())
            if capture is not None:
                verified_capture(
                    temporary, batch["byte_size"], batch["sha256"], "ARCHIVE_INTEGRITY_FAILED"
                )
            elif file_digest(temporary) != batch["sha256"]:
                raise DomainError("ARCHIVE_INTEGRITY_FAILED", 409)
            temporary.rename(path)
            obj = {
                "id": object_id,
                "workspace_id": lease.workspace_id,
                "sha256": batch["sha256"],
                "sensor_id": batch["sensor_id"],
                "storage_key": key,
                "byte_size": batch["byte_size"],
                "sealed_at": now(),
            }
        with self.service.db.engine.begin() as conn:
            self.queue.guard(conn, lease)
            conn.execute(
                select(t.workspaces)
                .where(t.workspaces.c.id == lease.workspace_id)
                .with_for_update()
            ).first()
            winner = (
                conn.execute(
                    select(t.objects).where(
                        t.objects.c.workspace_id == lease.workspace_id,
                        t.objects.c.sha256 == batch["sha256"],
                        t.objects.c.sensor_id == batch["sensor_id"],
                    )
                )
                .mappings()
                .first()
            )
            if winner:
                obj = dict(winner)
            else:
                conn.execute(t.objects.insert().values(**obj))
            conn.execute(
                t.batches.update()
                .where(
                    t.batches.c.workspace_id == lease.workspace_id, t.batches.c.id == lease.batch_id
                )
                .values(object_id=obj["id"])
            )
        return obj

    def step(self, lease: Lease) -> bool:
        obj = self.seal(lease)
        actor = self.service.system_actor(lease.workspace_id)
        with self.service.db.engine.begin() as conn:
            checkpoint = dict(self.queue.guard(conn, lease))
            batch = dict(self.service._get(conn, t.batches, actor, lease.batch_id))
            from packages.storage.context import ContextService

            metadata, salt = ContextService(self.service).parser_metadata(
                conn, actor, batch["dataset_id"], batch["source_type"], batch["sensor_id"]
            )
        path = self.service.settings.raw_store / obj["storage_key"]
        capture = None
        if batch["source_type"] == "pcap_packet":
            path = self.service.archive_path(obj["storage_key"])
            capture = verified_capture(
                path, obj["byte_size"], obj["sha256"], "ARCHIVE_INTEGRITY_FAILED"
            )
        elif file_digest(path) != obj["sha256"]:
            raise DomainError("ARCHIVE_INTEGRITY_FAILED", 409)
        context = ParseContext(
            lease.workspace_id,
            batch["dataset_id"],
            obj["id"],
            obj["sha256"],
            batch["sensor_id"],
            batch["source_type"],
            batch["timezone"],
            metadata=metadata,
            identity_salt=salt,
        )
        records, audit_rows = [], []
        pcap_state, rejected = {}, {}
        with BytesIO(capture) if capture is not None else path.open("rb") as source:
            if capture is not None:
                records, line_number, offset, complete, pcap_state, rejected = read_packet_chunk(
                    source,
                    context,
                    obj["byte_size"],
                    checkpoint,
                    self.service.settings.import_chunk_lines,
                )
            else:
                source.seek(checkpoint["cursor_byte"])
                line_number = checkpoint["cursor_line"]
                for _ in range(self.service.settings.import_chunk_lines):
                    before = source.tell()
                    line = source.readline()
                    if not line:
                        break
                    line_number += 1
                    if context.source_type == "linux_audit":
                        audit_rows.append((line_number, line, before))
                        continue
                    try:
                        event = parse_record(line, line_number, context)
                    except (ValueError, KeyError, TypeError, OverflowError, UnicodeError):
                        event = None
                    records.append((line_number, event, 1))
                offset = source.tell()
                complete = not source.read(1)
        pending = (checkpoint["checkpoint"] or {}).get("audit_pending", {})
        if context.source_type == "linux_audit":
            from packages.ingest.audit_stream import consume

            records, pending = consume(audit_rows, pending, context, path, eof=complete)
        has_partial = (checkpoint["checkpoint"] or {}).get("has_partial_audit", False) or any(
            event is not None and "partial_audit" in event.quality_flags for _, event, _ in records
        )
        with self.service.db.engine.begin() as conn:
            self.queue.guard(conn, lease)
            conn.execute(
                select(t.workspaces)
                .where(t.workspaces.c.id == lease.workspace_id)
                .with_for_update()
            ).first()
            batch = dict(self.service._get(conn, t.batches, actor, lease.batch_id))
            counts = {
                key: batch[key]
                for key in ("accepted", "duplicate", "quarantined", "aggregated_records")
            }
            for number, event, consumed in records:
                if event is None:
                    conn.execute(
                        t.quarantine.insert().values(
                            id=str(uuid4()),
                            workspace_id=lease.workspace_id,
                            batch_id=lease.batch_id,
                            object_id=obj["id"],
                            line=number,
                            error_code=rejected.get(number, "INVALID_OR_UNSUPPORTED_RECORD"),
                        )
                    )
                    counts["quarantined"] += 1
                    continue
                payload = event.model_dump(mode="json")
                exists = conn.execute(
                    select(t.events.c.payload).where(
                        t.events.c.workspace_id == lease.workspace_id,
                        t.events.c.event_id == event.event_id,
                    )
                ).first()
                if exists and context.source_type == "linux_audit":
                    transient = {"ingested_at", "source_locators"}
                    previous = {k: v for k, v in exists[0].items() if k not in transient}
                    current = {k: v for k, v in payload.items() if k not in transient}
                    if previous != current:
                        for ref in event.source_locators:
                            for line in range(ref.record_start, ref.record_end + 1):
                                conn.execute(
                                    t.quarantine.insert().values(
                                        id=str(uuid4()),
                                        workspace_id=lease.workspace_id,
                                        batch_id=lease.batch_id,
                                        object_id=str(ref.object_id),
                                        line=line,
                                        error_code="NATIVE_ID_CONTENT_CONFLICT",
                                    )
                                )
                        counts["quarantined"] += consumed
                        continue
                counts["aggregated_records"] += consumed
                if exists:
                    counts["duplicate"] += 1
                else:
                    conn.execute(
                        t.events.insert().values(
                            workspace_id=lease.workspace_id,
                            dataset_id=batch["dataset_id"],
                            event_id=event.event_id,
                            event_time=event.event_time.isoformat(timespec="microseconds"),
                            event_type=event.event_type,
                            payload=payload,
                        )
                    )
                    counts["accepted"] += 1
                already_member = conn.execute(
                    select(t.batch_events.c.event_id).where(
                        t.batch_events.c.workspace_id == lease.workspace_id,
                        t.batch_events.c.batch_id == lease.batch_id,
                        t.batch_events.c.event_id == event.event_id,
                    )
                ).first()
                if already_member:
                    continue
                conn.execute(
                    t.batch_events.insert().values(
                        workspace_id=lease.workspace_id,
                        batch_id=lease.batch_id,
                        event_id=event.event_id,
                    )
                )
            self.queue.guard(conn, lease)
            conn.execute(
                t.jobs.update()
                .where(t.jobs.c.id == lease.job_id)
                .values(
                    cursor_line=line_number,
                    cursor_byte=offset,
                    checkpoint=pcap_state
                    or {
                        "audit_pending": pending,
                        "has_partial_audit": has_partial,
                    },
                )
            )
            conn.execute(
                t.batches.update()
                .where(
                    t.batches.c.workspace_id == lease.workspace_id, t.batches.c.id == lease.batch_id
                )
                .values(**counts, raw_records=line_number)
            )
            if complete:
                publication = (
                    conn.execute(
                        select(func.max(t.members.c.publication)).where(
                            t.members.c.workspace_id == lease.workspace_id,
                            t.members.c.session_id == batch["session_id"],
                        )
                    ).scalar_one()
                    or 0
                ) + 1
                # Publish the complete batch atomically without per-event SQL round trips.
                existing = (
                    select(t.members.c.event_id)
                    .where(
                        t.members.c.workspace_id == lease.workspace_id,
                        t.members.c.session_id == batch["session_id"],
                        t.members.c.event_id == t.batch_events.c.event_id,
                    )
                    .correlate(t.batch_events)
                    .exists()
                )
                conn.execute(
                    t.members.insert().from_select(
                        ["workspace_id", "session_id", "event_id", "publication"],
                        select(
                            literal(lease.workspace_id),
                            literal(batch["session_id"]),
                            t.batch_events.c.event_id,
                            literal(publication),
                        ).where(
                            t.batch_events.c.workspace_id == lease.workspace_id,
                            t.batch_events.c.batch_id == lease.batch_id,
                            ~existing,
                        ),
                    )
                )
                state = "partial" if counts["quarantined"] or has_partial else "succeeded"
                from packages.storage.analysis import AnalysisService

                detection_error = None
                try:
                    AnalysisService(self.service).detect(
                        conn, actor, batch["dataset_id"], batch["session_id"]
                    )
                except DomainError as exc:
                    if exc.code not in {"RULE_SCOPE_TOO_LARGE", "RULE_RESOURCE_LIMIT"}:
                        raise
                    state, detection_error = "partial", exc.code
                conn.execute(
                    t.batches.update()
                    .where(
                        t.batches.c.workspace_id == lease.workspace_id,
                        t.batches.c.id == lease.batch_id,
                    )
                    .values(status=state, error_code=detection_error)
                )
                self.queue.finish(conn, lease, state)
                self.service._audit(conn, actor, "import.complete", lease.batch_id)
        if complete:
            try:
                (self.service.settings.staging_store / batch["staging_key"]).unlink(missing_ok=True)
            except OSError:
                logger.warning("staging_cleanup_deferred job_id=%s", lease.job_id)
        return complete


class Worker:
    def __init__(self, service: DataService, queue: Queue, worker_id: str | None = None):
        self.service, self.queue = service, queue
        self.worker_id = worker_id or str(uuid4())
        self.stop = threading.Event()

    def _heartbeats(self, lease: Lease, done: threading.Event) -> None:
        while not done.wait(self.service.settings.worker_heartbeat_seconds):
            try:
                self.queue.heartbeat(lease)
            except (LeaseLost, OperationalError):
                return

    def run_one(self, *, raise_errors: bool = False) -> bool:
        lease = self.queue.claim(self.worker_id)
        if lease is None:
            return False
        started = time.monotonic()
        logger.info(
            json.dumps(
                {
                    "timestamp": now(),
                    "level": "info",
                    "service": "worker",
                    "job_id": lease.job_id,
                    "action": "claimed",
                    "worker_id": self.worker_id,
                    "attempt": lease.attempt,
                    "version": lease.version,
                }
            )
        )
        done = threading.Event()
        thread = threading.Thread(target=self._heartbeats, args=(lease, done), daemon=True)
        thread.start()
        try:
            if lease.kind == "import":
                runner = ImportRunner(self.service, self.queue)
                while not runner.step(lease):
                    pass
            elif lease.kind == "replay":
                from packages.storage.replay import ReplayRunner

                runner = ReplayRunner(self.service, self.queue)
                while (delay := runner.step(lease)) is not None:
                    if self.stop.wait(delay):
                        return True
            elif lease.kind == "investigation":
                from packages.storage.analysis import AnalysisService

                AnalysisService(self.service).process(lease, self.queue)
            else:
                raise DomainError("UNKNOWN_JOB_KIND", 422)
        except LeaseLost:
            pass
        except Exception as exc:
            try:
                self.queue.fail(
                    lease,
                    exc.code if isinstance(exc, (DomainError, PcapReadError)) else "WORKER_ERROR",
                    retryable=isinstance(exc, (OSError, OperationalError)),
                    capture_failure=(
                        {"byte_offset": exc.offset, "record": exc.record}
                        if isinstance(exc, PcapReadError)
                        else None
                    ),
                )
            except LeaseLost:
                pass
            logger.warning(
                json.dumps(
                    {
                        "job_id": lease.job_id,
                        "action": "job_error",
                        "error_code": type(exc).__name__,
                    }
                )
            )
            if raise_errors:
                raise
        finally:
            done.set()
            thread.join(timeout=2)
            logger.info(
                json.dumps(
                    {
                        "timestamp": now(),
                        "level": "info",
                        "service": "worker",
                        "job_id": lease.job_id,
                        "action": "attempt_ended",
                        "duration_ms": round((time.monotonic() - started) * 1000),
                    }
                )
            )
        return True

    def run(self, max_jobs: int | None = None) -> None:
        processed = 0
        while not self.stop.is_set():
            try:
                available = self.run_one()
            except OperationalError:
                available = False
                logger.warning("queue_database_unavailable")
            if available:
                processed += 1
                if max_jobs is not None and processed >= max_jobs:
                    return
            else:
                self.stop.wait(self.service.settings.worker_poll_seconds)
