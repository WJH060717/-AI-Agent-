"""Snapshot-bound deterministic investigations; no model invocation or response action."""

import hmac
import json
from datetime import UTC, datetime, timedelta
from io import BytesIO
from uuid import UUID, uuid4, uuid5

from pydantic import ValidationError
from sqlalchemy import and_, func, select

from packages.contracts.models import (
    AgentBudget,
    Claim,
    EvidenceRef,
    FactPredicate,
    InvestigationScope,
    NormalizedEvent,
    Report,
    SourceLocator,
    stable_event_id,
)
from packages.detection.common import DOS_DDOS_FAMILY
from packages.detection.fragmentation import FRAGMENT_RULES, PACKET_SCOPE_LIMIT
from packages.detection.gre_bursts import GRE_BURST_RULE
from packages.detection.http_packets import HTTP_PACKET_RULES
from packages.detection.limits import DetectionBudget, DetectionLimit, checkpoint
from packages.detection.os_fingerprint import OS_FINGERPRINT_RULE
from packages.detection.packet_bursts import BURST_RULES
from packages.detection.packet_conflicts import ARP_CONFLICT_RULE, DNS_DIFFERENCE_RULE
from packages.detection.packet_recon import HOST_DISCOVERY_RULE, PING_SWEEP_RULE, PORT_SCAN_RULE
from packages.detection.registry import detect_all, reproduce
from packages.graph.paths import analyze_paths
from packages.graph.service import evidence_graph
from packages.storage import schema_v5 as t
from packages.storage.queue import Lease, Queue
from packages.storage.service import Actor, DataService, DomainError, digest, file_digest, now

PACKET_RULE_IDS = (
    FRAGMENT_RULES.keys()
    | BURST_RULES.keys()
    | HTTP_PACKET_RULES.keys()
    | {PORT_SCAN_RULE, PING_SWEEP_RULE, HOST_DISCOVERY_RULE, GRE_BURST_RULE}
    | {ARP_CONFLICT_RULE, DNS_DIFFERENCE_RULE, OS_FINGERPRINT_RULE}
)


class AnalysisService:
    def __init__(self, service: DataService):
        self.service, self.db = service, service.db

    def detect(self, conn, actor: Actor, dataset_id: str, session_id: str) -> None:
        settings = self.service.settings
        try:
            with (
                conn.begin_nested(),
                DetectionBudget(
                    work_limit=settings.detection_work_limit,
                    seconds=min(
                        settings.detection_timeout_seconds, settings.worker_lease_seconds / 3
                    ),
                    byte_limit=settings.detection_byte_limit,
                    finding_limit=settings.detection_finding_limit,
                    reference_limit=settings.detection_reference_limit,
                ),
            ):
                self._detect(conn, actor, dataset_id, session_id)
                checkpoint()
        except DetectionLimit as exc:
            raise DomainError("RULE_RESOURCE_LIMIT", 422) from exc

    def _detect(self, conn, actor: Actor, dataset_id: str, session_id: str) -> None:
        source = (
            select(t.events.c.payload)
            .join(
                t.members,
                and_(
                    t.members.c.workspace_id == t.events.c.workspace_id,
                    t.members.c.event_id == t.events.c.event_id,
                ),
            )
            .where(
                t.events.c.workspace_id == actor.workspace_id,
                t.events.c.dataset_id == dataset_id,
                t.members.c.session_id == session_id,
            )
        )
        packet_event = t.events.c.event_type == "network.packet"
        events = []
        for subset, limit in (
            (~packet_event, self.service.settings.detection_event_limit),
            (packet_event, PACKET_SCOPE_LIMIT),
        ):
            selected = source.where(subset)
            if conn.execute(selected.with_only_columns(func.count())).scalar_one() > limit:
                raise DomainError("RULE_SCOPE_TOO_LARGE", 422)
            rows = conn.execute(
                selected.limit(limit + 1).execution_options(yield_per=500)
            ).scalars()
            start = len(events)
            try:
                for row in rows:
                    checkpoint(size=len(json.dumps(row, ensure_ascii=False).encode()))
                    events.append(NormalizedEvent.model_validate(row))
            finally:
                rows.close()
            if len(events) - start > limit:
                raise DomainError("RULE_SCOPE_TOO_LARGE", 422)
        from packages.contracts.context import DatasetContext

        context_row = self.service._optional(conn, t.contexts, actor, dataset_id)
        baselines = (
            DatasetContext.model_validate(context_row["payload"]).egress_baselines
            if context_row
            else []
        )
        findings = detect_all(events, session_id, baselines)
        for finding in findings:
            checkpoint()
            exists = conn.execute(
                select(t.findings.c.id).where(
                    t.findings.c.workspace_id == actor.workspace_id,
                    t.findings.c.id == finding["id"],
                )
            ).first()
            if exists:
                continue
            conn.execute(
                t.findings.insert().values(
                    workspace_id=actor.workspace_id,
                    id=finding["id"],
                    dataset_id=dataset_id,
                    session_id=session_id,
                    payload=finding,
                )
            )
        from packages.storage.incidents import CatalogService

        CatalogService(self.service).publish(
            conn,
            actor,
            dataset_id,
            session_id,
            findings,
            events,
        )

    def incident_page(
        self, actor: Actor, dataset: str, session: str, limit: int = 50, cursor: str | None = None
    ) -> dict:
        from packages.storage.incidents import CatalogService

        return CatalogService(self.service).page(actor, dataset, session, limit, cursor) | {
            "warnings": self.service.overview(actor, dataset, session)["warnings"]
        }

    def list_incidents(self, actor: Actor, dataset: str, session: str) -> list[dict]:
        page = self.incident_page(actor, dataset, session, 100)
        if page["next_cursor"]:
            raise DomainError("INCIDENT_LIST_LIMIT_EXCEEDED", 422)
        return page["items"]

    def _syn_reproduction_context(self, actor, snapshot, witness):
        if not witness or witness[0].dst is None:
            raise DomainError("FINDING_EVIDENCE_MISSING_FROM_SNAPSHOT", 409)
        event = witness[0]
        with self.db.engine.connect() as conn:
            rows = conn.execute(
                select(t.events.c.payload)
                .join(
                    t.members,
                    and_(
                        t.members.c.workspace_id == t.events.c.workspace_id,
                        t.members.c.event_id == t.events.c.event_id,
                    ),
                )
                .where(
                    t.events.c.workspace_id == actor.workspace_id,
                    t.events.c.dataset_id == str(event.dataset_id),
                    t.members.c.session_id == snapshot["scope"]["session_id"],
                    t.events.c.event_type == "network.packet",
                    t.events.c.payload["source_locators"][0]["object_id"].as_string()
                    == str(event.source_locators[0].object_id),
                    t.events.c.payload["dst"]["ip"].as_string() == str(event.dst.ip),
                    t.events.c.payload["packet"]["protocol_number"].as_integer() == 6,
                )
                .limit(PACKET_SCOPE_LIMIT + 1)
                .execution_options(yield_per=500)
            ).scalars()
            selected = []
            for row in rows:
                checkpoint(size=len(json.dumps(row, ensure_ascii=False).encode()))
                selected.append(NormalizedEvent.model_validate(row))
        if len(selected) > PACKET_SCOPE_LIMIT:
            raise DomainError("RULE_SCOPE_TOO_LARGE", 422)
        if not {event.event_id for event in witness}.issubset(e.event_id for e in selected):
            raise DomainError("FINDING_EVIDENCE_MISSING_FROM_SNAPSHOT", 409)
        return selected

    @staticmethod
    def _snapshot_event_assets(event: NormalizedEvent) -> set[str]:
        """Only inventory-resolved or collector-bound assets are trusted for context."""
        assets = set()
        if event.asset_id:
            assets.add(str(event.asset_id))
        if event.host:
            assets.add(str(event.host.asset_id))
        for endpoint in (event.src, event.dst):
            if (
                endpoint
                and endpoint.asset_id
                and endpoint.resolution_quality == "inventory_interval"
            ):
                assets.add(str(endpoint.asset_id))
        return assets

    @staticmethod
    def _snapshot_reason(event: NormalizedEvent) -> str:
        if event.event_type == "security.alert":
            return "alert_context"
        if event.event_type == "auth.login":
            return "auth_context"
        if event.event_type == "host.process":
            return "process_context"
        if event.event_type == "network.packet":
            return "packet_context"
        if event.event_type.startswith("network."):
            return "network_context"
        return "file_context"

    def _select_snapshot_events(
        self, conn, actor: Actor, incident: dict, detail: dict, start: datetime, end: datetime
    ) -> tuple[list[str], dict]:
        """Keep every rule seed, then bounded context tied to trusted assets.

        The snapshot is still immutable: tools only see the returned event IDs.
        Context is never pulled by raw IP equality or by scanning outside the
        workspace/dataset/session/window.
        """
        finding_ids = list(dict.fromkeys(detail.get("finding_ids") or [incident["finding_id"]]))
        findings = [
            self.service._get(conn, t.findings, actor, fid)["payload"] for fid in finding_ids
        ]
        seed_ids: set[str] = set()
        for finding in findings:
            seed_ids.update(finding.get("evidence_ids", []))
        if not seed_ids:
            raise DomainError("SNAPSHOT_SEEDS_MISSING", 409)
        limit = self.service.settings.snapshot_event_limit
        if len(seed_ids) > limit:
            raise DomainError(
                "SNAPSHOT_SEEDS_EXCEED_LIMIT", 422
            ) from ValueError(f"seeds={len(seed_ids)} limit={limit}")

        seed_rows = conn.execute(
            select(t.events.c.payload)
            .join(
                t.members,
                and_(
                    t.members.c.workspace_id == t.events.c.workspace_id,
                    t.members.c.event_id == t.events.c.event_id,
                ),
            )
            .where(
                t.events.c.workspace_id == actor.workspace_id,
                t.events.c.dataset_id == incident["dataset_id"],
                t.members.c.session_id == incident["session_id"],
                t.events.c.event_id.in_(seed_ids),
            )
        ).scalars()
        seed_events = [NormalizedEvent.model_validate(row) for row in seed_rows]
        if {event.event_id for event in seed_events} != seed_ids:
            raise DomainError("FINDING_EVIDENCE_MISSING_FROM_SNAPSHOT", 409)
        for event in seed_events:
            if not start <= event.event_time < end:
                raise DomainError("FINDING_EVIDENCE_OUTSIDE_INCIDENT_WINDOW", 409)

        seed_assets = set().union(
            *(self._snapshot_event_assets(event) for event in seed_events)
        ) if seed_events else set()
        seed_domains = {event.sensor.observation_domain for event in seed_events}
        context_row = self.service._optional(conn, t.contexts, actor, incident["dataset_id"])
        if context_row:
            from packages.contracts.context import DatasetContext

            dataset_context = DatasetContext.model_validate(context_row["payload"])
            for asset in dataset_context.assets:
                if str(asset.asset_id) not in seed_assets:
                    continue
                seed_domains.update(address.observation_domain for address in asset.addresses)
        scan_limit = self.service.settings.snapshot_scan_limit
        rows = conn.execute(
            select(t.events.c.payload)
            .join(
                t.members,
                and_(
                    t.members.c.workspace_id == t.events.c.workspace_id,
                    t.members.c.event_id == t.events.c.event_id,
                ),
            )
            .where(
                t.events.c.workspace_id == actor.workspace_id,
                t.events.c.dataset_id == incident["dataset_id"],
                t.members.c.session_id == incident["session_id"],
                t.events.c.event_time >= start.isoformat(timespec="microseconds"),
                t.events.c.event_time < end.isoformat(timespec="microseconds"),
            )
            .order_by(t.events.c.event_time, t.events.c.event_id)
            .limit(scan_limit + 1)
        ).scalars()
        candidates = []
        try:
            for row in rows:
                candidates.append(NormalizedEvent.model_validate(row))
        finally:
            rows.close()
        if len(candidates) > scan_limit:
            raise DomainError(
                "SNAPSHOT_SCAN_LIMIT_EXCEEDED", 422
            ) from ValueError(
                f"candidates>{scan_limit}; narrow the incident window or raise "
                "SNAPSHOT_SCAN_LIMIT after capacity review"
            )

        reasons: dict[str, str] = {}
        for event in candidates:
            if event.event_id in seed_ids:
                reasons[event.event_id] = "seed"

        context: list[tuple[int, float, NormalizedEvent, str]] = []
        seed_times = [event.event_time for event in seed_events]
        for event in candidates:
            if event.event_id in reasons:
                continue
            if event.sensor.observation_domain not in seed_domains:
                continue
            if event.asset_id and str(event.asset_id) not in seed_assets:
                continue
            assets = self._snapshot_event_assets(event)
            if assets & seed_assets:
                reason = self._snapshot_reason(event)
            elif not seed_assets and event.sensor.observation_domain in seed_domains:
                reason = "domain_context"
            elif event.event_type == "security.alert" and (
                event.sensor.observation_domain in seed_domains
                or not assets
                or assets & seed_assets
            ):
                reason = "alert_context"
            else:
                continue
            distance = min(
                abs((event.event_time - stamp).total_seconds()) for stamp in seed_times
            )
            priority = {
                "alert_context": 0,
                "auth_context": 1,
                "process_context": 2,
                "network_context": 3,
                "packet_context": 4,
                "file_context": 5,
                "domain_context": 6,
            }[reason]
            context.append((priority, distance, event, reason))
        context.sort(key=lambda item: (item[0], item[1], item[2].event_id))
        budget = limit - len(seed_ids)
        selected_context = context[:budget]
        omitted = context[budget:]
        for _, _, event, reason in selected_context:
            reasons[event.event_id] = reason

        selected_ids = list(seed_ids) + [item[2].event_id for item in selected_context]
        selected_ids = sorted(
            set(selected_ids),
            key=lambda eid: next(
                (
                    (event.event_time, event.event_id)
                    for event in [*seed_events, *[item[2] for item in selected_context]]
                    if event.event_id == eid
                ),
                (end, eid),
            ),
        )
        selected_events = {
            event.event_id: event
            for event in [*seed_events, *[item[2] for item in selected_context]]
        }
        source_counts: dict[str, int] = {}
        type_counts: dict[str, int] = {}
        reason_counts: dict[str, int] = {}
        for eid in selected_ids:
            event = selected_events[eid]
            source_counts[event.sensor.type] = source_counts.get(event.sensor.type, 0) + 1
            type_counts[event.event_type] = type_counts.get(event.event_type, 0) + 1
            reason = reasons[eid]
            reason_counts[reason] = reason_counts.get(reason, 0) + 1
        omitted_type_counts: dict[str, int] = {}
        for _, _, event, _ in omitted:
            omitted_type_counts[event.event_type] = omitted_type_counts.get(event.event_type, 0) + 1
        manifest = {
            "version": "snapshot_selection@1.0.0",
            "seed_finding_count": len(findings),
            "seed_event_count": len(seed_ids),
            "selected_event_count": len(selected_ids),
            "candidate_event_count": len(candidates),
            "trusted_asset_ids": sorted(seed_assets),
            "seed_observation_domains": sorted(seed_domains),
            "source_counts": source_counts,
            "type_counts": type_counts,
            "reason_counts": reason_counts,
            "event_reasons": {eid: reasons[eid] for eid in selected_ids},
            "coverage": {
                "status": "partial" if omitted else "complete",
                "omitted_event_count": len(omitted),
                "omitted_type_counts": omitted_type_counts,
                "limits": {
                    "snapshot_event_limit": limit,
                    "snapshot_scan_limit": scan_limit,
                },
            },
            "limitations": [
                "上下文仅纳入可信资产映射或同一观测域内的安全告警；原始 IP 相等不构成映射。",
                "种子全部保留；上下文超限时按告警、认证、进程、网络、抓包优先级和距种子时间取舍。",
                "partial 表示仍有同窗口上下文未纳入，不能据此声称完整覆盖。",
            ],
        }
        return selected_ids, manifest

    def create_run(
        self,
        actor: Actor,
        incident_id: str,
        key: str,
        mode: str = "auto",
        budget: AgentBudget | None = None,
    ) -> dict:
        self.service.require(actor, ("analyst", "admin"))
        if mode not in {"auto", "live", "deterministic"}:
            raise DomainError("INVALID_INVESTIGATION_MODE", 422)
        route = f"investigate:{incident_id}"
        request_hash = (
            digest(mode.encode())
            if mode == "auto" and budget is None
            else digest(
                json.dumps([mode, (budget or AgentBudget()).model_dump()], sort_keys=True).encode()
            )
        )
        with self.db.engine.begin() as conn:
            conn.execute(
                select(t.workspaces)
                .where(t.workspaces.c.id == actor.workspace_id)
                .with_for_update()
            ).first()
            incident = self.service._get(conn, t.incidents, actor, incident_id)
            detail = self.service._get(conn, t.details, actor, incident_id)["payload"]
            previous = self.service._idem(conn, actor, route, key, request_hash)
            if previous:
                return previous
            first = datetime.fromisoformat(incident["start_time"])
            last = datetime.fromisoformat(incident["end_time"])
            span = (last - first).total_seconds()
            if span >= 1800:
                raise DomainError("INCIDENT_WINDOW_TOO_LARGE", 422)
            margin_us = 1800000000 - (last - first) // timedelta(microseconds=1)
            padding = timedelta(microseconds=min(300000000, margin_us // 2))
            start, end = first - padding, last + padding
            if end == last:
                # Scope end is exclusive; retain the final evidence at the 30-minute cap.
                end += timedelta(microseconds=1)
            ids, manifest = self._select_snapshot_events(
                conn, actor, incident, detail, start, end
            )
            if not ids:
                raise DomainError("SNAPSHOT_EMPTY_OR_TOO_LARGE", 422)
            run_id, snapshot_id, job_id = (str(uuid4()) for _ in range(3))
            scope = InvestigationScope(
                workspace_id=actor.workspace_id,
                dataset_id=incident["dataset_id"],
                session_id=incident["session_id"],
                snapshot_id=snapshot_id,
                start=start,
                end=end,
                selection=manifest,
            )
            conn.execute(
                t.snapshots.insert().values(
                    workspace_id=actor.workspace_id,
                    id=snapshot_id,
                    incident_id=incident_id,
                    scope=scope.model_dump(mode="json"),
                    event_ids=ids,
                    created_at=now(),
                )
            )
            conn.execute(
                t.jobs.insert().values(
                    id=job_id,
                    workspace_id=actor.workspace_id,
                    batch_id=None,
                    kind="investigation",
                    payload={"run_id": run_id},
                    state="queued",
                )
            )
            conn.execute(
                t.runs.insert().values(
                    workspace_id=actor.workspace_id,
                    id=run_id,
                    incident_id=incident_id,
                    snapshot_id=snapshot_id,
                    job_id=job_id,
                    state="queued",
                    created_at=now(),
                )
            )
            result = {
                "run_id": run_id,
                "snapshot_id": snapshot_id,
                "job_id": job_id,
                "state": "queued",
            }
            from packages.agent.state import initialize

            initialize(
                conn,
                actor.workspace_id,
                run_id,
                mode,
                budget or AgentBudget(),
                self.service.settings,
            )
            self.service._remember(conn, actor, route, key, request_hash, result)
            self.service._audit(conn, actor, "investigation.create", run_id)
            return result

    def _snapshot_events(self, conn, actor: Actor, snapshot) -> list[NormalizedEvent]:
        ids = snapshot["event_ids"]
        rows = (
            conn.execute(
                select(t.events.c.payload).where(
                    t.events.c.workspace_id == actor.workspace_id, t.events.c.event_id.in_(ids)
                )
            )
            .scalars()
            .all()
        )
        if len(rows) != len(ids):
            raise DomainError("SNAPSHOT_EVIDENCE_MISSING", 409)
        scope = InvestigationScope.model_validate(snapshot["scope"])
        result = sorted(
            [NormalizedEvent.model_validate(r) for r in rows],
            key=lambda e: (e.event_time, e.event_id),
        )
        for event in result:
            if (
                event.dataset_id != scope.dataset_id
                or not scope.start <= event.event_time < scope.end
            ):
                raise DomainError("EVIDENCE_OUT_OF_SCOPE", 409)
        return result

    def _verify(self, actor: Actor, events: list[NormalizedEvent]) -> None:
        from packages.storage.worker import verified_capture

        checked = set()
        with self.db.engine.connect() as conn:
            for event in events:
                for ref in event.source_locators:
                    if (str(ref.object_id), ref.raw_sha256) in checked:
                        continue
                    obj = self.service._get(conn, t.objects, actor, str(ref.object_id))
                    try:
                        path = self.service.archive_path(obj["storage_key"])
                        if ref.pcap is not None:
                            verified_capture(
                                path, obj["byte_size"], obj["sha256"], "ARCHIVE_INTEGRITY_FAILED"
                            )
                            actual = obj["sha256"]
                        else:
                            actual = file_digest(path)
                    except OSError:
                        raise DomainError("EVIDENCE_UNAVAILABLE", 409) from None
                    if actual != ref.raw_sha256 or actual != obj["sha256"]:
                        raise DomainError("ARCHIVE_INTEGRITY_FAILED", 409)
                    checked.add((str(ref.object_id), ref.raw_sha256))

    def process(self, lease: Lease, queue: Queue) -> None:
        actor = self.service.system_actor(lease.workspace_id)
        with self.db.engine.begin() as conn:
            queue.guard(conn, lease)
            run = dict(self.service._get(conn, t.runs, actor, lease.payload["run_id"]))
            snapshot = dict(self.service._get(conn, t.snapshots, actor, run["snapshot_id"]))
            incident = dict(self.service._get(conn, t.incidents, actor, run["incident_id"]))
            detail = self.service._get(conn, t.details, actor, incident["id"])["payload"]
            findings = [
                self.service._get(conn, t.findings, actor, fid)["payload"]
                for fid in detail["finding_ids"]
            ]
            events = self._snapshot_events(conn, actor, snapshot)
        self._verify(actor, events)
        for finding in findings:
            finding_ids = set(finding["evidence_ids"])
            if not finding_ids.issubset(snapshot["event_ids"]):
                raise DomainError("FINDING_EVIDENCE_MISSING_FROM_SNAPSHOT", 409)
            witness = [e for e in events if e.event_id in finding_ids]
            if finding["rule_id"] == "R18" and finding["rule_version"] != "1.0.0":
                settings = self.service.settings
                try:
                    with DetectionBudget(
                        work_limit=settings.detection_work_limit,
                        seconds=min(
                            settings.detection_timeout_seconds, settings.worker_lease_seconds / 3
                        ),
                        byte_limit=settings.detection_byte_limit,
                        finding_limit=settings.detection_finding_limit,
                        reference_limit=settings.detection_reference_limit,
                    ):
                        context = self._syn_reproduction_context(actor, snapshot, witness)
                        reproduced = reproduce(context, snapshot["scope"]["session_id"], finding)
                except DetectionLimit as exc:
                    raise DomainError("RULE_RESOURCE_LIMIT", 422) from exc
            else:
                reproduced = reproduce(witness, snapshot["scope"]["session_id"], finding)
            if not any(
                f["id"] == finding["id"]
                and f["evidence_ids"] == finding["evidence_ids"]
                and (finding["rule_id"] not in PACKET_RULE_IDS or f == finding)
                for f in reproduced
            ):
                raise DomainError("RULE_EVIDENCE_MISMATCH", 409)
        scope = InvestigationScope.model_validate(snapshot["scope"])
        graph = evidence_graph(events, scope)
        path_analysis = analyze_paths(events, scope, set(detail["evidence_ids"]))
        from packages.agent.runtime import AgentRuntime
        from packages.agent.state import initialize

        with self.db.engine.begin() as conn:
            queue.guard(conn, lease)
            if self.service._optional(conn, t.agent_states, actor, run["id"]) is None:
                initialize(
                    conn,
                    actor.workspace_id,
                    run["id"],
                    "deterministic",
                    AgentBudget(),
                    self.service.settings,
                )
            prepared_state = self.service._get(conn, t.agent_states, actor, run["id"])
            if "pipeline_prepared" not in prepared_state["payload"]:
                from packages.agent.state import checkpoint

                payload = dict(prepared_state["payload"])
                payload["pipeline_prepared"] = {
                    "graph_truncated": graph["truncated"] or path_analysis.truncated,
                    "event_count": len(events),
                }
                checkpoint(
                    conn,
                    actor.workspace_id,
                    run["id"],
                    prepared_state["version"],
                    prepared_state["phase"],
                    payload,
                    "PIPELINE_PREPARED",
                )
        agent = AgentRuntime(self.service, queue, lease).run()
        self._verify(actor, events)
        allowed = set(snapshot["event_ids"])
        refs = [
            EvidenceRef(
                event_id=e.event_id,
                fragments=e.source_locators,
                fields_used=["event_time", "src", "dst", "asset_id", "user", "auth"]
                + (["network", "http"] if e.http else [])
                + (["dns"] if e.dns else [])
                + (["packet"] if e.packet else []),
            )
            for e in events
            if e.event_id in detail["evidence_ids"]
        ]
        if not refs or any(ref.event_id not in allowed for ref in refs):
            raise DomainError("REPORT_EVIDENCE_OUT_OF_SCOPE", 409)
        report_id = str(uuid5(UUID(run["id"]), "report-v1"))
        rule_ids = sorted({f["rule_id"] for f in findings})
        from packages.agent.behavior_reporting import assess_behaviors
        from packages.agent.reporting import rule_guidance
        from packages.contracts.models import ClaimValidation

        alternatives, recommendations = rule_guidance(rule_ids)
        claims = [
            Claim(
                claim_id="rule-" + f["id"],
                kind="observed",
                statement=f"固定版本{f['rule_id']}规则在该快照上触发。",
                fact_predicate=FactPredicate(
                    name="rule_triggered", values={"rule_id": f["rule_id"], "finding_id": f["id"]}
                ),
                evidence_refs=[ref for ref in refs if ref.event_id in f["evidence_ids"]],
                support_level="high",
                limitations=["规则触发不等于恶意行为或真实攻击者身份"]
                + (
                    [f"合并类别候选 {f['attack_subtype']}。"]
                    if f.get("attack_subtype", "").startswith(f"{DOS_DDOS_FAMILY}-")
                    else []
                )
                + (
                    [
                        "贡献证据中可见"
                        + str(f["flood_observation"]["observed_source_ip_count"])
                        + "个源IP，DoS/DDoS来源分布未知。"
                    ]
                    if "flood_observation" in f
                    else []
                )
                + (
                    f["limitations"]
                    if f["rule_id"] in {"R07", "R08", "R09", "R10", "R11", *PACKET_RULE_IDS}
                    else []
                ),
            )
            for f in findings
        ]
        from packages.agent.evidence_state import comparison

        investigation_analysis = comparison(agent)
        report = Report(
            report_id=report_id,
            run_id=run["id"],
            snapshot_id=run["snapshot_id"],
            mode="deterministic_fallback",
            generated_at=datetime.now(UTC),
            summary=f"{' / '.join(rule_ids)}产生{len(findings)}条可复核规则候选；"
            + (
                "受控Agent完成模型与只读工具流程，自由文本仍需人工复核。"
                if agent["report_mode"] == "live"
                else "本次未完成模型推理，使用确定性结果。"
            ),
            claims=[
                *claims,
                *[Claim.model_validate(c) for c in agent["validated_claims"]],
                Claim(
                    claim_id="identity-unknown",
                    kind="unknown",
                    statement="真实操作者身份、后续影响与攻击意图尚无充分证据。",
                ),
            ],
            timeline=[e.event_id for e in events],
            paths=[p.path_id for p in path_analysis.paths],
            candidate_origins=[origin.origin_id for origin in path_analysis.origins],
            path_analysis=path_analysis,
            investigation_analysis=investigation_analysis,
            behavior_assessments=assess_behaviors(
                findings, events, refs, path_analysis, agent["stop_reason"]
            ),
            affected_assets=sorted({e.asset_id for e in events if e.asset_id}, key=str),
            alternatives=alternatives,
            gaps=[
                "缺少操作者身份与授权运维上下文",
                "当前图为观测与显式身份关联，未证实完整因果攻击路径",
                *(["Agent未完成项：" + agent["stop_reason"]] if agent["stop_reason"] else []),
            ],
            recommendations=recommendations,
            provenance={
                "knowledge_version": agent.get("knowledge_version", "not_loaded"),
                "rule_version": ",".join(f["rule_id"] + "@" + f["rule_version"] for f in findings),
                "finding_ids": ",".join(detail["finding_ids"]),
                "incident_id": incident["id"],
                "path_version": "event_paths@1.0.0",
                "template_version": "1.5.0",
                "agent_version": agent.get("agent_version", "bounded_agent@1.0.0"),
                "prompt_version": agent.get("prompt_version", "evidence_agent@1.0.0"),
                "assessment_config_hash": agent.get("assessment_config_hash", "unavailable"),
                "baseline_hashes": ",".join(
                    sorted({f["baseline_hash"] for f in findings if "baseline_hash" in f})
                ),
                "model_config_version": agent["model_config_version"],
                "model_execution": (
                    "protocol_test_stub"
                    if agent.get("model_metadata", {}).get("test_stub", False)
                    else "configured_model"
                )
                if agent["used"]["model_calls"]
                else "disabled",
                "budget_used": json.dumps(agent["used"], sort_keys=True),
                "graph_version": "evidence_graph@1.1.0",
                "model": agent.get("model_metadata", {}).get("name", "unknown"),
                "provider": agent.get("model_metadata", {}).get("provider", "unknown"),
                "config_hash": digest(
                    json.dumps([f["config"] for f in findings], sort_keys=True).encode()
                ),
            },
            validation="passed",
        )
        report.mode = agent["report_mode"]
        report.claim_validation = ClaimValidation(
            validated_observed=sum(c.kind == "observed" for c in report.claims),
            unknown_claims=sum(c.kind == "unknown" for c in report.claims),
            rejected_codes=agent["rejected"],
            repair_attempts=agent["repair_count"],
            stop_reason=agent["stop_reason"],
        )
        if investigation_analysis:
            report.hypotheses = [
                h.statement + " 状态=" + h.status for h in investigation_analysis.after.hypotheses
            ]
            report.alternatives += [
                "同窗正常进程线索（仅上下文）：" + h.observation + " 不证明流量归属或没有攻击。"
                for h in investigation_analysis.after.hypotheses
                if h.status == "weakened"
            ]
            report.gaps += sorted(
                {
                    g.code + "：" + g.explanation
                    for g in investigation_analysis.after.gaps
                    if g.status != "resolved"
                }
            )
        if agent["report_mode"] == "live" and agent["draft"]:
            report.alternatives += [
                "模型待复核替代解释：" + text[:1000] for text in agent["draft"]["alternatives"]
            ]
            report.gaps += ["模型提示缺口：" + text[:1000] for text in agent["draft"]["gaps"]]
        from packages.agent.pipeline import progress_for_run

        with self.db.engine.connect() as conn:
            actions = list(
                conn.execute(
                    select(t.agent_actions)
                    .where(
                        t.agent_actions.c.workspace_id == actor.workspace_id,
                        t.agent_actions.c.run_id == run["id"],
                    )
                    .order_by(t.agent_actions.c.seq)
                ).mappings()
            )
        report.pipeline_progress = progress_for_run(
            len(events),
            agent["terminal"],
            agent["terminal"],
            actions,
            report_ready=True,
            graph_truncated=graph["truncated"] or path_analysis.truncated,
        )
        serialized_graph = {
            "nodes": graph["nodes"],
            "edges": [e.model_dump(mode="json") for e in graph["edges"]],
            "truncated": graph["truncated"],
        }
        from packages.agent.cache import report_cache_key
        from packages.agent.state import config_version

        if agent["model_config_version"] == config_version(self.service.settings):
            report.provenance["cache_key"] = report_cache_key(
                self.service.settings,
                snapshot,
                [e.model_dump(mode="json") for e in events],
                findings,
                agent["budget"],
            )
        report.provenance["cost_microusd"] = str(agent["used"].get("cost_microusd", 0))
        report.provenance["actual_cost_microusd"] = str(
            agent["used"].get("actual_cost_microusd", 0)
        )
        report.provenance["cost_basis"] = (
            "configured USD estimate; reservation not refunded; not invoice"
        )
        report.provenance["price_version"] = agent.get("model_metadata", {}).get(
            "price_version", "unavailable"
        )
        with self.db.engine.begin() as conn:
            queue.guard(conn, lease)
            conn.execute(
                t.reports.insert().values(
                    workspace_id=actor.workspace_id,
                    id=report_id,
                    run_id=run["id"],
                    version=1,
                    payload=report.model_dump(mode="json"),
                )
            )
            conn.execute(
                t.runs.update()
                .where(t.runs.c.workspace_id == actor.workspace_id, t.runs.c.id == run["id"])
                .values(state=agent["terminal"], report_id=report_id, graph=serialized_graph)
            )
            queue.finish(
                conn, lease, "succeeded" if agent["terminal"] == "completed" else "partial"
            )
            self.service._audit(conn, actor, "report.publish", report_id)

    def get_run(self, actor: Actor, run_id: str) -> dict:
        with self.db.engine.connect() as conn:
            row = self.service._get(conn, t.runs, actor, run_id)
            result = {
                key: row[key]
                for key in ("id", "incident_id", "snapshot_id", "job_id", "state", "report_id")
            }
            snapshot_row = self.service._get(conn, t.snapshots, actor, row["snapshot_id"])
            selection = snapshot_row["scope"].get("selection")
            if selection is not None:
                result["snapshot_manifest"] = selection
            state = self.service._optional(conn, t.agent_states, actor, run_id)
            if state:
                result.update(
                    phase=state["phase"],
                    state_version=state["version"],
                    budget_used=state["payload"]["used"],
                    budget=state["payload"]["budget"],
                    requested_mode=state["payload"]["requested_mode"],
                    retrieved_count=len(state["payload"]["retrieved"]),
                    cache_hits=state["payload"]["cache_hits"],
                    stop_reason=state["payload"]["stop_reason"],
                    query_stop_reason=state["payload"].get("query_stop_reason"),
                )
            # Final views use the saved report, including historical absence.
            if row["report_id"]:
                report = self.service._get(conn, t.reports, actor, row["report_id"])["payload"]
                if report.get("pipeline_progress") is not None:
                    result["pipeline_progress"] = report["pipeline_progress"]
            elif state:
                from packages.agent.pipeline import progress_for_run

                snapshot = self.service._get(conn, t.snapshots, actor, row["snapshot_id"])
                actions = list(
                    conn.execute(
                        select(t.agent_actions)
                        .where(
                            t.agent_actions.c.workspace_id == actor.workspace_id,
                            t.agent_actions.c.run_id == run_id,
                        )
                        .order_by(t.agent_actions.c.seq)
                    ).mappings()
                )
                result["pipeline_progress"] = progress_for_run(
                    len(snapshot["event_ids"]),
                    state["phase"],
                    row["state"],
                    actions,
                    graph_truncated=state["payload"]
                    .get("pipeline_prepared", {})
                    .get("graph_truncated", False),
                    prepared="pipeline_prepared" in state["payload"],
                    terminal_phase=state["payload"].get("pipeline_terminal_phase"),
                ).model_dump(mode="json")
            return result

    def tool_call_page(
        self, actor: Actor, run_id: str, limit: int = 50, cursor: str | None = None
    ) -> dict:
        self.service.require(actor, ("analyst", "admin"))
        self.get_run(actor, run_id)
        from packages.storage.paging import immutable_page

        with self.db.engine.connect() as conn:
            rows = (
                conn.execute(
                    select(t.agent_actions)
                    .where(
                        t.agent_actions.c.workspace_id == actor.workspace_id,
                        t.agent_actions.c.run_id == run_id,
                    )
                    .order_by(t.agent_actions.c.seq)
                )
                .mappings()
                .all()
            )
        items = [
            {
                k: row[k]
                for k in (
                    "seq",
                    "kind",
                    "name",
                    "status",
                    "args_hash",
                    "args_payload",
                    "result_digest",
                    "request_id",
                    "usage",
                    "error_code",
                    "new_evidence_count",
                    "started_at",
                    "ended_at",
                )
            }
            for row in rows
        ]
        for item, row in zip(items, rows, strict=True):
            result = row["result_payload"] or {}
            item.update(
                evidence_ids=result.get("evidence_ids", []),
                cache_hit=row["cache_hit"],
                reason_summary=result.get(
                    "reason_summary",
                    "受控只读工具执行" if row["kind"] == "tool" else "有限格式模型草稿",
                ),
            )
        return immutable_page(
            actor,
            ["agent-actions", run_id],
            items,
            lambda item: [f"{item['seq']:04d}"],
            limit,
            cursor,
        )

    def transition_page(
        self, actor: Actor, run_id: str, limit: int = 50, cursor: str | None = None
    ) -> dict:
        self.get_run(actor, run_id)
        from packages.storage.paging import immutable_page

        with self.db.engine.connect() as conn:
            rows = (
                conn.execute(
                    select(t.agent_transitions).where(
                        t.agent_transitions.c.workspace_id == actor.workspace_id,
                        t.agent_transitions.c.run_id == run_id,
                    )
                )
                .mappings()
                .all()
            )
        items = [
            {key: row[key] for key in ("version", "phase", "reason", "occurred_at", "budget_used")}
            for row in rows
        ]
        return immutable_page(
            actor,
            ["agent-transitions", run_id],
            items,
            lambda item: [f"{item['version']:06d}"],
            limit,
            cursor,
        )

    def get_graph(self, actor: Actor, run_id: str) -> dict:
        with self.db.engine.connect() as conn:
            row = self.service._get(conn, t.runs, actor, run_id)
            if row["graph"] is None:
                raise DomainError("INVESTIGATION_NOT_COMPLETE", 409)
            return row["graph"]

    def graph_page(
        self,
        actor: Actor,
        run_id: str,
        limit: int = 50,
        cursor: str | None = None,
        focus_entity: str | None = None,
    ) -> dict:
        from packages.storage.paging import immutable_page

        graph = self.get_graph(actor, run_id)
        edges, nodes = graph["edges"], graph["nodes"]
        if focus_entity:
            if not any(node["entity_id"] == focus_entity for node in nodes):
                raise DomainError("NOT_FOUND", 404)
            edges = [edge for edge in edges if focus_entity in (edge["source"], edge["target"])]
            visible = {focus_entity} | {
                eid for edge in edges for eid in (edge["source"], edge["target"])
            }
            nodes = [node for node in nodes if node["entity_id"] in visible]
        page = immutable_page(
            actor,
            ["graph", run_id, focus_entity or ""],
            edges,
            lambda edge: [edge["edge_id"]],
            limit,
            cursor,
        )
        return {
            "nodes": sorted(nodes, key=lambda node: node["entity_id"]),
            "edges": page["items"],
            "next_cursor": page["next_cursor"],
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "truncated": graph["truncated"],
        }

    def timeline_page(
        self, actor: Actor, run_id: str, limit: int = 50, cursor: str | None = None
    ) -> dict:
        from packages.storage.paging import immutable_page

        with self.db.engine.connect() as conn:
            run = self.service._get(conn, t.runs, actor, run_id)
            snapshot = self.service._get(conn, t.snapshots, actor, run["snapshot_id"])
            events = self._snapshot_events(conn, actor, snapshot)
        return immutable_page(
            actor,
            ["timeline", run_id, run["snapshot_id"]],
            [e.model_dump(mode="json") for e in events],
            lambda e: [e["event_time"], e["event_id"]],
            limit,
            cursor,
        )

    def get_paths(self, actor: Actor, run_id: str) -> dict:
        run = self.get_run(actor, run_id)
        if run["report_id"] is None:
            raise DomainError("INVESTIGATION_NOT_COMPLETE", 409)
        report = self.get_report(actor, run["report_id"])
        if report["validation"] != "passed":
            raise DomainError("EVIDENCE_UNVERIFIABLE", 409)
        if report.get("path_analysis") is None:
            raise DomainError("LEGACY_PATH_ANALYSIS_UNAVAILABLE", 409)
        return report["path_analysis"]

    def get_incident(self, actor: Actor, incident_id: str) -> dict:
        with self.db.engine.connect() as conn:
            incident = dict(self.service._get(conn, t.incidents, actor, incident_id))
            detail = self.service._get(conn, t.details, actor, incident_id)["payload"]
            findings = [
                self.service._get(conn, t.findings, actor, fid)["payload"]
                for fid in detail["finding_ids"]
            ]
        return incident | {"finding": findings[0], "findings": findings, "membership": detail}

    def get_report(self, actor: Actor, report_id: str) -> dict:
        with self.db.engine.connect() as conn:
            report = self.service._get(conn, t.reports, actor, report_id)["payload"]
            snapshot = self.service._get(conn, t.snapshots, actor, report["snapshot_id"])
            events = self._snapshot_events(conn, actor, snapshot)
        try:
            self._verify(actor, events)
        except DomainError:
            return report | {
                "validation": "partial",
                "gaps": [*report["gaps"], "当前原始证据不可验证；历史报告内容未改写"],
            }
        return report

    def _packet_evidence(
        self, conn, actor: Actor, event: NormalizedEvent, ref: SourceLocator
    ) -> dict:
        from packages.ingest.pcap_packet import (
            ARP_REPLY_PARSER_VERSION,
            ARP_REQUEST_PARSER_VERSION,
            DNS_DATAGRAM_PARSER_VERSION,
            GRE_PARSER_VERSION,
            MAX_CAPTURE_BYTES,
            OS_PROBE_PARSER_VERSION,
            PARSER_VERSION,
            locate_record,
            observation,
        )

        obj = self.service._get(conn, t.objects, actor, str(ref.object_id))
        size = obj["byte_size"]
        if not 24 <= size <= MAX_CAPTURE_BYTES or obj["sensor_id"] != event.sensor.sensor_id:
            raise DomainError("EVIDENCE_RANGE_INVALID", 409)
        try:
            with self.service.archive_path(obj["storage_key"]).open("rb") as source:
                data = source.read(size + 1)
        except OSError:
            raise DomainError("EVIDENCE_UNAVAILABLE", 409) from None
        if len(data) != size or not digest(data) == obj["sha256"] == ref.raw_sha256:
            raise DomainError("ARCHIVE_INTEGRITY_FAILED", 409)
        try:
            record = locate_record(BytesIO(data), size, ref)
            parser = event.parser_version.split("+", 1)[0]
            src, dst, packet, flags = observation(
                record,
                include_echo_header=parser in {"pcap-packet@1.1.0", PARSER_VERSION},
                include_http_segment=parser == PARSER_VERSION,
                include_arp_request=parser == ARP_REQUEST_PARSER_VERSION,
                include_gre_summary=parser == GRE_PARSER_VERSION,
                include_arp_reply=parser == ARP_REPLY_PARSER_VERSION,
                include_dns_datagram=parser == DNS_DATAGRAM_PARSER_VERSION,
                include_os_probe=parser == OS_PROBE_PARSER_VERSION,
            )
        except ValueError:
            raise DomainError("EVIDENCE_RANGE_INVALID", 409) from None
        expected_id = stable_event_id(
            event.workspace_id,
            event.dataset_id,
            event.sensor.sensor_id,
            [ref],
            native_record_id=f"pcap:{ref.raw_sha256}:{record.number}",
            instance_id=event.sensor.instance_id,
        )
        if (
            expected_id != event.event_id
            or event.packet != packet
            or event.src is None
            or event.dst is None
            or (src.ip, src.port, dst.ip, dst.port)
            != (event.src.ip, event.src.port, event.dst.ip, event.dst.port)
            or event.time_quality.original != record.original_time
            or not set(flags).issubset(event.quality_flags)
        ):
            raise DomainError("EVIDENCE_RANGE_INVALID", 409)
        return {
            "object_id": str(ref.object_id),
            "sha256": ref.raw_sha256,
            "lines": [],
            "pcap_record": {
                "record_number": record.number,
                "byte_range": ref.pcap.model_dump(mode="json"),
                "capture_time": (
                    datetime.fromtimestamp(record.seconds, UTC)
                    + timedelta(microseconds=record.micros)
                ).isoformat(),
                "packet": packet.model_dump(mode="json"),
                "capture_truncated": "capture_truncated" in flags,
            },
        }

    def packet_evidence(self, actor: Actor, event_id: str, packet_scope: str) -> dict:
        from packages.storage.paging import decode

        location = decode(actor, ["packet.evidence"], packet_scope)
        if (
            len(location) != 3
            or not all(isinstance(value, str) for value in location[:2])
            or type(location[2]) is not int
            or location[2] < 1
        ):
            raise DomainError("INVALID_CURSOR", 422)
        dataset, session, highwater = location
        with self.db.engine.connect() as conn:
            payload = conn.execute(
                select(t.events.c.payload)
                .join(
                    t.members,
                    and_(
                        t.members.c.workspace_id == t.events.c.workspace_id,
                        t.members.c.event_id == t.events.c.event_id,
                    ),
                )
                .where(
                    t.events.c.workspace_id == actor.workspace_id,
                    t.events.c.dataset_id == dataset,
                    t.events.c.event_id == event_id,
                    t.events.c.event_type == "network.packet",
                    t.members.c.session_id == session,
                    t.members.c.publication <= highwater,
                )
            ).scalar_one_or_none()
            if payload is None:
                raise DomainError("EVIDENCE_OUT_OF_SCOPE", 404)
            try:
                event = NormalizedEvent.model_validate(payload)
            except ValidationError:
                raise DomainError("EVIDENCE_RANGE_INVALID", 409) from None
            fragment = self._packet_evidence(conn, actor, event, event.source_locators[0])
        return {
            "event_id": event_id,
            "verified": True,
            "redacted": True,
            "fragments": [fragment],
            "next_cursor": None,
        }

    def evidence(
        self,
        actor: Actor,
        event_id: str,
        snapshot_id: str,
        cursor: str | None = None,
        limit: int = 20,
    ) -> dict:
        with self.db.engine.connect() as conn:
            snapshot = self.service._get(conn, t.snapshots, actor, snapshot_id)
            if event_id not in snapshot["event_ids"]:
                raise DomainError("EVIDENCE_OUT_OF_SCOPE", 404)
        event = NormalizedEvent.model_validate(self.service.get_event(actor, event_id))
        if event.packet is None:
            self._verify(actor, [event])

        def signature(index: int) -> str:
            from packages.storage.paging import sign

            binding = json.dumps(
                [actor.workspace_id, actor.digest, snapshot_id, event_id, index]
            ).encode()
            return sign(actor, binding)

        start = 0
        if cursor:
            try:
                position, signed = cursor.split(".")
                start = int(position)
                if start < 0 or not hmac.compare_digest(signed, signature(start)):
                    raise ValueError("invalid cursor")
            except (ValueError, TypeError) as exc:
                raise DomainError("INVALID_EVIDENCE_CURSOR", 422) from exc
        locations = [
            ref.model_copy(update={"record_start": line, "record_end": line})
            for ref in event.source_locators
            for line in range(ref.record_start, ref.record_end + 1)
        ]
        if start >= len(locations):
            raise DomainError("INVALID_EVIDENCE_CURSOR", 422)
        if not 1 <= limit <= 20:
            raise DomainError("INVALID_LIMIT", 422)
        end = min(start + limit, len(locations))
        fragments = []
        permitted = {
            "ts",
            "uid",
            "id.orig_h",
            "id.orig_p",
            "id.resp_h",
            "id.resp_p",
            "proto",
            "orig_bytes",
            "resp_bytes",
            "timestamp",
            "event_type",
            "src_ip",
            "dest_ip",
            "src_port",
            "dest_port",
            "flow_id",
            "synthetic",
            "record_type",
            "audit_serial",
            "boot_id",
        }
        if event.sensor.type.startswith("linux_"):
            permitted.discard("uid")
        with self.db.engine.connect() as conn:
            for ref in locations[start:end]:
                if ref.pcap is not None:
                    fragments.append(self._packet_evidence(conn, actor, event, ref))
                    continue
                if ref.record_end - ref.record_start >= 20:
                    raise DomainError("EVIDENCE_RANGE_TOO_LARGE", 422)
                obj = self.service._get(conn, t.objects, actor, str(ref.object_id))
                lines = []
                with self.service.archive_path(obj["storage_key"]).open("rb") as source:
                    for number, raw in enumerate(source, start=1):
                        if ref.record_start <= number <= ref.record_end:
                            record = json.loads(raw)
                            redacted = {k: v for k, v in record.items() if k in permitted}
                            # Project validated observations, never raw URI/credentials/TXT.
                            if event.http is not None:
                                redacted["http"] = event.http.model_dump(mode="json")
                            if event.dns is not None:
                                redacted["dns"] = event.dns.model_dump(mode="json")
                            if event.sensor.type == "linux_audit":
                                from packages.storage.evidence_projection import process_projection

                                process_fields = process_projection(record.get("process"))
                                if process_fields:
                                    redacted["process"] = process_fields
                            if event.sensor.type == "linux_auth":
                                redacted["auth"] = {
                                    k: v
                                    for k, v in record.get("auth", {}).items()
                                    if k in ("outcome", "method", "service")
                                }
                            if event.user and event.sensor.type.startswith("linux_"):
                                redacted["user_redacted"] = event.user.name_redacted
                            lines.append(
                                {"line": number, "text": json.dumps(redacted, ensure_ascii=False)}
                            )
                        if number >= ref.record_end:
                            break
                if len(lines) != ref.record_end - ref.record_start + 1:
                    raise DomainError("EVIDENCE_RANGE_INVALID", 409)
                fragments.append(
                    {"object_id": str(ref.object_id), "sha256": ref.raw_sha256, "lines": lines}
                )
        return {
            "event_id": event_id,
            "verified": True,
            "redacted": True,
            "fragments": fragments,
            "next_cursor": f"{end}.{signature(end)}" if end < len(locations) else None,
        }
