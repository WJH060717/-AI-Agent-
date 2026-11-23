"""Prediction side of the offline harness: reads approved telemetry, never labels."""

import tempfile
import threading
import time
from pathlib import Path

from sqlalchemy import select

from eval.contracts import EvaluationConfig, Execution, RunInput
from eval.freeze import read_scoped
from packages.agent.runtime import AgentRuntime
from packages.agent.validation import DraftError, validate_draft
from packages.config import Settings
from packages.contracts.agent import ReportDraft
from packages.contracts.context import DatasetContext
from packages.storage import schema_v6 as t
from packages.storage.analysis import AnalysisService
from packages.storage.context import ContextService
from packages.storage.database import Database
from packages.storage.queue import Queue
from packages.storage.service import DataService, DomainError
from scripts.model_stub import ProtocolStub


class SingleSummary(AgentRuntime):
    """B2 policy: same resource ceilings, one draft call, zero tools, zero repair calls."""

    def step(self) -> bool:
        self.reload()
        self.guard()
        if self.phase == "planning":
            self.payload["query_stop_reason"] = "ABLATION_B2_NO_RETRIEVAL"
            self.save("drafting", "ABLATION_B2_SINGLE_SUMMARY")
        if self.phase == "validating":
            try:
                validate_draft(
                    ReportDraft.model_validate(self.payload["draft"]),
                    self.tools.events,
                    set(self.tools.membership["evidence_ids"]),
                    self.findings,
                    self.paths,
                )
            except DraftError as exc:
                self.payload["rejected"].append(str(exc))
                self.payload["stop_reason"] = "B2_DRAFT_VALIDATION_FAILED"
                self.save("degraded", "B2_NO_REPAIR_POLICY")
        return super().step()


def import_run(service: DataService, actor, run: RunInput, root: Path) -> dict:
    dataset = service.create_dataset(
        actor,
        {"name": "offline evaluation input", "provenance_type": run.provenance_type},
        run.run_id,
    )
    if run.context:
        ContextService(service).configure(
            actor,
            dataset["dataset_id"],
            DatasetContext.model_validate_json(read_scoped(root, run.context)),
            "context",
        )
    for index, source in enumerate(run.sources):
        batch = service.stage_bytes(
            actor,
            dataset["dataset_id"],
            source.source_type,
            source.sensor_id,
            "UTC",
            read_scoped(root, source.object),
            f"{run.run_id}:input-{index}",
        )
        service.process_one()
        status = service.get_batch(actor, batch["batch_id"])
        if status["status"] != "succeeded":
            raise ValueError("EVALUATION_IMPORT_NOT_COMPLETE")
    return dataset


def observe_investigation(
    service: DataService,
    actor,
    investigation: dict,
    config: EvaluationConfig,
    group: str,
    started: float,
    result: dict,
) -> dict:
    """Every accepted run is accounted for, including exceptions and censored waits."""
    analysis = AnalysisService(service)
    queue = Queue(service.db, service.settings)
    errors = []
    state = {"state": "unknown", "report_id": None}
    observed = False
    attempts = 0
    deadline = started + config.budget.timeout_seconds
    try:
        while time.perf_counter() < deadline:
            try:
                if group == "B2":
                    lease = queue.claim("offline-b2")
                    if lease is not None:
                        if lease.job_id != investigation["job_id"]:
                            raise ValueError("UNEXPECTED_EVALUATION_JOB")
                        done = threading.Event()

                        def heartbeat(done=done, lease=lease):
                            while not done.wait(service.settings.worker_heartbeat_seconds):
                                queue.heartbeat(lease)

                        thread = threading.Thread(target=heartbeat, daemon=True)
                        thread.start()
                        try:
                            SingleSummary(service, queue, lease).run()
                            analysis.process(lease, queue)
                        except Exception:
                            queue.fail(lease, "B2_EXECUTION_FAILED", retryable=False)
                            raise
                        finally:
                            done.set()
                            thread.join(timeout=2)
                else:
                    service.process_one()
            except Exception as exc:
                errors.append(exc.code if isinstance(exc, DomainError) else type(exc).__name__)
            state = analysis.get_run(actor, investigation["run_id"])
            attempts = queue.status(actor, investigation["job_id"])["attempt"]
            if state["state"] in {"completed", "partial", "failed", "cancelled"}:
                observed = True
                break
            time.sleep(0.05)
    finally:
        try:
            state = analysis.get_run(actor, investigation["run_id"])
            attempts = queue.status(actor, investigation["job_id"])["attempt"]
            observed = state["state"] in {"completed", "partial", "failed", "cancelled"}
        except Exception:
            errors.append("FINAL_STATE_UNAVAILABLE")
        usage = state.get("budget_used", {})
        item = {
            "run_id": investigation["run_id"],
            "status": state["state"],
            "elapsed_ms": (time.perf_counter() - started) * 1000,
            "terminal_observed": observed,
            "attempts": attempts,
            "error": state.get("stop_reason") or (errors[-1] if errors else None),
            "attempt_errors": errors,
            "usage": usage,
            "usage_available": "budget_used" in state,
            "model_price_version": service.settings.model_price_version,
            "model_mode": result["mode"],
            "timing_basis": "create start to terminal observation including queue/retries"
            if observed
            else "censored at observation deadline/error; terminal time unknown",
        }
        result["investigations"].append(item)
        for key, value in usage.items():
            result["usage"][key] = result["usage"].get(key, 0) + value
    if not observed:
        result["status"] = "failed"
        result["error"] = "INVESTIGATION_OBSERVATION_INCOMPLETE"
    return state


def collect(
    service: DataService,
    actor,
    dataset: dict,
    run: RunInput,
    config: EvaluationConfig,
    group: str,
    repeat: int,
) -> dict:
    started = time.perf_counter()
    result = Execution(
        run_id=run.run_id,
        scenario_id=run.scenario_id,
        group=group,
        repeat=repeat,
        status="completed",
        elapsed_ms=0,
    ).model_dump(mode="json")
    result["limitations"] = [
        "Elapsed time covers investigation after common ingestion, not ingest latency.",
        "B0/B1 are templates; B2 is one summary with no retrieval; B3 uses bounded tools.",
    ]
    try:
        with service.db.engine.connect() as conn:
            findings = (
                conn.execute(
                    select(t.findings.c.payload).where(
                        t.findings.c.workspace_id == actor.workspace_id,
                        t.findings.c.dataset_id == dataset["dataset_id"],
                    )
                )
                .scalars()
                .all()
            )
            events = (
                conn.execute(
                    select(t.events.c.payload).where(
                        t.events.c.workspace_id == actor.workspace_id,
                        t.events.c.dataset_id == dataset["dataset_id"],
                    )
                )
                .scalars()
                .all()
            )
        result["events"] = [
            {k: e[k] for k in ("event_id", "asset_id", "source_locators")} for e in events
        ]
        by_id = {e["event_id"]: e for e in events}
        for finding in findings:
            assets = {
                str(by_id[eid]["asset_id"])
                for eid in finding["evidence_ids"]
                if by_id[eid]["asset_id"]
            }
            result["detections"].append(
                {
                    "id": finding["id"],
                    "rule_id": finding["rule_id"],
                    "asset_id": finding.get("source_asset_id")
                    or finding.get("asset_id")
                    or (next(iter(assets)) if len(assets) == 1 else None),
                    "start": finding["start_time"],
                    "end": finding["end_time"],
                    "observable": True,
                }
            )
        if group == "B0":
            result["mode"] = "template"
            return result
        if group in {"B2", "B3"} and service.settings.model_provider == "disabled":
            result.update(status="blocked", mode="disabled", error="MODEL_DISABLED")
            return result
        analysis = AnalysisService(service)
        incidents = analysis.list_incidents(
            actor, dataset["dataset_id"], dataset["default_session_id"]
        )
        result["mode"] = (
            "template"
            if group == "B1"
            else "protocol_test_stub"
            if service.settings.model_test_stub
            else "configured_model"
        )
        for index, incident in enumerate(incidents):
            investigation_started = time.perf_counter()
            investigation = analysis.create_run(
                actor,
                incident["id"],
                f"{group}-{repeat}-{index}",
                mode="deterministic" if group == "B1" else "live",
                budget=config.budget,
            )
            state = observe_investigation(
                service, actor, investigation, config, group, investigation_started, result
            )
            if state["state"] != "completed":
                result["status"] = "partial" if state["state"] == "partial" else "failed"
                result["error"] = state.get("stop_reason") or "INVESTIGATION_NOT_COMPLETE"
            if not state["report_id"]:
                continue
            report = analysis.get_report(actor, state["report_id"])
            result["reports"].append(
                {
                    k: report[k]
                    for k in (
                        "report_id",
                        "run_id",
                        "snapshot_id",
                        "mode",
                        "generated_at",
                        "claims",
                        "claim_validation",
                        "provenance",
                    )
                }
            )
            paths = report["path_analysis"]
            result["graph_edges"].extend(
                {k: e[k] for k in ("from_event_id", "to_event_id", "relation")}
                for e in paths["links"]
            )
            result["origins"].extend(o["event_id"] for o in paths["origins"])
            if report.get("investigation_analysis"):
                result["before_after"].append(report["investigation_analysis"])
            with service.db.engine.connect() as conn:
                snapshot = service._get(conn, t.snapshots, actor, investigation["snapshot_id"])
                allowed = set(snapshot["event_ids"])
            for claim in report["claims"]:
                for ref in claim["evidence_refs"]:
                    result["references_total"] += 1
                    if ref["event_id"] in allowed:
                        service.verify_evidence(actor, ref["event_id"])
                        result["references_valid"] += 1
            validation = report["claim_validation"]
            result["observed_validated"] += validation["validated_observed"]
            result["rejected_claims"] += len(validation["rejected_codes"])
    except Exception as exc:
        result.update(
            status="failed", error=exc.code if isinstance(exc, DomainError) else type(exc).__name__
        )
    finally:
        result["elapsed_ms"] = (time.perf_counter() - started) * 1000
    return Execution.model_validate(result).model_dump(mode="json")


def execute(config: EvaluationConfig, root: Path, emit) -> None:
    stub = ProtocolStub() if config.model_mode == "protocol_stub" else None
    try:
        stub_port = stub.start() if stub else None
        with tempfile.TemporaryDirectory(
            prefix="trace-d11-eval-", ignore_cleanup_errors=True
        ) as temp:
            folder = Path(temp)
            options = {"model_provider": "disabled", "model_test_stub": False}
            if stub:
                options.update(
                    model_provider="compatible",
                    model_base_url=f"http://127.0.0.1:{stub_port}/v1",
                    model_name="protocol-test-stub",
                    model_api_key="local-eval-dummy",
                    model_test_stub=True,
                )
            elif config.model_mode == "configured":
                options = {}
            settings = Settings(
                _env_file=None,
                app_env="test",
                database_url=f"sqlite:///{folder / 'test.db'}",
                raw_store=folder / "raw",
                staging_store=folder / "staging",
                **options,
            )
            if config.model_mode == "configured" and (
                settings.model_provider != "compatible" or settings.model_test_stub
            ):
                raise ValueError("CONFIGURED_MODEL_NOT_AVAILABLE")
            database = Database(settings)
            database.migrate()
            service = DataService(database, settings)
            workspace, _ = service.init_workspace("offline evaluation")
            actor = service.system_actor(workspace)
            try:
                for run in config.runs:
                    try:
                        dataset = import_run(service, actor, run, root)
                    except Exception as exc:
                        for repeat in range(config.repeats):
                            for group in config.groups:
                                emit(
                                    Execution(
                                        run_id=run.run_id,
                                        scenario_id=run.scenario_id,
                                        group=group,
                                        repeat=repeat,
                                        status="failed",
                                        elapsed_ms=0,
                                        error=exc.code
                                        if isinstance(exc, DomainError)
                                        else type(exc).__name__,
                                    ).model_dump(mode="json")
                                )
                        continue
                    for repeat in range(config.repeats):
                        for group in config.groups:
                            emit(collect(service, actor, dataset, run, config, group, repeat))
            finally:
                database.engine.dispose()
    finally:
        if stub:
            stub.stop()
