"""D2 HTTP boundary; all business routes require scoped bearer authentication."""

from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from typing import Literal
from uuid import UUID, uuid4

from fastapi import Depends, FastAPI, File, Form, Header, Query, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import Response
from sqlalchemy.exc import SQLAlchemyError
from starlette.exceptions import HTTPException

from apps.api.errors import RateLimited, error_response
from apps.api.limits import BodyLimit, RequestLimiter
from apps.api.web import mount_web
from packages.config import Settings
from packages.contracts.api import (
    AgentActionPage,
    AgentTransitionPage,
    ContextResponse,
    DatasetCreate,
    DatasetPage,
    DatasetResponse,
    EventPage,
    EvidenceResponse,
    GraphResponse,
    ImportResponse,
    ImportStatus,
    IncidentPage,
    InvestigationCreate,
    RunResponse,
    RunStatus,
)
from packages.contracts.context import DatasetContext
from packages.contracts.models import NormalizedEvent, PathAnalysis, Report
from packages.contracts.replay import ReplayCreate, ReplayStatus
from packages.contracts.reports import (
    ReportPage,
    ReviewCreate,
    ReviewPage,
    ReviewRecord,
    RuntimeConfiguration,
)
from packages.storage.analysis import AnalysisService
from packages.storage.context import ContextService, SensorSelectionRequired
from packages.storage.database import Database
from packages.storage.queue import Queue
from packages.storage.replay import ReplayService
from packages.storage.reports import ReportService
from packages.storage.service import Actor, DataService, DomainError


def create_app(settings: Settings | None = None) -> FastAPI:
    config = settings or Settings()
    service = DataService(Database(config), config) if config.database_url else None

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        try:
            yield
        finally:
            if service is not None:
                service.db.engine.dispose()

    application = FastAPI(title="Telemetry Trace", version="0.1.0.dev43", lifespan=lifespan)
    application.add_middleware(BodyLimit, max_bytes=config.max_upload_mb * 1024 * 1024 + 65536)

    limiter = RequestLimiter(
        config.api_read_requests_per_minute,
        config.api_write_requests_per_minute,
        config.api_rate_max_identities,
    )

    @application.middleware("http")
    async def request_context(request: Request, call_next):
        request.state.request_id = str(uuid4())
        length = request.headers.get("content-length")
        if length and (
            not length.isascii()
            or not length.isdigit()
            or len(length) > 10
            or int(length) > config.max_upload_mb * 1024 * 1024 + 65536
        ):
            return error_response(request, "UPLOAD_TOO_LARGE", 413)
        try:
            response = await call_next(request)
        except Exception:
            # Details belong to server diagnostics, never to the API caller.
            return error_response(request, "INTERNAL_ERROR", 500)
        response.headers["X-Request-ID"] = request.state.request_id
        return response

    @application.exception_handler(DomainError)
    async def domain_error(request: Request, exc: DomainError):
        details = (
            {"sensor_ids": exc.sensor_ids} if isinstance(exc, SensorSelectionRequired) else None
        )
        return error_response(
            request, exc.code, exc.status, getattr(exc, "retry_after", None), details=details
        )

    @application.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        return error_response(request, "INVALID_REQUEST", 422)

    @application.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException):
        return error_response(
            request, "UPLOAD_TOO_LARGE" if exc.status_code == 413 else "HTTP_ERROR", exc.status_code
        )

    @application.exception_handler(SQLAlchemyError)
    async def database_error(request: Request, exc: SQLAlchemyError):
        return error_response(request, "DATABASE_UNAVAILABLE", 503)

    def get_service() -> DataService:
        if service is None:
            raise DomainError("DATABASE_NOT_CONFIGURED", 503)
        return service

    def actor(request: Request, authorization: str | None = Header(default=None)) -> Actor:
        if not authorization or not authorization.startswith("Bearer "):
            raise DomainError("UNAUTHENTICATED", 401)
        identity = get_service().authenticate(authorization[7:])
        retry = limiter.check(
            identity.workspace_id + ":" + identity.digest,
            "read" if request.method in {"GET", "HEAD"} else "write",
        )
        if retry:
            raise RateLimited(retry)
        return identity

    def admin(identity: Actor = Depends(actor)) -> Actor:
        DataService.require(identity, ("admin",))
        return identity

    @application.get("/api/v1/health/live")
    def live() -> dict[str, str]:
        return {"status": "ok", "stage": "d12"}

    @application.get("/api/v1/runtime-config", response_model=RuntimeConfiguration)
    def runtime_config(identity: Actor = Depends(admin)):
        from packages.agent.state import config_version

        return RuntimeConfiguration(
            model_provider=config.model_provider,
            model_test_stub=config.model_test_stub,
            model_config_hash=config_version(config),
            agent_max_cost_microusd=config.agent_max_cost_microusd,
            pricing_configured=config.model_input_usd_per_million is not None
            and config.model_output_usd_per_million is not None,
            price_version=config.model_price_version,
            report_export_max_lines=config.report_export_max_lines,
            report_export_max_bytes=config.report_export_max_bytes,
            read_requests_per_minute=config.api_read_requests_per_minute,
            write_requests_per_minute=config.api_write_requests_per_minute,
        )

    @application.post("/api/v1/datasets", response_model=DatasetResponse, status_code=201)
    def create_dataset(
        payload: DatasetCreate,
        identity: Actor = Depends(admin),
        key: str = Header(alias="Idempotency-Key"),
    ):
        return get_service().create_dataset(identity, payload.model_dump(mode="json"), key)

    @application.post(
        "/api/v1/datasets/{dataset_id}/replays", response_model=ReplayStatus, status_code=202
    )
    def create_replay(
        dataset_id: UUID,
        payload: ReplayCreate,
        identity: Actor = Depends(actor),
        key: str = Header(alias="Idempotency-Key"),
    ):
        return ReplayService(get_service()).create(identity, str(dataset_id), payload, key)

    @application.get("/api/v1/replays/{job_id}", response_model=ReplayStatus)
    def replay_status(job_id: UUID, identity: Actor = Depends(actor)):
        return ReplayService(get_service()).status(identity, str(job_id))

    @application.get("/api/v1/datasets", response_model=DatasetPage)
    def list_datasets(
        request: Request,
        limit: int = 50,
        cursor: str | None = None,
        identity: Actor = Depends(actor),
    ):
        return {
            **get_service().dataset_page(identity, limit, cursor),
            "request_id": request.state.request_id,
        }

    @application.post("/api/v1/datasets/{dataset_id}/context", response_model=ContextResponse)
    def configure_context(
        dataset_id: UUID,
        payload: DatasetContext,
        identity: Actor = Depends(admin),
        key: str = Header(alias="Idempotency-Key"),
    ):
        return ContextService(get_service()).configure(identity, str(dataset_id), payload, key)

    @application.post("/api/v1/imports", response_model=ImportResponse, status_code=202)
    def upload(
        file: UploadFile = File(),
        dataset_id: UUID = Form(),
        source_type: str = Form(),
        sensor_id: str | None = Form(default=None),
        timezone: str = Form("UTC"),
        identity: Actor = Depends(admin),
        key: str = Header(alias="Idempotency-Key"),
    ):
        def chunks() -> Iterator[bytes]:
            while data := file.file.read(65536):
                yield data

        try:
            return get_service().stage_chunks(
                identity, str(dataset_id), source_type, sensor_id, timezone, chunks(), key
            )
        finally:
            file.file.close()

    @application.get("/api/v1/imports/{batch_id}", response_model=ImportStatus)
    def import_status(batch_id: UUID, identity: Actor = Depends(actor)):
        return get_service().get_batch(identity, str(batch_id))

    @application.get("/api/v1/events", response_model=EventPage)
    def events(
        request: Request,
        dataset_id: UUID,
        session_id: UUID,
        limit: int = Query(default=50, ge=1, le=100),
        cursor: str | None = None,
        identity: Actor = Depends(actor),
    ):
        return get_service().list_events(
            identity, str(dataset_id), str(session_id), limit, cursor
        ) | {"request_id": request.state.request_id}

    @application.get("/api/v1/events/{event_id}", response_model=NormalizedEvent)
    def event(event_id: str, identity: Actor = Depends(actor)):
        return get_service().get_event(identity, event_id)

    @application.get("/api/v1/overview")
    def overview(dataset_id: UUID, session_id: UUID, identity: Actor = Depends(actor)):
        return get_service().overview(identity, str(dataset_id), str(session_id))

    @application.get("/api/v1/jobs/{job_id}")
    def job_status(job_id: UUID, identity: Actor = Depends(actor)):
        DataService.require(identity, ("analyst", "admin"))
        return Queue(get_service().db, config).status(identity, str(job_id))

    @application.post("/api/v1/jobs/{job_id}/cancel", status_code=202)
    def cancel_job(job_id: UUID, identity: Actor = Depends(actor)):
        queue = Queue(get_service().db, config)
        queue.cancel(identity, str(job_id))
        return queue.status(identity, str(job_id))

    @application.get("/api/v1/incidents", response_model=IncidentPage)
    def incidents(
        request: Request,
        dataset_id: UUID,
        session_id: UUID,
        limit: int = 50,
        cursor: str | None = None,
        identity: Actor = Depends(actor),
    ):
        return {
            **AnalysisService(get_service()).incident_page(
                identity, str(dataset_id), str(session_id), limit, cursor
            ),
            "request_id": request.state.request_id,
        }

    @application.get("/api/v1/incidents/{incident_id}")
    def incident_detail(incident_id: UUID, identity: Actor = Depends(actor)):
        return AnalysisService(get_service()).get_incident(identity, str(incident_id))

    @application.post(
        "/api/v1/incidents/{incident_id}/investigations",
        response_model=RunResponse,
        status_code=202,
    )
    def investigate(
        incident_id: UUID,
        payload: InvestigationCreate,
        identity: Actor = Depends(actor),
        key: str = Header(alias="Idempotency-Key"),
    ):
        return AnalysisService(get_service()).create_run(
            identity, str(incident_id), key, payload.mode, payload.budget
        )

    @application.get("/api/v1/investigations/{run_id}", response_model=RunStatus)
    def run_status(run_id: UUID, identity: Actor = Depends(actor)):
        return AnalysisService(get_service()).get_run(identity, str(run_id))

    @application.get("/api/v1/investigations/{run_id}/tool-calls", response_model=AgentActionPage)
    def agent_actions(
        request: Request,
        run_id: UUID,
        limit: int = 50,
        cursor: str | None = None,
        identity: Actor = Depends(actor),
    ):
        return {
            **AnalysisService(get_service()).tool_call_page(identity, str(run_id), limit, cursor),
            "request_id": request.state.request_id,
        }

    @application.get(
        "/api/v1/investigations/{run_id}/transitions", response_model=AgentTransitionPage
    )
    def agent_transitions(
        request: Request,
        run_id: UUID,
        limit: int = 50,
        cursor: str | None = None,
        identity: Actor = Depends(actor),
    ):
        return {
            **AnalysisService(get_service()).transition_page(identity, str(run_id), limit, cursor),
            "request_id": request.state.request_id,
        }

    @application.post("/api/v1/investigations/{run_id}/cancel", status_code=202)
    def cancel_run(run_id: UUID, identity: Actor = Depends(actor)):
        service = get_service()
        run = AnalysisService(service).get_run(identity, str(run_id))
        Queue(service.db, config).cancel(identity, run["job_id"])
        return AnalysisService(service).get_run(identity, str(run_id))

    @application.get("/api/v1/investigations/{run_id}/graph", response_model=GraphResponse)
    def graph(
        run_id: UUID,
        limit: int = 50,
        cursor: str | None = None,
        focus_entity: str | None = None,
        identity: Actor = Depends(actor),
    ):
        return AnalysisService(get_service()).graph_page(
            identity, str(run_id), limit, cursor, focus_entity
        )

    @application.get("/api/v1/investigations/{run_id}/timeline", response_model=EventPage)
    def timeline(
        request: Request,
        run_id: UUID,
        limit: int = 50,
        cursor: str | None = None,
        identity: Actor = Depends(actor),
    ):
        return {
            **AnalysisService(get_service()).timeline_page(identity, str(run_id), limit, cursor),
            "request_id": request.state.request_id,
        }

    @application.get("/api/v1/investigations/{run_id}/paths", response_model=PathAnalysis)
    def paths(run_id: UUID, identity: Actor = Depends(actor)):
        return AnalysisService(get_service()).get_paths(identity, str(run_id))

    @application.get("/api/v1/reports/{report_id}", response_model=Report)
    def report(
        report_id: UUID,
        mode: Literal["original", "cached"] = "original",
        identity: Actor = Depends(actor),
    ):
        if mode == "cached":
            return ReportService(get_service()).cached(identity, str(report_id))
        return AnalysisService(get_service()).get_report(identity, str(report_id))

    @application.get("/api/v1/incidents/{incident_id}/reports", response_model=ReportPage)
    def report_history(
        incident_id: UUID,
        request: Request,
        limit: int = 50,
        cursor: str | None = None,
        identity: Actor = Depends(actor),
    ):
        return {
            **ReportService(get_service()).history(identity, str(incident_id), limit, cursor),
            "request_id": request.state.request_id,
        }

    @application.post(
        "/api/v1/reports/{report_id}/reviews", response_model=ReviewRecord, status_code=201
    )
    def review_report(
        report_id: UUID,
        payload: ReviewCreate,
        identity: Actor = Depends(actor),
        key: str = Header(alias="Idempotency-Key"),
    ):
        return ReportService(get_service()).review(identity, str(report_id), payload, key)

    @application.get("/api/v1/reports/{report_id}/reviews", response_model=ReviewPage)
    def report_reviews(
        report_id: UUID,
        request: Request,
        limit: int = 50,
        cursor: str | None = None,
        identity: Actor = Depends(actor),
    ):
        return {
            **ReportService(get_service()).reviews(identity, str(report_id), limit, cursor),
            "request_id": request.state.request_id,
        }

    @application.get("/api/v1/reports/{report_id}/export")
    def export_report(
        report_id: UUID, format: Literal["json", "html"] = "html", identity: Actor = Depends(actor)
    ):
        raw = ReportService(get_service()).export(identity, str(report_id), format)
        return Response(
            raw,
            media_type="application/json" if format == "json" else "text/html",
            headers={
                "Content-Disposition": f'attachment; filename="report-{report_id}.{format}"',
                "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; "
                "base-uri 'none'; form-action 'none'; sandbox",
                "X-Content-Type-Options": "nosniff",
                "Cache-Control": "no-store",
            },
        )

    @application.get("/api/v1/raw-objects/{object_id}/download")
    def download_object(object_id: UUID, identity: Actor = Depends(actor)):
        raw, extension = ReportService(get_service()).raw_download_with_extension(
            identity, str(object_id)
        )
        return Response(
            raw,
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": f'attachment; filename="object-{object_id}.{extension}"',
                "X-Content-Type-Options": "nosniff",
                "Cache-Control": "no-store",
            },
        )

    @application.get("/api/v1/evidence/{event_id}", response_model=EvidenceResponse)
    def evidence(
        event_id: str,
        snapshot_id: UUID | None = None,
        cursor: str | None = None,
        packet_scope: str | None = Query(default=None, max_length=512),
        identity: Actor = Depends(actor),
    ):
        analysis = AnalysisService(get_service())
        if packet_scope is not None and snapshot_id is None and cursor is None:
            return analysis.packet_evidence(identity, event_id, packet_scope)
        if snapshot_id is not None and packet_scope is None:
            return analysis.evidence(identity, event_id, str(snapshot_id), cursor)
        raise DomainError("INVALID_REQUEST", 422)

    mount_web(application, config.web_dist)
    return application


app = create_app()


def main() -> None:
    import uvicorn

    settings = Settings()
    uvicorn.run(create_app(settings), host=settings.app_bind, port=settings.app_port)


if __name__ == "__main__":
    main()
