import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from packages.agent.model import CompatibleModel, ModelError
from packages.agent.runtime import AgentRuntime
from packages.config import Settings
from packages.storage.analysis import AnalysisService
from packages.storage.queue import LeaseLost, Queue
from tests.integration.d6_helpers import ModelStub, pending


def test_slow_drip_http_obeys_total_deadline_and_transport_can_be_cancelled():
    entered, stopped = threading.Event(), threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            self.send_response(200)
            self.send_header("Content-Length", "200")
            self.end_headers()
            entered.set()
            try:
                for _ in range(200):
                    self.wfile.write(b" ")
                    self.wfile.flush()
                    time.sleep(0.01)
            except OSError:
                pass
            finally:
                stopped.set()

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    settings = Settings(
        _env_file=None,
        app_env="test",
        model_provider="compatible",
        model_base_url=f"http://127.0.0.1:{server.server_port}/v1",
        model_name="test",
        model_api_key="dummy",
    )
    try:
        model = CompatibleModel(settings)
        request = model.request("plan", {}, 100)
        start = time.monotonic()
        with pytest.raises(ModelError):
            model.complete(request, "plan", timeout=0.15)
        assert time.monotonic() - start < 1
        entered.clear()
        stopped.clear()
        model = CompatibleModel(settings)
        errors = []

        def call():
            try:
                model.complete(request, "plan", timeout=3)
            except ModelError as exc:
                errors.append(str(exc))

        worker = threading.Thread(target=call)
        worker.start()
        assert entered.wait(3)
        model.cancel_current()
        worker.join(timeout=1)
        assert not worker.is_alive() and stopped.wait(0.5) and errors

        # A superseded worker must also close the transport, not just discard its result.
        entered.clear()
        stopped.clear()
        lost = threading.Event()
        runtime = AgentRuntime.__new__(AgentRuntime)
        runtime.model = CompatibleModel(settings)

        def guard():
            if lost.is_set():
                raise LeaseLost("test lease superseded")

        runtime.guard = guard
        lease_errors = []

        def leased_call():
            try:
                runtime.bounded(lambda: runtime.model.complete(request, "plan", timeout=3), 3)
            except LeaseLost as exc:
                lease_errors.append(str(exc))

        worker = threading.Thread(target=leased_call)
        worker.start()
        assert entered.wait(3)
        lost.set()
        worker.join(timeout=1.5)
        assert not worker.is_alive() and stopped.wait(0.5) and lease_errors
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_resume_with_changed_model_configuration_degrades_before_new_endpoint(context):
    settings, db, service, _, _ = context
    with ModelStub() as first, ModelStub() as changed:
        first.configure(settings)
        actor, _, run = pending(context)
        queue = Queue(db, settings)
        lease = queue.claim("model-config")
        runtime = AgentRuntime(service, queue, lease)
        runtime.step()
        runtime.step()
        assert runtime.phase == "planning"
        changed.configure(settings)
        settings.model_name = "changed-model"
        outcome = AgentRuntime(service, queue, lease).run()
        assert (
            outcome["terminal"] == "partial"
            and outcome["stop_reason"] == "MODEL_CONFIGURATION_CHANGED"
        )
        assert not first.requests and not changed.requests
        # Publication must not relabel the run with the newly configured model.
        analysis = AnalysisService(service)
        analysis.process(lease, queue)
        status = analysis.get_run(actor, run["run_id"])
        report = analysis.get_report(actor, status["report_id"])
        assert report["provenance"]["model"] == "protocol-test-stub"


def test_model_context_retains_bound_incident_and_tool_continuation_metadata(context):
    settings, _, service, _, _ = context
    with ModelStub("paged") as stub:
        stub.configure(settings)
        actor, _, run = pending(context)
        service.process_one()
    state = AnalysisService(service).get_run(actor, run["run_id"])
    assert state["retrieved_count"] == 2 and state["budget_used"]["tool_calls"] == 2, (
        state["stop_reason"],
        state["budget_used"],
        state["cache_hits"],
        [
            (
                r["phase"],
                len(r["untrusted_context"]["tool_results"]),
                [bool(t["next_cursor"]) for t in r["untrusted_context"]["tool_results"]],
            )
            for r in stub.requests
        ],
    )
    later = stub.requests[1]["untrusted_context"]
    assert later["incident_id"]
    page = later["tool_results"][0]
    assert page["next_cursor"] and page["truncated"] and page["coverage"]
    assert "warnings" in page and page["arguments"]["limit"] == 1


def test_invalid_arguments_are_redacted_before_any_checkpoint_or_action(context):
    import json

    from sqlalchemy import select

    from packages.storage import schema_v5 as t

    settings, db, service, _, _ = context
    with ModelStub("invalid_parameters") as stub:
        stub.configure(settings)
        actor, _, run = pending(context)
        service.process_one()
    with db.engine.connect() as conn:
        actions = (
            conn.execute(
                select(t.agent_actions).where(
                    t.agent_actions.c.workspace_id == actor.workspace_id,
                    t.agent_actions.c.run_id == run["run_id"],
                )
            )
            .mappings()
            .all()
        )
        checkpoint = conn.execute(
            select(t.agent_states.c.payload).where(t.agent_states.c.id == run["run_id"])
        ).scalar_one()
    assert "private-marker" not in json.dumps([dict(a) for a in actions]) + json.dumps(checkpoint)
