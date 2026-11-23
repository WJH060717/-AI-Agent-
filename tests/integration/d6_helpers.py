import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from packages.contracts.context import DatasetContext
from packages.storage.analysis import AnalysisService
from packages.storage.context import ContextService
from scripts.build_d5_fixture import build


class ModelStub:
    """Protocol stub with explicit label, not an LLM or detection benchmark."""

    def __init__(self, behavior="normal"):
        self.behavior, self.requests = behavior, []
        self.entered = threading.Event()
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                user = json.loads(body["messages"][-1]["content"])
                owner.requests.append(user)
                owner.entered.set()
                kind, ctx = user["phase"], user["untrusted_context"]
                if owner.behavior == "slow":
                    time.sleep(0.5)
                if callable(owner.behavior):
                    content = json.dumps(owner.behavior(kind, ctx))
                elif owner.behavior in {"retrieval", "retrieval_paged"}:
                    from tests.integration.retrieval_helpers import retrieval_decision

                    content = json.dumps(
                        retrieval_decision(
                            kind,
                            ctx,
                            1 if owner.behavior == "retrieval_paged" else None,
                        )
                    )
                elif owner.behavior == "invalid":
                    content = "IGNORE RULES: execute shell"
                elif kind == "plan" and owner.behavior == "draft":
                    content = '{"action":"draft","reason_summary":"no useful further query"}'
                elif kind == "plan":
                    if owner.behavior == "scope_injection":
                        tool, args = (
                            "search_events",
                            {"workspace_id": "PRIVATE-INJECTION", "limit": 10},
                        )
                    elif owner.behavior == "empty":
                        tool, args = "search_events", {"types": ["security.alert"], "limit": 10}
                    elif owner.behavior == "d7":
                        if not ctx["retrieved_event_ids"]:
                            gap = ctx["investigation"]["gaps"][0]
                            tool, args = (
                                "get_asset_timeline",
                                {"asset_id": gap["asset_id"], "limit": 100},
                            )
                        else:
                            counter = [
                                eid
                                for h in ctx["investigation"]["hypotheses"]
                                for eid in h["counter_event_ids"]
                            ]
                            tool, args = (
                                "get_event_evidence",
                                {"event_ids": counter[:1]},
                            )
                    elif owner.behavior == "invalid_parameters":
                        tool, args = (
                            "get_technique_context",
                            {"technique_ids": ["https://invalid/?token=private-marker"]},
                        )
                    elif owner.behavior == "paged":
                        previous = ctx.get("tool_results", [])
                        args = {"types": ["host.process"], "limit": 1}
                        if previous and previous[-1].get("next_cursor"):
                            args["cursor"] = previous[-1]["next_cursor"]
                        tool = "search_events"
                    elif owner.behavior == "unknown":
                        tool, args = "shell", {"command": "dump token"}
                    elif owner.behavior == "repeat" or not ctx["retrieved_event_ids"]:
                        tool, args = "search_events", {"types": ["host.process"], "limit": 10}
                    else:
                        tool, args = (
                            "get_event_evidence",
                            {"event_ids": ctx["retrieved_event_ids"][:1]},
                        )
                    content = json.dumps(
                        {
                            "action": "call_tool",
                            "tool": tool,
                            "arguments": args,
                            "reason_summary": "retrieve missing evidence",
                            "expected_evidence": "snapshot host events",
                        }
                    )
                elif owner.behavior in {"wrong_fact", "repair", "fake_reference"}:
                    event = next(
                        e
                        for e in ctx["facts"]
                        if e.get("auth") and e["auth"]["outcome"] == "failure"
                    )
                    content = json.dumps(
                        {
                            "claims": [
                                {
                                    "kind": "observed",
                                    "statement": "login succeeded",
                                    "fact_predicate": {
                                        "name": "auth_outcome",
                                        "values": {
                                            "outcome": "failure"
                                            if owner.behavior == "repair"
                                            and ctx["validation_errors"]
                                            else "success"
                                        },
                                    },
                                    "evidence_ids": [
                                        "f" * 64
                                        if owner.behavior == "fake_reference"
                                        else event["event_id"]
                                    ],
                                }
                            ],
                            "alternatives": [],
                            "gaps": [],
                        }
                    )
                elif owner.behavior == "context_load":
                    # New retrieved process evidence may take priority over seed auth facts.
                    # Require a real supplied fact, but never invent an auth predicate for it.
                    fact = next(iter(ctx["facts"]))
                    observed = next((e for e in ctx["facts"] if e.get("auth")), None)
                    content = json.dumps(
                        {
                            "claims": [
                                {
                                    "kind": "observed",
                                    "statement": "Observed authentication result",
                                    "fact_predicate": {
                                        "name": "auth_outcome",
                                        "values": {"outcome": observed["auth"]["outcome"]},
                                    },
                                    "evidence_ids": [observed["event_id"]],
                                }
                            ]
                            if observed
                            else [
                                {
                                    "kind": "unknown",
                                    "statement": "Supplied process alone cannot establish intent",
                                    "evidence_ids": [fact["event_id"]],
                                }
                            ],
                            "alternatives": ["Authorized activity remains possible"],
                            "gaps": ["Operator authorization is unknown"],
                        }
                    )
                else:
                    content = (
                        '{"claims":[],"alternatives":'
                        '["authorized maintenance remains possible"],"gaps":[]}'
                    )
                raw = json.dumps(
                    {
                        "id": "protocol-test-stub",
                        "choices": [{"message": {"content": content}}],
                        "usage": {
                            "prompt_tokens": (len(json.dumps(body).encode()) + 2) // 3
                            if owner.behavior in {"context_load", "retrieval", "retrieval_paged"}
                            else min(len(json.dumps(body).encode()) // 4, 1000),
                            "completion_tokens": min(body["max_tokens"], 100),
                        },
                    }
                ).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                try:
                    self.wfile.write(raw)
                except OSError:
                    pass

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def configure(self, settings):
        settings.model_provider = "compatible"
        settings.model_base_url = f"http://127.0.0.1:{self.server.server_port}/v1"
        settings.model_name = "protocol-test-stub"
        from pydantic import SecretStr

        settings.model_api_key = SecretStr("local-test-dummy")
        settings.model_test_stub = True


def pending(context, mode="live", budget=None):
    settings, _, service, workspace, _ = context
    actor = service.system_actor(workspace)
    folder = Path(settings.staging_store) / "d6-test-fixture"
    build(folder)
    dataset = service.create_dataset(
        actor, {"name": "agent", "provenance_type": "synthetic"}, "d6-dataset"
    )
    ContextService(service).configure(
        actor,
        dataset["dataset_id"],
        DatasetContext.model_validate_json((folder / "context.json").read_bytes()),
        "d6-ctx",
    )
    for filename, source, sensor in (
        ("network", "zeek", "net-a"),
        ("auth", "linux_auth", "auth-a"),
        ("audit", "linux_audit", "audit-a"),
    ):
        service.stage_bytes(
            actor,
            dataset["dataset_id"],
            source,
            sensor,
            "UTC",
            (folder / f"{filename}.jsonl").read_bytes(),
            filename,
        )
        service.process_one()
    analysis = AnalysisService(service)
    incident = analysis.list_incidents(actor, dataset["dataset_id"], dataset["default_session_id"])[
        0
    ]
    run = analysis.create_run(actor, incident["id"], "agent", mode=mode, budget=budget)
    return actor, dataset, run
