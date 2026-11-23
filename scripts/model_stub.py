"""LOCAL PROTOCOL TEST STUB, NOT AN LLM. Only for labelled development/browser tests."""

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread


class ProtocolStub:
    def __init__(self, port=0):
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                if self.path != "/v1/chat/completions":
                    self.send_error(404)
                    return
                body = json.loads(self.rfile.read(min(int(self.headers["Content-Length"]), 65536)))
                request = json.loads(body["messages"][-1]["content"])
                context = request["untrusted_context"]
                if request["phase"] == "plan":
                    investigation = context.get("investigation", {})
                    counter = [
                        eid
                        for h in investigation.get("hypotheses", [])
                        for eid in h.get("counter_event_ids", [])
                    ]
                    missing_context = next(
                        (
                            g
                            for g in investigation.get("gaps", [])
                            if g["code"] == "normal_process_context" and g["asset_id"]
                        ),
                        None,
                    )
                    if context["retrieved_event_ids"]:
                        name, args = (
                            "get_event_evidence",
                            {"event_ids": (counter or context["retrieved_event_ids"])[:1]},
                        )
                    elif missing_context:
                        name, args = (
                            "get_asset_timeline",
                            {"asset_id": missing_context["asset_id"], "limit": 100},
                        )
                    else:
                        name, args = "search_events", {"types": ["host.process"], "limit": 10}
                    content = {
                        "action": "call_tool",
                        "tool": name,
                        "arguments": args,
                        "reason_summary": "Protocol stub requests bounded host evidence",
                        "expected_evidence": "Snapshot process context",
                    }
                else:
                    content = {
                        "claims": [
                            {
                                "kind": "unknown",
                                "statement": "本次使用本地协议测试桩，未运行真实LLM。",
                                "evidence_ids": [],
                            }
                        ],
                        "alternatives": [],
                        "gaps": [],
                    }
                raw = json.dumps(
                    {
                        "id": "local-protocol-stub",
                        "choices": [{"message": {"content": json.dumps(content)}}],
                        "usage": {
                            "prompt_tokens": min(1000, len(json.dumps(body)) // 4),
                            "completion_tokens": min(100, body["max_tokens"]),
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

        self.server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        self.thread = Thread(target=self.server.serve_forever, daemon=True)

    def start(self):
        self.thread.start()
        return self.server.server_port

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=18081)
    args = parser.parse_args()
    stub = ProtocolStub(args.port)
    print(f"LOCAL TEST STUB, NOT AN LLM: http://127.0.0.1:{stub.start()}/v1", flush=True)
    try:
        stub.thread.join()
    except KeyboardInterrupt:
        stub.stop()
