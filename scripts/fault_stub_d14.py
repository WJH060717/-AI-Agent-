"""Loopback fault injection: disconnected transport or nonexistent model citation."""

import hmac
import json
import secrets
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread


class FaultStub:
    def __init__(self) -> None:
        self.mode = "disconnect"
        self.control_token = secrets.token_urlsafe(32)
        self.requests: list[dict] = []
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                if self.path.startswith("/control/"):
                    # Drain the bounded body before replying: closing a Windows socket
                    # with unread request bytes can reset it and discard the response.
                    try:
                        length = int(self.headers.get("Content-Length", "0"))
                    except ValueError:
                        self.send_error(400)
                        return
                    if not 0 <= length <= 4096:
                        self.send_error(413)
                        return
                    if len(self.rfile.read(length)) != length:
                        self.send_error(400)
                        return
                    if not hmac.compare_digest(
                        self.headers.get("X-D14-Control", ""), owner.control_token
                    ):
                        self.send_error(403)
                        return
                    if self.path != "/control/bad-reference":
                        self.send_error(404)
                        return
                    owner.mode = "bad-reference"
                    self.send_response(200)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if self.path != "/v1/chat/completions":
                    self.send_error(404)
                    return
                length = min(int(self.headers.get("Content-Length", "0")), 100_000)
                body = json.loads(self.rfile.read(length))
                request = json.loads(body["messages"][-1]["content"])
                phase = request["phase"]
                owner.requests.append({"mode": owner.mode, "phase": phase})
                if owner.mode == "disconnect":
                    self.connection.shutdown(socket.SHUT_RDWR)
                    self.connection.close()
                    return
                content = (
                    {"action": "draft", "reason_summary": "LOCAL FAULT INJECTION, NOT LLM"}
                    if phase == "plan"
                    else {
                        "claims": [
                            {
                                "kind": "observed",
                                "statement": "FAULT INJECTION: unsupported claim",
                                "fact_predicate": {
                                    "name": "auth_outcome",
                                    "values": {"outcome": "success"},
                                },
                                "evidence_ids": ["f" * 64],
                            }
                        ],
                        "alternatives": [],
                        "gaps": [],
                    }
                )
                raw = json.dumps(
                    {
                        "id": "d14-local-fault-not-llm",
                        "choices": [{"message": {"content": json.dumps(content)}}],
                        "usage": {"prompt_tokens": 1, "completion_tokens": 1},
                    }
                ).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                try:
                    self.wfile.write(raw)
                except OSError:
                    pass

            def log_message(self, *args) -> None:
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.origin = f"http://127.0.0.1:{self.server.server_port}"

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
