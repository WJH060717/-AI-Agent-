import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest

from packages.agent.model import CompatibleModel, ModelError, parse_payload
from packages.config import Settings


def test_model_requires_exact_json_not_prose_and_accepts_two_decision_types():
    assert parse_payload('{"action":"draft","reason_summary":"enough"}', "plan").action == "draft"
    for content in (
        '```json\n{"action":"draft"}\n```',
        '{"action":"shell"}',
        '{"claims":[],"workspace_id":"x"}',
    ):
        with pytest.raises(ModelError):
            parse_payload(content, "plan" if "action" in content else "draft")


def test_real_compatible_http_request_usage_limits_and_no_redirect_leak():
    captured = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            captured.append((self.path, self.headers.get("Authorization"), body))
            if self.path == "/redirect/chat/completions":
                self.send_response(302)
                self.send_header("Location", "/leak")
                self.end_headers()
                return
            raw = json.dumps(
                {
                    "id": "local-test-response",
                    "choices": [
                        {"message": {"content": '{"action":"draft","reason_summary":"enough"}'}}
                    ],
                    "usage": {"prompt_tokens": 50, "completion_tokens": 20},
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        settings = Settings(
            _env_file=None,
            app_env="test",
            model_provider="compatible",
            model_base_url=f"http://127.0.0.1:{server.server_port}/v1",
            model_name="protocol-test-stub",
            model_api_key="local-dummy",
        )
        model = CompatibleModel(settings)
        request = model.request("plan", {"facts": [], "scope": {"snapshot_id": "fixed"}}, 100)
        result = model.complete(request, "plan", timeout=2)
        assert result.input_tokens == 50 and result.output_tokens == 20
        assert result.value.action == "draft"
        assert captured[0][0] == "/v1/chat/completions"
        assert captured[0][2]["max_tokens"] == 100
        assert "local-dummy" not in json.dumps(captured[0][2])
        settings.model_base_url = f"http://127.0.0.1:{server.server_port}/redirect"
        with pytest.raises(ModelError, match="HTTP"):
            CompatibleModel(settings).complete(request, "plan", timeout=2)
        assert len(captured) == 2
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.parametrize(
    "url",
    [
        "http://external.example/v1",
        "https://user:secret@example.com/v1",
        "https://example.com/v1?token=x",
        "file:///tmp/model",
    ],
)
def test_model_endpoint_is_explicit_safe_configuration(url):
    with pytest.raises(ValueError):
        Settings(
            _env_file=None,
            model_provider="compatible",
            model_name="m",
            model_api_key="dummy",
            model_base_url=url,
        )
