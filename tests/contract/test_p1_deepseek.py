"""Optional thinking control crosses the real HTTP boundary without exposing secrets."""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest

from packages.agent.cache import report_cache_key
from packages.agent.model import CompatibleModel
from packages.agent.state import config_version
from packages.config import Settings
from scripts.p1_acceptance import model_readiness


def test_explicit_non_thinking_request_reaches_transport_and_parses_json():
    captured = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            captured.append(payload)
            response = json.dumps(
                {
                    "id": "local-compatibility-check",
                    "choices": [
                        {"message": {"content": '{"action":"draft","reason_summary":"done"}'}}
                    ],
                    "usage": {"prompt_tokens": 30, "completion_tokens": 15},
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        settings = Settings(
            _env_file=None,
            model_provider="compatible",
            model_base_url=f"http://127.0.0.1:{server.server_port}",
            model_name="local-test-only",
            model_api_key="local-canary-not-a-provider-key",
            model_thinking="disabled",
        )
        client = CompatibleModel(settings)
        result = client.complete(client.request("plan", {"facts": []}, 100), "plan", timeout=3)
        assert result.value.action == "draft"
        assert captured[0]["thinking"] == {"type": "disabled"}
        assert captured[0]["response_format"] == {"type": "json_object"}
        assert "local-canary" not in json.dumps(captured[0])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_default_provider_request_omits_thinking_control():
    client = CompatibleModel(Settings(_env_file=None))
    assert "thinking" not in json.loads(client.request("plan", {}, 50))


@pytest.mark.parametrize("value", ["enabled", "automatic", {}, True])
def test_unsupported_thinking_control_is_rejected(value):
    with pytest.raises(ValueError):
        Settings(_env_file=None, model_thinking=value)


def test_thinking_control_invalidates_resume_and_report_cache_identity():
    default = Settings(_env_file=None)
    disabled = Settings(_env_file=None, model_thinking="disabled")
    snapshot = {
        "workspace_id": "w",
        "id": "s",
        "incident_id": "i",
        "scope": {"session_id": "session"},
        "event_ids": ["e"],
    }
    assert config_version(default) != config_version(disabled)
    assert report_cache_key(default, snapshot, [], [], {}) != report_cache_key(
        disabled, snapshot, [], [], {}
    )


def test_private_readiness_accepts_thinking_without_disclosing_private_values(tmp_path):
    path = tmp_path / "private.json"
    path.write_text(
        json.dumps(
            {
                "model_provider": "compatible",
                "model_base_url": "https://approved.invalid",
                "model_name": "test-model",
                "model_api_key": "local-canary-secret",
                "model_thinking": "disabled",
                "model_input_usd_per_million": 0.3,
                "model_output_usd_per_million": 1.2,
                "model_price_version": "test-price",
                "agent_max_cost_microusd": 100000,
            }
        ),
        encoding="utf-8",
    )
    result = model_readiness(path)
    assert result.status == "configuration_ready"
    assert not result.connectivity_verified
    assert "local-canary" not in result.model_dump_json()
