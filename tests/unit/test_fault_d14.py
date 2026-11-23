import http.client
import json
import socket
import urllib.error
import urllib.request

import pytest

from scripts.fault_stub_d14 import FaultStub


def request(server, path, payload, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-D14-Control"] = token
    req = urllib.request.Request(
        server.origin + path, data=json.dumps(payload).encode(), headers=headers
    )
    return urllib.request.urlopen(req, timeout=3)


def test_stub_disconnect_and_scope_of_bad_reference():
    server = FaultStub()
    server.start()
    body = {"messages": [{"content": json.dumps({"phase": "plan"})}]}
    try:
        with pytest.raises((http.client.RemoteDisconnected, urllib.error.URLError)):
            request(server, "/v1/chat/completions", body)
        with request(server, "/control/bad-reference", {}, server.control_token) as response:
            assert response.status == 200
        with request(server, "/v1/chat/completions", body) as response:
            value = json.load(response)
            assert json.loads(value["choices"][0]["message"]["content"])["action"] == "draft"
        body["messages"][0]["content"] = json.dumps({"phase": "draft"})
        with request(server, "/v1/chat/completions", body) as response:
            value = json.loads(json.load(response)["choices"][0]["message"]["content"])
            assert value["claims"][0]["evidence_ids"] == ["f" * 64]
    finally:
        server.stop()


def test_stub_control_requires_private_token():
    server = FaultStub()
    server.start()
    try:
        with pytest.raises(urllib.error.HTTPError) as error:
            request(server, "/control/bad-reference", {}, "incorrect")
        assert error.value.code == 403
        assert server.mode == "disconnect"
    finally:
        server.stop()


def test_control_waits_for_complete_body_before_success():
    server = FaultStub()
    server.start()
    try:
        with socket.create_connection(server.server.server_address, timeout=2) as connection:
            connection.settimeout(0.1)
            connection.sendall(
                (
                    "POST /control/bad-reference HTTP/1.0\r\n"
                    f"X-D14-Control: {server.control_token}\r\nContent-Length: 2\r\n\r\n"
                ).encode()
            )
            with pytest.raises(TimeoutError):
                connection.recv(1024)
            assert server.mode == "disconnect"
            connection.sendall(b"{}")
            connection.settimeout(2)
            assert b"200 OK" in connection.recv(1024)
            assert server.mode == "bad-reference"
    finally:
        server.stop()
