"""Malformed API inputs must be client errors; Unicode passwords must work."""
import copy
import json
import threading
import time
from http.client import HTTPConnection

import pytest

from core import web_server as web


@pytest.fixture
def api(monkeypatch):
    original_tokens = dict(web.AUTH_TOKENS)
    state = {"web_password": web._hash_password("fixture-password")}
    monkeypatch.setattr(web, "load_data", lambda: copy.deepcopy(state))
    monkeypatch.setattr(web, "atomic_update", lambda update: update(state))
    token = "input-validation-test-only"
    web.AUTH_TOKENS[token] = time.time() + 60
    server = web.ThreadedHTTPServer(("127.0.0.1", 0), web.LDWebRequestHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def request(path, body, authenticated=False):
        headers = {"Content-Type": "application/json"}
        if authenticated:
            headers["Authorization"] = "Bearer " + token
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        try:
            connection.request("POST", path, json.dumps(body), headers)
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    try:
        yield request, state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        web.AUTH_TOKENS.clear()
        web.AUTH_TOKENS.update(original_tokens)


@pytest.mark.parametrize("body", [[], None, "text", 42, True])
def test_non_object_body_is_rejected(api, body):
    request, _ = api
    status, result = request("/api/login", body)
    assert status == 400
    assert "error" in result


@pytest.mark.parametrize("password", [None, 12345678, [], {"nested": "value"}])
def test_password_fields_require_strings(api, password):
    request, state = api
    original_hash = state["web_password"]
    assert request("/api/login", {"password": password})[0] == 400
    assert request("/api/password", {"new_password": password}, authenticated=True)[0] == 400
    assert state["web_password"] == original_hash


def test_unicode_legacy_password_is_migrated(api):
    request, state = api
    password = "رمز-آزمایشی-۱۲۳۴"
    state["web_password"] = password
    assert request("/api/login", {"password": password})[0] == 200
    assert state["web_password"].startswith("pbkdf2_sha256$")
    assert web._verify_password(password, state["web_password"])


def test_unicode_bootstrap_password(api, monkeypatch):
    request, state = api
    password = "رمز-آغازین-۱۲۳۴"
    state.clear()
    monkeypatch.setenv("VX_LB_WEB_PASSWORD", password)
    assert request("/api/login", {"password": password})[0] == 200
    assert web._verify_password(password, state["web_password"])


@pytest.mark.parametrize("path", ["add", "delete", "test", "cc"])
@pytest.mark.parametrize("server_type", ["typo", None, 42])
def test_invalid_server_role_is_rejected_before_accessing_servers(api, path, server_type, monkeypatch):
    request, _ = api
    def unexpected_access(*args, **kwargs):
        pytest.fail("Invalid server roles must be rejected before accessing the inventory")
    monkeypatch.setattr(web, "get_servers", unexpected_access)
    monkeypatch.setattr(web, "get_pools", unexpected_access)
    status, _ = request("/api/servers/" + path, {"type": server_type}, authenticated=True)
    assert status == 400


@pytest.mark.parametrize("ports", ["443", 443, None])
def test_pool_creation_does_not_split_scalar_ports(api, ports, monkeypatch):
    request, _ = api
    monkeypatch.setattr(web, "transport_busy", lambda: False)
    status, _ = request("/api/pools/create", {
        "name": "production", "kharej_ip": "192.0.2.1", "iran_ips": ["192.0.2.2"],
        "client_ports": ports,
    }, authenticated=True)
    assert status == 400
