"""Security-boundary tests for optional audit forwarding and redaction."""
import asyncio
import json
import os
from pathlib import Path
import tempfile
import socket
import unittest
from unittest.mock import patch

import httpx
from starlette.testclient import TestClient
from starlette.applications import Starlette
from starlette.responses import StreamingResponse
from starlette.routing import Route, WebSocketRoute
import uvicorn

from audit_proxy import AuditLog, create_app, inspect_response, load_clients, request_details, safe_url

CLIENT_TOKEN = "test-client-credential-" + "a" * 32
UPSTREAM_TOKEN = "test-upstream-credential-" + "b" * 32


class RedactionTests(unittest.TestCase):
    def test_urls_drop_credentials_queries_and_fragments(self):
        self.assertEqual(safe_url("https://person:password@example.com:8443/account/a?token=secret#private"),
                         "https://example.com:8443/account/a")
        self.assertEqual(safe_url("https://[::1]:8443/a?q=secret"), "https://[::1]:8443/a")
        for url in ["data:text/plain,password", "javascript:secret()", "file:///private", "https://x:bad/a", None]:
            self.assertIsNone(safe_url(url))

    def test_tool_code_forms_and_client_info_are_not_serialized(self):
        payload = {"method": "tools/call", "params": {"name": "browser_actions", "arguments": {
            "session_id": "agent-1", "actions": [{"password": "form-secret"}], "expression": "code-secret",
            "cookies": [{"value": "cookie-secret"}], "extra_headers": {"Authorization": "header-secret"}}}}
        self.assertEqual(request_details(payload), {"rpc_method": "tools/call", "tool": "browser_actions", "browser_session": "agent-1"})
        self.assertEqual(request_details({"method": "initialize", "params": {"clientInfo": {"name": "forged-client"}}}),
                         {"rpc_method": "initialize"})

    def test_rpc_and_tool_failures_are_distinct_from_http_success(self):
        self.assertEqual(inspect_response(b'{"error":{"message":"secret"}}', "application/json"), {"rpc_outcome": "rpc_error"})
        self.assertEqual(inspect_response(b'{"result":{"isError":true,"content":[{"text":"secret"}]}}', "application/json"), {"rpc_outcome": "tool_error"})
        self.assertEqual(inspect_response(b"", "application/json", True)["rpc_outcome"], "uninspected")

    def test_sse_optional_space_multiline_and_malformed_method(self):
        for data in [b'data:{"result":{"isError":true}}\n\n',
                     b'data: {"result":\ndata: {"isError":true}}\n\n']:
            self.assertEqual(inspect_response(data, "text/event-stream"), {"rpc_outcome": "tool_error"})
        for method in [{"secret": "value"}, ["secret"], None]:
            self.assertEqual(request_details({"method": method}), {"rpc_method": "other"})


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.log = Path(self.temp.name) / "events.jsonl"
        self.forwarded = []

    def tearDown(self):
        self.temp.cleanup()

    def client(self, response=None, audit=None):
        async def upstream(request):
            self.forwarded.append(request)
            return response or httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {"isError": False}})
        original = httpx.AsyncClient
        app = create_app(upstream="http://127.0.0.1:8001/mcp", upstream_token=UPSTREAM_TOKEN,
                         clients={"trusted-label": CLIENT_TOKEN}, audit=audit or AuditLog(self.log))
        factory = lambda **kwargs: original(transport=httpx.MockTransport(upstream), **kwargs)
        return app, patch("audit_proxy.httpx.AsyncClient", side_effect=factory)

    def events(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def test_invalid_token_is_not_forwarded_or_logged(self):
        app, mock = self.client()
        with mock, TestClient(app) as client:
            for token in [None, "wrong-secret"]:
                headers = {} if token is None else {"Authorization": "Bearer " + token}
                self.assertEqual(client.post("/mcp", headers=headers, json={"secret": "body-secret"}).status_code, 401)
        self.assertFalse(self.forwarded)
        self.assertNotIn("wrong-secret", self.log.read_text())
        self.assertNotIn("body-secret", self.log.read_text())
        self.assertEqual(len([e for e in self.events() if e["event"] == "denied"]), 2)

    def test_identity_redaction_and_sse_passthrough(self):
        body = b'data: {"jsonrpc":"2.0","id":1,"result":{"structuredContent":{"url":"https://name:pass@example.com/result?secret=value#private"},"content":[{"text":"page-secret"}]}}\n\n'
        response = httpx.Response(200, content=body, headers={"Content-Type": "text/event-stream", "Mcp-Session-Id": "transport-secret"})
        app, mock = self.client(response)
        with mock, TestClient(app) as client:
            result = client.post("/mcp", headers={"Authorization": "Bearer " + CLIENT_TOKEN, "X-Audit-Client": "forged"},
                                 json={"method": "tools/call", "params": {"name": "browser_fetch", "arguments": {
                                     "session_id": "browser-1", "url": "https://user:pass@example.com/start?token=request-secret#private"}}})
            self.assertEqual(result.content, body)
            self.assertEqual(result.headers["Mcp-Session-Id"], "transport-secret")
        self.assertEqual(self.forwarded[0].headers["authorization"], "Bearer " + UPSTREAM_TOKEN)
        self.assertNotIn("x-audit-client", self.forwarded[0].headers)
        text = self.log.read_text()
        for secret in [CLIENT_TOKEN, UPSTREAM_TOKEN, "request-secret", "page-secret", "transport-secret", "forged", "name:pass", "user:pass"]:
            self.assertNotIn(secret, text)
        request = next(e for e in self.events() if e["event"] == "request")
        completion = next(e for e in self.events() if e["event"] == "completed")
        self.assertEqual(request["client"], "trusted-label")
        self.assertEqual(request["requested_url"], "https://example.com/start")
        self.assertEqual(completion["returned_url"], "https://example.com/result")
        self.assertEqual(completion["rpc_outcome"], "success")

    def test_oversized_request_is_rejected_before_forwarding(self):
        app, mock = self.client()
        with mock, TestClient(app) as client:
            self.assertEqual(client.post("/mcp", headers={"Authorization": "Bearer " + CLIENT_TOKEN}, content=b"a" * (1024 * 1024 + 1)).status_code, 413)
        self.assertFalse(self.forwarded)

    def test_storage_failure_prevents_the_action(self):
        class FailingLog:
            async def write(self, event, **fields):
                if event == "request":
                    raise OSError("disk full")
        app, mock = self.client(audit=FailingLog())
        with mock, TestClient(app) as client:
            self.assertEqual(client.post("/mcp", headers={"Authorization": "Bearer " + CLIENT_TOKEN}, json={"method": "tools/list"}).status_code, 503)
        self.assertFalse(self.forwarded)

    def test_notifications_get_delete_and_protocol_headers(self):
        app, mock = self.client(httpx.Response(202, content=b""))
        headers = {"Authorization": "Bearer " + CLIENT_TOKEN,
                   "Mcp-Session-Id": "test-session", "MCP-Protocol-Version": "2025-03-26"}
        with mock, TestClient(app) as client:
            for method in ["GET", "DELETE"]:
                self.assertEqual(client.request(method, "/mcp", headers=headers).status_code, 202)
            self.assertEqual(client.post("/mcp", headers=headers, json={"method": "notifications/initialized"}).status_code, 202)
        self.assertEqual(len(self.forwarded), 3)
        for request in self.forwarded:
            self.assertEqual(request.headers["Mcp-Session-Id"], "test-session")
            self.assertEqual(request.headers["MCP-Protocol-Version"], "2025-03-26")

    def test_log_permissions_rotation_and_symlink_refusal(self):
        audit = AuditLog(self.log, max_bytes=300, backups=2)
        async def writes():
            for _ in range(10):
                await audit.write("probe", label="x" * 100)
        asyncio.run(writes())
        self.assertEqual(os.stat(self.log).st_mode & 0o777, 0o600)
        self.assertLessEqual(len(list(self.log.parent.glob("events.jsonl*"))), 3)
        self.log.unlink()
        target = self.log.parent / "target"
        target.write_text("untouched")
        self.log.symlink_to(target)
        with self.assertRaises(OSError):
            asyncio.run(audit.write("probe"))
        self.assertEqual(target.read_text(), "untouched")

    def test_client_credentials_require_private_file_and_unique_tokens(self):
        path = self.log.parent / "clients.json"
        path.write_text(json.dumps({"version": 1, "clients": {"agent": CLIENT_TOKEN}}))
        path.chmod(0o644)
        with self.assertRaises(ValueError):
            load_clients(path)
        path.chmod(0o600)
        self.assertEqual(load_clients(path), {"agent": CLIENT_TOKEN})
        path.write_text(json.dumps({"version": 1, "clients": {"agent": CLIENT_TOKEN, "other": CLIENT_TOKEN}}))
        with self.assertRaises(ValueError):
            load_clients(path)


class LiveProtocolTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.log = Path(self.temp.name) / "events.jsonl"
        self.servers = []

    async def asyncTearDown(self):
        for server, task, sock in reversed(self.servers):
            server.should_exit = True
            await asyncio.wait_for(task, 4)
            sock.close()
        self.temp.cleanup()

    async def serve(self, app):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        sock.listen()
        server = uvicorn.Server(uvicorn.Config(app, log_level="error", access_log=False,
                                               timeout_graceful_shutdown=1))
        task = asyncio.create_task(server.serve(sockets=[sock]))
        self.servers.append((server, task, sock))
        for _ in range(100):
            if server.started:
                return sock.getsockname()[1]
            await asyncio.sleep(0.01)
        self.fail("Test server did not start")

    def events(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    async def test_real_stream_disconnect_retains_completion(self):
        async def endpoint(request):
            async def messages():
                yield b'data:{"jsonrpc":"2.0","id":1,"result":{}}\n\n'
                while True:
                    await asyncio.sleep(0.05)
                    yield b": heartbeat\n\n"
            return StreamingResponse(messages(), media_type="text/event-stream")
        upstream_port = await self.serve(Starlette(routes=[Route("/mcp", endpoint)]))
        app = create_app(upstream=f"http://127.0.0.1:{upstream_port}/mcp", upstream_token=UPSTREAM_TOKEN,
                         clients={"agent": CLIENT_TOKEN}, audit=AuditLog(self.log))
        gateway_port = await self.serve(app)
        async with httpx.AsyncClient(trust_env=False) as client:
            async with client.stream("GET", f"http://127.0.0.1:{gateway_port}/mcp", headers={"Authorization": "Bearer " + CLIENT_TOKEN}) as response:
                self.assertEqual(response.status_code, 200)
                async for chunk in response.aiter_bytes():
                    self.assertIn(b"data:", chunk)
                    break
        for _ in range(100):
            completions = [e for e in self.events() if e["event"] == "completed"]
            if completions:
                self.assertEqual(completions[0]["outcome"], "cancelled_or_disconnected")
                return
            await asyncio.sleep(0.01)
        self.fail("Client disconnected but no completion audit was retained")

    async def test_observer_recovers_after_storage_failure_and_clean_close(self):
        async def websocket(ws):
            await ws.accept()
            await ws.receive_text()
            await ws.send_json({"method": "Target.targetCreated", "params": {"targetInfo": {
                "targetId": "page-1", "type": "page", "url": "https://user:password@example.com/path?token=secret#private"}}})
            await ws.close()
        port = await self.serve(Starlette(routes=[WebSocketRoute("/browser", websocket)]))
        class FailFirstGap(AuditLog):
            failed = False
            async def write(self, event, **fields):
                if event == "observer_gap" and not self.failed:
                    self.failed = True
                    raise OSError("synthetic storage failure")
                await super().write(event, **fields)
        audit = FailFirstGap(self.log)
        calls = []
        async def discovery(request):
            calls.append(request)
            self.assertEqual(request.extensions["timeout"]["read"], 10)
            if len(calls) == 1:
                raise httpx.ReadTimeout("synthetic timeout", request=request)
            return httpx.Response(200, json={"webSocketDebuggerUrl": f"ws://127.0.0.1:{port}/browser"})
        original = httpx.AsyncClient
        app = create_app(upstream="http://127.0.0.1:8001/mcp", upstream_token=UPSTREAM_TOKEN,
                         clients={"agent": CLIENT_TOKEN}, audit=audit, cdp_url="http://127.0.0.1:9222")
        with patch("audit_proxy.httpx.AsyncClient", side_effect=lambda **kw: original(transport=httpx.MockTransport(discovery), **kw)):
            await self.serve(app)
            for _ in range(800):
                events = self.events()
                if len([e for e in events if e["event"] == "observer_connected"]) >= 2:
                    self.assertTrue(audit.failed)
                    self.assertTrue(any(e.get("reason") == "connection_closed" for e in events))
                    observation = next(e for e in events if e["event"] == "browser_observation")
                    self.assertEqual(observation["url"], "https://example.com/path")
                    self.assertEqual(observation["client"], "unattributed")
                    self.assertNotIn("password", self.log.read_text())
                    self.assertNotIn("token=", self.log.read_text())
                    return
                await asyncio.sleep(0.01)
        self.fail("Observer did not recover and reconnect")


if __name__ == "__main__":
    unittest.main()
