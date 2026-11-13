#!/usr/bin/env python3
"""Optional private, credential-attributed MCP audit gateway and CDP observer.

Uses the dependencies in audit-requirements.txt. Logs are private operational
evidence, not a tamper-proof ledger.
"""
from __future__ import annotations

import argparse
import asyncio
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
from urllib.parse import urlsplit, urlunsplit
import uuid

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, StreamingResponse
from starlette.routing import Route
import uvicorn
from websockets.asyncio.client import connect

BODY_LIMIT = 1024 * 1024
IDENTIFIER = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
HOP_HEADERS = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
               "te", "trailer", "transfer-encoding", "upgrade", "content-length"}


def identifier(value):
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return value if IDENTIFIER.fullmatch(value) else "sha256:" + hashlib.sha256(value.encode()).hexdigest()[:16]
    return None


def safe_url(value):
    """Return HTTP(S) origin/path only; never echo malformed or opaque input."""
    if not isinstance(value, str) or len(value) > 16384:
        return None
    try:
        url = urlsplit(value)
        if url.scheme.lower() not in {"http", "https"} or not url.hostname:
            return None
        host = url.hostname.lower()
        if ":" in host:
            host = "[" + host + "]"
        if url.port is not None:
            host += ":" + str(url.port)
        return urlunsplit((url.scheme.lower(), host, (url.path or "/")[:2048], "", ""))
    except (ValueError, UnicodeError):
        return None


def request_details(payload):
    """An allowlist: never log arbitrary arguments, clientInfo, scripts or IDs."""
    if not isinstance(payload, dict):
        return {"rpc_method": "unparsed"}
    method = payload.get("method")
    known = {"initialize", "tools/list", "tools/call", "ping", "resources/list",
             "resources/read", "prompts/list", "prompts/get", "notifications/initialized",
             "notifications/cancelled", "notifications/progress"}
    result = {"rpc_method": method if isinstance(method, str) and method in known else "other"}
    params = payload.get("params")
    if method == "tools/call" and isinstance(params, dict):
        result["tool"] = identifier(params.get("name"))
        args = params.get("arguments")
        if isinstance(args, dict):
            result["browser_session"] = identifier(args.get("session_id"))
            url = safe_url(args.get("url"))
            if url:
                result["requested_url"] = url
    return {key: value for key, value in result.items() if value is not None}


def inspect_response(data, content_type, truncated=False):
    """Extract only outcome and top-level response URL, not content or errors."""
    if truncated:
        return {"rpc_outcome": "uninspected", "response_inspection_truncated": True}
    try:
        if "text/event-stream" in content_type:
            messages, fields = [], []
            for line in data.decode().splitlines() + [""]:
                if line == "":
                    if fields:
                        messages.append(json.loads("\n".join(fields)))
                        fields = []
                elif line.startswith("data:"):
                    value = line[5:]
                    fields.append(value[1:] if value.startswith(" ") else value)
        else:
            messages = [json.loads(data)] if data else []
        responses = [m for m in messages if isinstance(m, dict) and ("result" in m or "error" in m)]
        if not responses:
            return {"rpc_outcome": "no_result"}
        message = responses[-1]
        if "error" in message:
            return {"rpc_outcome": "rpc_error"}
        result = message.get("result")
        if not isinstance(result, dict):
            return {"rpc_outcome": "success"}
        out = {"rpc_outcome": "tool_error" if result.get("isError") else "success"}
        structured = result.get("structuredContent")
        if isinstance(structured, dict):
            url = safe_url(structured.get("url"))
            if url:
                out["returned_url"] = url
            session = identifier(structured.get("session_id"))
            if session:
                out["browser_session"] = session
        return out
    except (ValueError, UnicodeError, TypeError):
        return {"rpc_outcome": "uninspected"}


class AuditLog:
    def __init__(self, path, max_bytes=100 * 1024 * 1024, backups=5):
        self.path = Path(path)
        self.max_bytes = max_bytes
        self.backups = backups
        self.lock = asyncio.Lock()
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if stat.S_IMODE(self.path.parent.stat().st_mode) & 0o077:
            raise ValueError("Audit directory must have mode 0700")

    async def write(self, event, **fields):
        record = {"schema_version": 1, "time": datetime.now(timezone.utc).isoformat(),
                  "event": event, **fields}
        line = (json.dumps(record, ensure_ascii=True, separators=(",", ":")) + "\n").encode()
        if len(line) > self.max_bytes:
            raise OSError("Audit record exceeds rotation limit")
        async with self.lock:
            if self.path.is_symlink():
                raise OSError("Audit log must not be a symbolic link")
            if self.path.exists() and self.path.stat().st_size + len(line) > self.max_bytes:
                for index in range(self.backups, 0, -1):
                    source = self.path if index == 1 else Path(str(self.path) + "." + str(index - 1))
                    if source.exists():
                        os.replace(source, str(self.path) + "." + str(index))
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            try:
                if stat.S_IMODE(os.fstat(fd).st_mode) & 0o077:
                    raise OSError("Audit log must have mode 0600")
                with os.fdopen(fd, "ab", closefd=False) as handle:
                    handle.write(line)
                    handle.flush()
                    os.fsync(fd)
            finally:
                os.close(fd)


def load_clients(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd) as handle:
        if stat.S_IMODE(os.fstat(handle.fileno()).st_mode) & 0o077:
            raise ValueError("Client credential file must have mode 0600")
        data = json.load(handle)
    clients = data.get("clients", {})
    if data.get("version") != 1 or not clients:
        raise ValueError("Expected version 1 and a nonempty clients mapping")
    tokens = set()
    for name, token in clients.items():
        if not IDENTIFIER.fullmatch(name) or not isinstance(token, str) or len(token) < 32 or token in tokens:
            raise ValueError("Client labels must be safe identifiers and tokens unique with at least 32 characters")
        tokens.add(token)
    return clients


def require_loopback(url):
    parsed = urlsplit(url)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"} or parsed.username or parsed.password:
        raise ValueError("Upstream and CDP URLs must be HTTP loopback addresses")


def create_app(*, upstream, upstream_token, clients, audit, cdp_url=None):
    require_loopback(upstream)
    if cdp_url:
        require_loopback(cdp_url)
    active = set()
    pending_audits = set()

    async def observe(client):
        while True:
            try:
                version = await client.get(cdp_url.rstrip("/") + "/json/version", timeout=10)
                version.raise_for_status()
                websocket = version.json()["webSocketDebuggerUrl"]
                parsed = urlsplit(websocket)
                if parsed.scheme != "ws" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
                    raise ValueError("CDP websocket is not loopback")
                async with connect(websocket, max_size=BODY_LIMIT, proxy=None) as ws:
                    await audit.write("observer_connected", client="unattributed")
                    await ws.send(json.dumps({"id": 1, "method": "Target.setDiscoverTargets", "params": {"discover": True}}))
                    seen = {}
                    async for raw in ws:
                        event = json.loads(raw)
                        method = event.get("method")
                        if method not in {"Target.targetCreated", "Target.targetInfoChanged", "Target.targetDestroyed"}:
                            continue
                        params = event.get("params", {})
                        if method == "Target.targetDestroyed":
                            seen.pop(params.get("targetId"), None)
                            continue
                        target = params.get("targetInfo", {})
                        url = safe_url(target.get("url"))
                        target_id = target.get("targetId")
                        if target.get("type") != "page" or not url or seen.get(target_id) == url:
                            continue
                        snapshot = method == "Target.targetCreated" and target_id not in seen
                        seen[target_id] = url
                        await audit.write("browser_observation", client="unattributed", url=url,
                                          target=identifier(target_id), observation="target_snapshot" if snapshot else "navigation",
                                          overlapping_requests=sorted(active)[:16], overlapping_request_count=len(active))
                await audit.write("observer_gap", client="unattributed", reason="connection_closed")
                await asyncio.sleep(3)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                # Exception text can contain raw URLs. Persist its class only.
                try:
                    await audit.write("observer_gap", client="unattributed", error_type=type(exc).__name__)
                except OSError:
                    print("Observer audit storage unavailable; retrying observation.", file=sys.stderr)
                await asyncio.sleep(3)

    @asynccontextmanager
    async def lifespan(app):
        async with httpx.AsyncClient(trust_env=False, timeout=httpx.Timeout(15, read=None)) as client:
            app.state.client = client
            await audit.write("gateway_started", clients=sorted(clients), observer_enabled=bool(cdp_url))
            task = asyncio.create_task(observe(client)) if cdp_url else None
            try:
                yield
            finally:
                if task:
                    task.cancel()
                    with suppress(asyncio.CancelledError):
                        await task
                if pending_audits:
                    await asyncio.gather(*pending_audits, return_exceptions=True)
                await audit.write("gateway_stopped")

    async def gateway(request: Request):
        started = time.monotonic()
        call_id = uuid.uuid4().hex
        auth = request.headers.get("authorization", "")
        supplied = auth[7:] if auth.startswith("Bearer ") else ""
        name = None
        for label, token in clients.items():
            if hmac.compare_digest(supplied.encode(), token.encode()):
                name = label
        try:
            if not name:
                await audit.write("denied", request=call_id, client="unknown", http_method=request.method,
                                  reason="missing_or_invalid_token")
                return JSONResponse({"error": "Unauthorized"}, status_code=401,
                                    headers={"WWW-Authenticate": "Bearer"})
            body = bytearray()
            async for chunk in request.stream():
                if len(body) + len(chunk) > BODY_LIMIT:
                    await audit.write("rejected", request=call_id, client=name, reason="request_too_large")
                    return JSONResponse({"error": "Request too large"}, status_code=413)
                body.extend(chunk)
            try:
                payload = json.loads(body) if body else None
            except (ValueError, UnicodeError):
                payload = None
            details = request_details(payload)
            await audit.write("request", request=call_id, client=name, http_method=request.method, **details)
        except OSError:
            return JSONResponse({"error": "Audit storage unavailable; request not forwarded"}, status_code=503)

        headers = {key: value for key, value in request.headers.items()
                   if key.lower() not in HOP_HEADERS | {"authorization", "x-audit-client"}}
        headers["authorization"] = "Bearer " + upstream_token
        active.add(call_id)
        try:
            message = request.app.state.client.build_request(request.method, upstream, headers=headers, content=bytes(body))
            response = await request.app.state.client.send(message, stream=True)
        except (httpx.HTTPError, OSError) as exc:
            active.discard(call_id)
            await audit.write("completed", request=call_id, client=name, outcome="upstream_unavailable",
                              error_type=type(exc).__name__, duration_ms=round((time.monotonic() - started) * 1000))
            return JSONResponse({"error": "Upstream unavailable"}, status_code=502)

        async def stream():
            captured = bytearray()
            truncated = False
            outcome = "disconnected"
            result = {}
            try:
                async for chunk in response.aiter_bytes():
                    if len(captured) + len(chunk) <= BODY_LIMIT:
                        captured.extend(chunk)
                    else:
                        truncated = True
                    yield chunk
                outcome = "completed"
                result = inspect_response(captured, response.headers.get("content-type", ""), truncated)
            except asyncio.CancelledError:
                outcome = "cancelled_or_disconnected"
                raise
            except Exception as exc:
                outcome = "stream_failed"
                result = {"error_type": type(exc).__name__}
                raise
            finally:
                active.discard(call_id)
                async def finalize():
                    try:
                        await response.aclose()
                    finally:
                        try:
                            await audit.write("completed", request=call_id, client=name,
                                outcome=outcome, http_status=response.status_code,
                                duration_ms=round((time.monotonic() - started) * 1000), **result)
                        except OSError:
                            print("Audit completion write failed; inspect unmatched request records.", file=sys.stderr)
                # Shield the entire cleanup, not just the append: disconnect
                # cancellation may otherwise interrupt aclose before the log.
                write = asyncio.create_task(finalize())
                pending_audits.add(write)
                write.add_done_callback(pending_audits.discard)
                await asyncio.shield(write)

        # aiter_bytes decodes compression, so its original encoding is no longer
        # applicable to the bytes yielded to the caller.
        response_headers = {key: value for key, value in response.headers.items()
                            if key.lower() not in HOP_HEADERS | {"content-encoding"}}
        return StreamingResponse(stream(), status_code=response.status_code, headers=response_headers)

    return Starlette(routes=[Route("/mcp", gateway, methods=["GET", "POST", "DELETE"])], lifespan=lifespan)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--upstream", default="http://127.0.0.1:8001/mcp")
    parser.add_argument("--clients", required=True)
    parser.add_argument("--log", default="/audit/events.jsonl")
    parser.add_argument("--cdp-url")
    parser.add_argument("--max-log-bytes", type=int, default=100 * 1024 * 1024)
    parser.add_argument("--backups", type=int, default=5)
    args = parser.parse_args()
    if args.max_log_bytes < 4096 or args.backups < 1:
        parser.error("Log size must be at least 4096 bytes and backups at least 1")
    token = os.environ.get("SCRAPLING_MCP_AUTH_TOKEN")
    if not token:
        parser.error("SCRAPLING_MCP_AUTH_TOKEN is required for the private upstream")
    os.umask(0o077)
    app = create_app(upstream=args.upstream, upstream_token=token,
                     clients=load_clients(args.clients),
                     audit=AuditLog(args.log, args.max_log_bytes, args.backups), cdp_url=args.cdp_url)
    uvicorn.run(app, host=args.host, port=args.port, access_log=False, log_level="warning")


if __name__ == "__main__":
    main()
