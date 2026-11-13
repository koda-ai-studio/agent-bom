#!/usr/bin/env python3
"""Smoke-test a built MCP server image: it starts, answers initialize and lists its tools.

``--transport stdio`` runs the image with no network and speaks JSON-RPC over
stdin/stdout. ``--transport http`` runs the image's own start-up command (the
hosted images sync the advisory database first, 60-150 s), waits up to
``--wait`` seconds for ``/health`` on a random loopback port, then calls
``initialize`` and ``tools/list`` on ``/mcp``. No tool is called, so the smoke
adds no upstream request to the ones the start-up sync makes.

Usage::

    python scripts/smoke_mcp_image.py agent-bom-mcp:ci --transport stdio --min-tools 8
    python scripts/smoke_mcp_image.py agent-bom-sse:ci --transport http --bearer --min-tools 8
    python scripts/smoke_mcp_image.py agent-bom-public-mcp:ci --transport http --expect-tools check,cve_lookup
"""

from __future__ import annotations

import argparse
import json
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any

PROTOCOL = "2025-06-18"
FORBIDDEN_TOOLS = ("agent_activity",)


def _initialize(request_id: int = 1) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "initialize",
        "params": {"protocolVersion": PROTOCOL, "capabilities": {}, "clientInfo": {"name": "image-smoke", "version": "1"}},
    }


INITIALIZED = {"jsonrpc": "2.0", "method": "notifications/initialized"}
TOOLS_LIST = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}


def check_tools(server_info: dict[str, Any], tools: list[str], *, min_tools: int, expect: list[str]) -> list[str]:
    """Problems with an initialize result and tool list; empty when the image is healthy."""
    problems: list[str] = []
    if server_info.get("name") != "agent-bom":
        problems.append(f"serverInfo.name is {server_info.get('name')!r}, expected 'agent-bom'")
    if len(tools) < min_tools:
        problems.append(f"{len(tools)} tools listed, expected at least {min_tools}: {sorted(tools)}")
    if expect and sorted(tools) != sorted(expect):
        problems.append(f"tools {sorted(tools)} differ from the expected {sorted(expect)}")
    problems.extend(f"forbidden tool {name} is served" for name in FORBIDDEN_TOOLS if name in tools)
    return problems


def _smoke_stdio(image: str, timeout: float) -> tuple[dict[str, Any], list[str]]:
    payload = "".join(json.dumps(message) + "\n" for message in (_initialize(), INITIALIZED, TOOLS_LIST))
    proc = subprocess.Popen(
        ["docker", "run", "--rm", "-i", "--network", "none", "-e", "AGENT_BOM_SKIP_UPDATE_CHECK=1", image],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert proc.stdin and proc.stdout
    proc.stdin.write(payload)
    proc.stdin.flush()
    responses: dict[int, dict[str, Any]] = {}
    deadline = time.monotonic() + timeout
    try:
        while 2 not in responses:
            if time.monotonic() > deadline:
                raise SystemExit(f"stdio server did not answer tools/list within {timeout:.0f}s")
            line = proc.stdout.readline()
            if not line:
                raise SystemExit(f"stdio server exited before answering: {proc.stderr.read() if proc.stderr else ''}")
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(message.get("id"), int):
                responses[message["id"]] = message
    finally:
        proc.stdin.close()
        proc.kill()
        proc.wait(timeout=30)
    return responses[1]["result"]["serverInfo"], [tool["name"] for tool in responses[2]["result"]["tools"]]


def _sse_json(body: str) -> dict[str, Any]:
    """The JSON-RPC message from a streamable-HTTP response (plain JSON or one SSE event)."""
    body = body.strip()
    if body.startswith("{"):
        return json.loads(body)
    data = [line[5:].strip() for line in body.splitlines() if line.startswith("data:")]
    if not data:
        raise ValueError(f"no JSON-RPC message in response: {body[:200]!r}")
    return json.loads(data[-1])


def _post(url: str, message: dict[str, Any], headers: dict[str, str]) -> tuple[dict[str, Any] | None, dict[str, str]]:
    request = urllib.request.Request(
        url,
        data=json.dumps(message).encode(),
        headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream", **headers},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310 - loopback URL built here
        body = response.read().decode("utf-8")
        return (_sse_json(body) if body.strip() else None), dict(response.headers)


def _container_state(name: str) -> str:
    result = subprocess.run(["docker", "inspect", "-f", "{{.State.Status}}", name], capture_output=True, text=True, check=False)
    return result.stdout.strip()


def _smoke_http(image: str, wait: float, bearer: bool, env: list[str]) -> tuple[dict[str, Any], list[str]]:
    name = f"mcp-image-smoke-{secrets.token_hex(4)}"
    token = secrets.token_urlsafe(32) if bearer else ""
    command = ["docker", "run", "-d", "--name", name, "-p", "127.0.0.1::8423", "-e", "AGENT_BOM_SKIP_UPDATE_CHECK=1"]
    if token:
        # A static bearer token must carry an expiry within the next hour.
        expires = (datetime.now(timezone.utc) + timedelta(minutes=50)).isoformat(timespec="seconds")
        command += ["-e", f"AGENT_BOM_MCP_BEARER_TOKEN={token}", "-e", f"AGENT_BOM_MCP_BEARER_TOKEN_EXPIRES_AT={expires}"]
    for item in env:
        command += ["-e", item]
    subprocess.run([*command, image], check=True, capture_output=True, text=True)
    try:
        port = (
            subprocess.run(["docker", "port", name, "8423/tcp"], check=True, capture_output=True, text=True).stdout.split(":")[-1].strip()
        )
        base = f"http://127.0.0.1:{port}"
        started = time.monotonic()
        while True:
            state = _container_state(name)
            if state != "running":
                raise SystemExit(f"container {state or 'vanished'} before /health answered")
            try:
                with urllib.request.urlopen(f"{base}/health", timeout=5) as response:  # noqa: S310 - loopback
                    if response.status == 200:
                        break
            except (urllib.error.URLError, ConnectionError, TimeoutError):
                pass
            if time.monotonic() - started > wait:
                raise SystemExit(f"/health did not answer within {wait:.0f}s")
            time.sleep(3)
        print(f"/health answered after {time.monotonic() - started:.0f}s")
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        init, response_headers = _post(f"{base}/mcp", _initialize(), headers)
        session = next((value for key, value in response_headers.items() if key.lower() == "mcp-session-id"), None)
        if session:
            headers["Mcp-Session-Id"] = session
        headers["MCP-Protocol-Version"] = PROTOCOL
        _post(f"{base}/mcp", INITIALIZED, headers)
        listed, _ = _post(f"{base}/mcp", TOOLS_LIST, headers)
        assert init and listed
        return init["result"]["serverInfo"], [tool["name"] for tool in listed["result"]["tools"]]
    except BaseException:
        logs = subprocess.run(["docker", "logs", "--tail", "80", name], capture_output=True, text=True, check=False)
        print(logs.stdout + logs.stderr, file=sys.stderr)
        raise
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("image")
    parser.add_argument("--transport", choices=("stdio", "http"), required=True)
    parser.add_argument("--min-tools", type=int, default=1)
    parser.add_argument("--expect-tools", default="", help="comma-separated exact tool set")
    parser.add_argument("--bearer", action="store_true", help="start the HTTP image with a random bearer token and use it")
    parser.add_argument("--env", action="append", default=[], help="extra KEY=VALUE for the container")
    parser.add_argument("--wait", type=float, default=300.0, help="seconds to wait for /health (default 300)")
    args = parser.parse_args(argv)

    if args.transport == "stdio":
        server_info, tools = _smoke_stdio(args.image, timeout=120.0)
    else:
        server_info, tools = _smoke_http(args.image, args.wait, args.bearer, args.env)
    expect = [name for name in args.expect_tools.split(",") if name]
    problems = check_tools(server_info, tools, min_tools=args.min_tools, expect=expect)
    if problems:
        for problem in problems:
            print(f"::error title=MCP image smoke ({args.image})::{problem}")
        return 1
    served = f"{server_info.get('name')} {server_info.get('version')}"
    print(f"OK: {args.image} ({args.transport}) {served}, {len(tools)} tools: {', '.join(sorted(tools))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
