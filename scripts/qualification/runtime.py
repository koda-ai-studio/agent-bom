#!/usr/bin/env python3
"""Runtime lane: real proxy and gateway processes under real MCP traffic.

Upstream servers record what reaches them, so a block means the upstream never
saw the call and a pass means it did. Credentials and injected text are fixture
values from the proxy characterization suite, never real secrets.
"""

from __future__ import annotations

import argparse
import json
import os
import queue
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import (  # noqa: E402
    REPO_ROOT,
    RESULTS_DIR,
    LaneResult,
    agent_bom_command,
    free_port,
    http_json,
    latency_summary,
    tail,
    wait_for_http,
)

FIXTURES = REPO_ROOT / "tests" / "fixtures" / "proxy_characterization"
FIXTURE_SECRET = "AKIA" + "IOSFODNN7EXAMPLE"
INJECTED_MARKER = "Ignore previous instructions"
RELAY_SAMPLES = 200


def _isolated_env(workdir: Path) -> dict[str, str]:
    home = workdir / "home"
    home.mkdir(exist_ok=True)
    return {
        **os.environ,
        "HOME": str(home),
        "USERPROFILE": str(home),
        "AGENT_BOM_STATE_DIR": str(home / ".agent-bom"),
        "AGENT_BOM_ALLOW_PRIVATE_EGRESS_URLS": "1",
    }


def tool_call(message_id: int, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": message_id, "method": "tools/call", "params": {"name": name, "arguments": arguments or {}}}


def tools_list(message_id: int) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": message_id, "method": "tools/list"}


def is_error(frame: dict[str, Any] | None) -> bool:
    return bool(frame and "error" in frame)


def frame_text(frame: dict[str, Any] | None) -> str:
    return json.dumps(frame or {})


class ProxySession:
    """Speak JSON-RPC to ``agent-bom proxy`` over stdio like an MCP client."""

    def __init__(self, arguments: list[str], server: Path, record: Path, env: dict[str, str]) -> None:
        command = agent_bom_command(
            "proxy", "--no-isolate", "--metrics-port", "0", *arguments, "--", sys.executable, str(server), str(record)
        )
        print("+ " + " ".join(command), flush=True)
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)  # noqa: S603
        self.record = record
        self.replies: queue.Queue[dict[str, Any]] = queue.Queue()
        self.stderr: list[str] = []
        threading.Thread(target=self._read_stdout, daemon=True).start()
        threading.Thread(target=self._read_stderr, daemon=True).start()

    def _read_stdout(self) -> None:
        assert self.process.stdout is not None
        for line in self.process.stdout:
            try:
                self.replies.put(json.loads(line))
            except ValueError:
                self.stderr.append(f"non-JSON stdout: {line[:200]}")

    def _read_stderr(self) -> None:
        assert self.process.stderr is not None
        for line in self.process.stderr:
            self.stderr.append(line)

    def request(self, message: dict[str, Any], timeout: float = 30) -> dict[str, Any] | None:
        assert self.process.stdin is not None
        self.process.stdin.write(json.dumps(message) + "\n")
        self.process.stdin.flush()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                reply = self.replies.get(timeout=max(0.1, deadline - time.monotonic()))
            except queue.Empty:
                break
            if reply.get("id") == message.get("id"):
                return reply
        return None

    def upstream_saw(self, tool: str) -> bool:
        if not self.record.is_file():
            return False
        for line in self.record.read_text(encoding="utf-8").splitlines():
            try:
                if (json.loads(line).get("params") or {}).get("name") == tool:
                    return True
            except ValueError:
                continue
        return False

    def close(self) -> int:
        assert self.process.stdin is not None
        try:
            self.process.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "test/exit"}) + "\n")
            self.process.stdin.close()
        except (BrokenPipeError, OSError):
            pass  # The process already closed its input; wait() below reports its exit.
        try:
            return self.process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.process.kill()
            return self.process.wait()


def audit_records(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def proxy_policy_session(result: LaneResult, workdir: Path) -> None:
    policy = workdir / "policy.json"
    policy.write_text(json.dumps({"rules": [{"id": "no-delete", "action": "block", "block_tools": ["delete_file"]}]}), encoding="utf-8")
    log = workdir / "proxy-audit.jsonl"
    session = ProxySession(
        ["--policy", str(policy), "--log", str(log), "--block-undeclared", "--detect-credentials"],
        FIXTURES / "fake_server.py",
        workdir / "proxy-record.jsonl",
        _isolated_env(workdir),
    )
    listed = session.request(tools_list(1))
    names = [tool["name"] for tool in ((listed or {}).get("result") or {}).get("tools", [])]
    result.check("proxy_lists_upstream_tools", "echo" in names and "delete_file" in names, names or session.stderr[-5:])
    passed = session.request(tool_call(2, "echo", {"text": "hello"}))
    result.check("proxy_passes_allowed_call", not is_error(passed) and "ok:echo" in frame_text(passed), frame_text(passed)[:300])
    result.check("proxy_allowed_call_reached_upstream", session.upstream_saw("echo"), "upstream record")
    blocked = session.request(tool_call(3, "delete_file", {"path": "/tmp/a"}))
    result.check("proxy_blocks_policy_tool", is_error(blocked) and "no-delete" in frame_text(blocked), frame_text(blocked)[:300])
    result.check("proxy_blocked_call_never_reached_upstream", not session.upstream_saw("delete_file"), "upstream record")
    undeclared = session.request(tool_call(4, "mystery"))
    result.check("proxy_blocks_undeclared_tool", is_error(undeclared), frame_text(undeclared)[:300])
    result.check("proxy_undeclared_never_reached_upstream", not session.upstream_saw("mystery"), "upstream record")
    leak = session.request(tool_call(5, "leak"))
    result.check(
        "proxy_redacts_leaked_credential",
        leak is not None and FIXTURE_SECRET not in frame_text(leak) and "REDACTED" in frame_text(leak),
        frame_text(leak)[:300],
    )
    timings: list[float] = []
    for index in range(RELAY_SAMPLES):
        began = time.perf_counter()
        reply = session.request(tool_call(100 + index, "echo", {"n": index}))
        if reply and not is_error(reply):
            timings.append((time.perf_counter() - began) * 1000)
    result.measurements["proxy_relay"] = latency_summary(timings)
    result.check("proxy_answers_every_sample", len(timings) == RELAY_SAMPLES, f"{len(timings)}/{RELAY_SAMPLES}")
    exit_code = session.close()
    result.check("proxy_exits_cleanly", exit_code == 0, f"exit {exit_code}\n{tail(''.join(session.stderr), 8)}")
    records = audit_records(log)
    decisions = {record.get("tool"): record.get("policy") for record in records if record.get("type") == "tools/call"}
    result.check("proxy_audits_block_and_pass", decisions.get("delete_file") == "blocked" and decisions.get("echo") == "allowed", decisions)
    result.check(
        "proxy_audit_does_not_store_secret", FIXTURE_SECRET not in log.read_text(encoding="utf-8") if log.is_file() else False, "audit log"
    )


def proxy_injection_session(result: LaneResult, workdir: Path) -> None:
    log = workdir / "injection-audit.jsonl"
    session = ProxySession(
        ["--log", str(log), "--injection-mode", "enforce"],
        FIXTURES / "malicious_server.py",
        workdir / "injection-record.jsonl",
        _isolated_env(workdir),
    )
    listed = session.request(tools_list(1))
    names = [tool["name"] for tool in ((listed or {}).get("result") or {}).get("tools", [])]
    result.check("proxy_strips_poisoned_tool", "echo" in names and "add_numbers" not in names, names or session.stderr[-5:])
    refused = session.request(tool_call(2, "add_numbers", {"a": 1}))
    result.check("proxy_refuses_stripped_tool", is_error(refused), frame_text(refused)[:300])
    result.check("proxy_stripped_tool_never_reached_upstream", not session.upstream_saw("add_numbers"), "upstream record")
    injected = session.request(tool_call(3, "weather"))
    result.check(
        "proxy_withholds_injected_result", is_error(injected) and INJECTED_MARKER not in frame_text(injected), frame_text(injected)[:300]
    )
    clean = session.request(tool_call(4, "echo"))
    result.check("proxy_still_passes_clean_tool", not is_error(clean) and "ok:echo" in frame_text(clean), frame_text(clean)[:300])
    session.close()


class Upstream:
    """A real HTTP MCP upstream that records every JSON-RPC frame it receives."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                pass

            def do_POST(self) -> None:  # noqa: N802
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
                outer.calls.append(body)
                reply = json.dumps(outer.answer(body)).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(reply)))
                self.end_headers()
                self.wfile.write(reply)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/mcp"

    @staticmethod
    def answer(body: dict[str, Any]) -> dict[str, Any]:
        if body.get("method") == "tools/list":
            tools = [
                {"name": "echo", "description": "Echo text.", "inputSchema": {"type": "object"}},
                {"name": "delete_file", "description": "Delete a file.", "inputSchema": {"type": "object"}},
            ]
            return {"jsonrpc": "2.0", "id": body.get("id"), "result": {"tools": tools}}
        name = (body.get("params") or {}).get("name")
        return {"jsonrpc": "2.0", "id": body.get("id"), "result": {"content": [{"type": "text", "text": f"ok:{name}"}]}}

    def saw(self, tool: str) -> bool:
        return any((call.get("params") or {}).get("name") == tool for call in self.calls)

    def stop(self) -> None:
        self.server.shutdown()


def gateway_session(result: LaneResult, workdir: Path) -> None:
    upstream = Upstream()
    upstreams = workdir / "upstreams.yaml"
    upstreams.write_text(
        f"upstreams:\n  - name: qual\n    url: {upstream.url}\n    transport: streamable-http\n    auth: none\n", encoding="utf-8"
    )
    policy = workdir / "gateway-policy.json"
    policy.write_text(json.dumps({"rules": [{"id": "no-delete", "action": "block", "block_tools": ["delete_file"]}]}), encoding="utf-8")
    port = free_port()
    token = "qualification-synthetic-gateway-token"
    expires = (datetime.now(timezone.utc) + timedelta(minutes=50)).isoformat()
    command = agent_bom_command(
        "gateway", "serve", "--upstreams", str(upstreams), "--policy", str(policy), "--bind", f"127.0.0.1:{port}",
        "--bearer-token", token, "--bearer-token-expires-at", expires,
    )  # fmt: skip
    log_path = RESULTS_DIR / "logs" / "gateway.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    print("+ " + " ".join(command).replace(token, "***"), flush=True)
    with log_path.open("wb") as log:
        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, env=_isolated_env(workdir))  # noqa: S603
        try:
            base = f"http://127.0.0.1:{port}"
            ready = wait_for_http(f"{base}/healthz", timeout=90)
            if not result.check("gateway_ready", ready, tail(log_path.read_text(encoding="utf-8", errors="replace"))):
                return
            _exercise_gateway(result, base, token, upstream)
        finally:
            process.terminate()
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()
            upstream.stop()


def _exercise_gateway(result: LaneResult, base: str, token: str, upstream: Upstream) -> None:
    def post(message: dict[str, Any], *, bearer: str | None = token) -> tuple[int, Any]:
        headers = {"Content-Type": "application/json"}
        if bearer:
            headers["Authorization"] = f"Bearer {bearer}"
        status, body, _size = http_json(f"{base}/mcp/qual", method="POST", body=json.dumps(message).encode(), headers=headers, timeout=30)
        return status, body

    status, _body = post(tool_call(1, "echo"), bearer=None)
    result.check("gateway_refuses_missing_token", status == 401, f"HTTP {status}")
    status, _body = post(tool_call(2, "echo"), bearer="wrong-token")
    result.check("gateway_refuses_wrong_token", status in (401, 403), f"HTTP {status}")
    result.check("gateway_refused_calls_never_reached_upstream", not upstream.calls, f"{len(upstream.calls)} upstream frames")
    status, body = post(tools_list(3))
    names = [tool["name"] for tool in (body.get("result") or {}).get("tools", [])] if isinstance(body, dict) else []
    result.check("gateway_lists_upstream_tools", status == 200 and "echo" in names, f"HTTP {status} {names}")
    status, body = post(tool_call(4, "echo", {"text": "hello"}))
    result.check("gateway_passes_allowed_call", status == 200 and "ok:echo" in json.dumps(body), f"HTTP {status} {str(body)[:300]}")
    result.check("gateway_allowed_call_reached_upstream", upstream.saw("echo"), "upstream record")
    status, body = post(tool_call(5, "delete_file", {"path": "/tmp/a"}))
    result.check(
        "gateway_blocks_policy_tool",
        isinstance(body, dict) and "error" in body and "Blocked by agent-bom gateway policy" in json.dumps(body),
        f"HTTP {status} {str(body)[:300]}",
    )
    result.check("gateway_blocked_call_never_reached_upstream", not upstream.saw("delete_file"), "upstream record")
    timings: list[float] = []
    for index in range(RELAY_SAMPLES):
        began = time.perf_counter()
        status, body = post(tool_call(100 + index, "echo", {"n": index}))
        if status == 200 and isinstance(body, dict) and "result" in body:
            timings.append((time.perf_counter() - began) * 1000)
    result.measurements["gateway_relay"] = latency_summary(timings)
    result.check("gateway_answers_every_sample", len(timings) == RELAY_SAMPLES, f"{len(timings)}/{RELAY_SAMPLES}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.parse_args()
    result = LaneResult("runtime", "proxy-and-gateway")
    with tempfile.TemporaryDirectory(prefix="qualification-runtime-") as tmp:
        workdir = Path(tmp).resolve()
        proxy_policy_session(result, workdir)
        proxy_injection_session(result, workdir)
        gateway_session(result, workdir)
    result.measurements["headline"] = {
        "proxy_p95_ms": (result.measurements.get("proxy_relay") or {}).get("p95_ms"),
        "gateway_p95_ms": (result.measurements.get("gateway_relay") or {}).get("p95_ms"),
    }
    return result.write()


if __name__ == "__main__":
    raise SystemExit(main())
