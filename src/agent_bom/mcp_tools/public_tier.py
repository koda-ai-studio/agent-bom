"""Opt-in anonymous read-only tier for the remote (streamable HTTP) MCP server.

Off by default. With ``AGENT_BOM_MCP_PUBLIC_READONLY=1`` a caller that sends
no ``Authorization`` header may use only the tools in ``PUBLIC_TOOL_SPECS``:
pure lookups against agent-bom's own advisory data and fixed upstream
registries, reading no server-host state and fetching no caller-chosen URL.
Everything else (other tools, resources, prompts, completions) still requires
the configured bearer token, and a request that carries any ``Authorization``
header follows the normal bearer path unchanged, so a bad token is a 401,
never a silent downgrade.

Enforcement is layered:

1. ``PublicTierGate`` (ASGI, outermost) bounds the anonymous request body,
   answers HTTP 401 for an anonymous ``tools/call`` outside the allowlist, and
   tags the remaining anonymous requests with a per-process random credential
   that only ``PublicTierTokenVerifier`` recognises.
2. ``public_tier_guard`` (MCP middleware) is default-deny for that identity:
   it filters ``tools/list``, empties resource/prompt listings, refuses every
   other method, and validates allowlisted arguments.
3. ``check_public_rate_limit`` adds a per-client and an aggregate anonymous
   budget on top of the server's existing per-caller limit.

Rate windows are in-process; a multi-replica deployment multiplies the
anonymous budget by the replica count.
"""

from __future__ import annotations

import hmac
import ipaddress
import json
import time
from collections import OrderedDict, deque
from dataclasses import dataclass
from typing import Any, Callable

from mcp.server.auth.provider import AccessToken
from mcp.shared.exceptions import MCPError

from agent_bom.core.settings import env_bool, env_int
from agent_bom.mcp_tools.request_identity import request_context, verified_access_token

PUBLIC_READONLY_ENV = "AGENT_BOM_MCP_PUBLIC_READONLY"
TRUSTED_PROXY_HOPS_ENV = "AGENT_BOM_MCP_PUBLIC_TRUSTED_PROXY_HOPS"
PUBLIC_CALLER_RATE_LIMIT_ENV = "AGENT_BOM_MCP_PUBLIC_CALLER_RATE_LIMIT"
PUBLIC_TOTAL_RATE_LIMIT_ENV = "AGENT_BOM_MCP_PUBLIC_TOTAL_RATE_LIMIT"

PUBLIC_CLIENT_ID = "agent-bom-public-anonymous"
PUBLIC_SCOPE = "public:read"
PUBLIC_CALLER_PREFIX = "public-anon:"
PUBLIC_MAX_BODY_BYTES = 16 * 1024
PUBLIC_MAX_ARG_CHARS = 256
_MCP_PATH = "/mcp"
_AUTH_REQUIRED_MESSAGE = "Authentication required: this MCP method is not part of the public read-only tier"
_HOST_CONTEXT_ECOSYSTEMS = frozenset({"deb", "apk", "rpm"})


@dataclass(frozen=True)
class PublicToolSpec:
    """One anonymously callable tool, its exact argument set and why it is safe."""

    arguments: tuple[str, ...]
    rationale: str
    validate: Callable[[dict[str, Any]], str | None] | None = None


def _check_arguments(arguments: dict[str, Any]) -> str | None:
    ecosystem = str(arguments.get("ecosystem") or "").strip().lower()
    if ecosystem in _HOST_CONTEXT_ECOSYSTEMS:
        return (
            f"OS-package checks ({ecosystem}) read the server host's distro and package database "
            "and require authentication on the public tier"
        )
    return None


# Reviewed by reading each implementation, not its name. Adding a tool here is
# a security decision: the invariant tests pin each tool's argument set so a new
# path/URL/host argument forces a re-review.
PUBLIC_TOOL_SPECS: dict[str, PublicToolSpec] = {
    "check": PublicToolSpec(
        arguments=("package", "ecosystem", "version", "offline"),
        rationale=(
            "mcp_tools/scanning.check_impl: OSV/local advisory lookup for one package coordinate; registry "
            "resolution and publication checks go to fixed registry origins with the name URL-encoded as a path "
            "segment (check_lookup.version_published); no file, scan-store or tenant read. OS ecosystems read "
            "host distro state and are refused anonymously."
        ),
        validate=_check_arguments,
    ),
    "intel_lookup": PublicToolSpec(
        arguments=("advisory_id",),
        rationale=(
            "mcp_tools/intel.intel_lookup_impl: one advisory from agent-bom's bundled intel database; operator "
            "advisory stores, plugin sources and saved scans are skipped for anonymous callers."
        ),
    ),
    "registry_lookup": PublicToolSpec(
        arguments=("server_name", "package_name"),
        rationale="mcp_tools/registry.registry_lookup_impl: substring match over the bundled MCP server registry; no I/O.",
    ),
}
PUBLIC_TOOL_ALLOWLIST: frozenset[str] = frozenset(PUBLIC_TOOL_SPECS)


def public_readonly_enabled() -> bool:
    """True only when the operator explicitly opted in."""
    return env_bool(PUBLIC_READONLY_ENV, False)


def anonymous_call_allowed(tool_name: Any) -> bool:
    return isinstance(tool_name, str) and tool_name in PUBLIC_TOOL_ALLOWLIST


def anonymous_tools_for(profile_tools: frozenset[str] | None) -> list[str]:
    return sorted(PUBLIC_TOOL_ALLOWLIST if profile_tools is None else PUBLIC_TOOL_ALLOWLIST & profile_tools)


def is_public_token(token: Any) -> bool:
    return token is not None and getattr(token, "client_id", None) == PUBLIC_CLIENT_ID


def current_caller_is_public() -> bool:
    context = request_context.get(None)
    return context is not None and is_public_token(verified_access_token(context))


# ── Identity ───────────────────────────────────────────────────────────────


class PublicTierTokenVerifier:
    """Recognise the gate's per-process anonymous credential; delegate the rest."""

    def __init__(self, inner: Any | None, anonymous_credential: str):
        self._inner = inner
        self._anonymous_credential = anonymous_credential

    async def verify_token(self, token: str):
        if token and hmac.compare_digest(token.encode(), self._anonymous_credential.encode()):
            return AccessToken(token=token, client_id=PUBLIC_CLIENT_ID, scopes=[PUBLIC_SCOPE], expires_at=None, resource=None)
        if self._inner is None:
            return None
        return await self._inner.verify_token(token)


def anonymous_caller_key(context: Any) -> str:
    """Bucket anonymous callers by client address.

    Behind a proxy the socket peer is the proxy, so the operator declares how
    many trusted hops append to ``X-Forwarded-For``; the entry that many places
    from the right was written by the outermost trusted proxy and cannot be
    forged by the client, unlike any entry to its left.
    """
    request = getattr(context, "request", None)
    client = getattr(request, "client", None)
    address = str(getattr(client, "host", "") or "")
    hops = env_int(TRUSTED_PROXY_HOPS_ENV, 0, minimum=0, maximum=10)
    if hops and request is not None:
        entries = [part.strip() for value in request.headers.getlist("x-forwarded-for") for part in value.split(",") if part.strip()]
        if len(entries) >= hops:
            address = entries[-hops]
    try:
        address = str(ipaddress.ip_address(address))
    except ValueError:
        address = "unknown" if not address or len(address) > 64 else address
    return f"{PUBLIC_CALLER_PREFIX}{address}"


# ── Rate limit ─────────────────────────────────────────────────────────────

_public_windows: OrderedDict[str, deque[float]] = OrderedDict()
_aggregate_window: deque[float] = deque()
_MAX_PUBLIC_CALLER_STATES = 4096


def reset_public_rate_windows() -> None:
    _public_windows.clear()
    _aggregate_window.clear()


def _hit(window: deque[float], *, limit: int, window_seconds: float, now: float) -> float | None:
    while window and window[0] <= now - window_seconds:
        window.popleft()
    if len(window) >= limit:
        return max(window[0] + window_seconds - now, 0.0)
    window.append(now)
    return None


def check_public_rate_limit(caller: str, *, window_seconds: float, now: float | None = None) -> float | None:
    """Retry-after seconds when an anonymous caller exceeds its budget, else None."""
    if not caller.startswith(PUBLIC_CALLER_PREFIX):
        return None
    current = time.monotonic() if now is None else now
    total_limit = env_int(PUBLIC_TOTAL_RATE_LIMIT_ENV, 300, minimum=1)
    caller_limit = env_int(PUBLIC_CALLER_RATE_LIMIT_ENV, 30, minimum=1)
    while _aggregate_window and _aggregate_window[0] <= current - window_seconds:
        _aggregate_window.popleft()
    if len(_aggregate_window) >= total_limit:
        return max(_aggregate_window[0] + window_seconds - current, 0.0)
    window = _public_windows.get(caller)
    if window is None:
        if len(_public_windows) >= _MAX_PUBLIC_CALLER_STATES:
            _public_windows.popitem(last=False)
        window = _public_windows[caller] = deque()
    else:
        _public_windows.move_to_end(caller)
    retry_after = _hit(window, limit=caller_limit, window_seconds=window_seconds, now=current)
    if retry_after is None:
        _aggregate_window.append(current)
    return retry_after


# ── MCP middleware (default deny for the anonymous identity) ───────────────


_JSONRPC_INVALID_REQUEST = -32600
_JSONRPC_INVALID_PARAMS = -32602


def _mcp_error(code: int, message: str) -> Exception:
    return MCPError(code, message)


def _auth_error(message: str = _AUTH_REQUIRED_MESSAGE) -> Exception:
    return _mcp_error(_JSONRPC_INVALID_REQUEST, message)


def _argument_error(message: str) -> Exception:
    return _mcp_error(_JSONRPC_INVALID_PARAMS, message)


def _validate_public_call(params: Any) -> None:
    name = params.get("name") if isinstance(params, dict) else None
    if not isinstance(name, str) or not anonymous_call_allowed(name):
        raise _auth_error()
    spec = PUBLIC_TOOL_SPECS[name]
    arguments = params.get("arguments") or {}
    if not isinstance(arguments, dict):
        raise _argument_error("Tool arguments must be an object")
    unknown = sorted(set(arguments) - set(spec.arguments))
    if unknown:
        raise _argument_error(f"Unknown argument(s) for {name}: {unknown}")
    for key, value in arguments.items():
        if isinstance(value, str) and len(value) > PUBLIC_MAX_ARG_CHARS:
            raise _argument_error(f"Argument {key!r} exceeds {PUBLIC_MAX_ARG_CHARS} characters on the public tier")
        if not isinstance(value, (str, bool, type(None))):
            raise _argument_error(f"Argument {key!r} must be a string or boolean on the public tier")
    refusal = spec.validate(arguments) if spec.validate else None
    if refusal:
        raise _argument_error(refusal)


def _filtered_tools(result: Any) -> Any:
    if isinstance(result, dict):
        return {**result, "tools": [tool for tool in result.get("tools", []) if anonymous_call_allowed(tool.get("name"))]}
    tools = [tool for tool in getattr(result, "tools", []) if anonymous_call_allowed(getattr(tool, "name", None))]
    return result.model_copy(update={"tools": tools, "next_cursor": None})


async def public_tier_guard(ctx: Any, call_next: Any) -> Any:
    if not is_public_token(verified_access_token(ctx)):
        return await call_next(ctx)
    method = ctx.method
    if method in {"initialize", "ping"} or method.startswith("notifications/"):
        return await call_next(ctx)
    if method == "tools/list":
        return _filtered_tools(await call_next(ctx))
    if method == "tools/call":
        _validate_public_call(dict(ctx.params or {}))
        return await call_next(ctx)
    if method == "resources/list":
        return {"resources": []}
    if method == "prompts/list":
        return {"prompts": []}
    raise _auth_error()


# ── ASGI gate ──────────────────────────────────────────────────────────────


async def _send_json(send: Any, status: int, payload: dict[str, Any], extra_headers: list[tuple[bytes, bytes]] | None = None) -> None:
    body = json.dumps(payload).encode()
    headers = [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()), *(extra_headers or [])]
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})


async def _send_unauthorized(send: Any) -> None:
    challenge = b'Bearer error="invalid_token", error_description="Authentication required for this tool"'
    await _send_json(send, 401, {"error": "invalid_token", "error_description": _AUTH_REQUIRED_MESSAGE}, [(b"www-authenticate", challenge)])


def _anonymous_calls_allowed(body: bytes) -> bool:
    try:
        parsed = json.loads(body) if body else None
    except (ValueError, UnicodeDecodeError):
        return True  # The transport answers malformed JSON with a parse error.
    messages = parsed if isinstance(parsed, list) else [parsed]
    for message in messages:
        if isinstance(message, dict) and message.get("method") == "tools/call":
            params = message.get("params")
            if not anonymous_call_allowed(params.get("name") if isinstance(params, dict) else None):
                return False
    return True


class PublicTierGate:
    """Outermost ASGI layer for the public tier; see the module docstring."""

    def __init__(self, app: Any, anonymous_credential: str):
        self.app = app
        self._authorization = f"Bearer {anonymous_credential}".encode()

    def __getattr__(self, name: str) -> Any:
        return getattr(self.app, name)

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope.get("type") != "http" or scope.get("path", "").rstrip("/") != _MCP_PATH:
            await self.app(scope, receive, send)
            return
        headers = list(scope.get("headers") or [])
        if any(key.lower() == b"authorization" for key, _ in headers):
            await self.app(scope, receive, send)
            return
        body = b""
        if scope.get("method") == "POST":
            declared = next((value for key, value in headers if key.lower() == b"content-length"), None)
            if declared is not None and declared.isdigit() and int(declared) > PUBLIC_MAX_BODY_BYTES:
                await _send_json(send, 413, {"error": "request_too_large", "limit_bytes": PUBLIC_MAX_BODY_BYTES})
                return
            more = True
            while more:
                message = await receive()
                if message["type"] == "http.disconnect":
                    return
                body += message.get("body", b"")
                more = message.get("more_body", False)
                if len(body) > PUBLIC_MAX_BODY_BYTES:
                    await _send_json(send, 413, {"error": "request_too_large", "limit_bytes": PUBLIC_MAX_BODY_BYTES})
                    return
            if not _anonymous_calls_allowed(body):
                await _send_unauthorized(send)
                return
        replayed = False

        async def replay() -> Any:
            nonlocal replayed
            if not replayed and scope.get("method") == "POST":
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        tagged = {**scope, "headers": [*headers, (b"authorization", self._authorization)]}
        await self.app(tagged, replay, send)
