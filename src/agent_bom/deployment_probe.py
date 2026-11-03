"""Helpers for Railway/MCP deployment health probes used in CI workflows."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from functools import partial
from typing import Any
from urllib.parse import urlsplit, urlunsplit

DEFAULT_BASE_URL = "https://agent-bom-mcp.up.railway.app"
_USER_AGENT = "agent-bom-deployment-probe"


def resolve_health_url(base_url: str | None) -> str:
    """Return the canonical MCP health URL for a base Railway endpoint.

    ``RAILWAY_MCP_URL`` is used in two different shapes across the repo:
    the bare Railway host for health probes and the ``/mcp`` endpoint for
    registry publishing. CI should accept either form and normalize both to
    the real health route exposed by the MCP server.
    """

    raw = (base_url or DEFAULT_BASE_URL).strip()
    if not raw:
        raw = DEFAULT_BASE_URL

    parts = urlsplit(raw)
    if not parts.scheme or not parts.netloc:
        raise ValueError(f"invalid base URL: {base_url!r}")
    if parts.scheme not in {"http", "https"}:
        raise ValueError(f"unsupported URL scheme for deployment probe: {parts.scheme!r}")

    path = parts.path.rstrip("/")
    if path.endswith("/mcp"):
        path = path[: -len("/mcp")]

    path = f"{path}/health" if path else "/health"
    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))


def resolve_server_card_url(base_url: str | None) -> str:
    """Return the public MCP server-card URL for a deployment origin."""

    raw = (base_url or DEFAULT_BASE_URL).strip()
    if not raw:
        raw = DEFAULT_BASE_URL

    parts = urlsplit(raw)
    if not parts.scheme or not parts.netloc:
        raise ValueError(f"invalid base URL: {base_url!r}")
    if parts.scheme not in {"http", "https"}:
        raise ValueError(f"unsupported URL scheme for deployment probe: {parts.scheme!r}")

    return urlunsplit((parts.scheme, parts.netloc, "/.well-known/mcp/server-card.json", "", ""))


class _NoAuthRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        raise ValueError("Authenticated MCP probe does not follow redirects")


def verify_mcp_auth(base_url: str | None, *, bearer_token: str | None, expected_version: str | None, timeout: float) -> None:
    """Require an authenticated initialize exchange; public metadata is not proof."""
    if not bearer_token:
        raise ValueError("Authenticated MCP probe requires an operator-provisioned bearer token")
    parts = urlsplit((base_url or DEFAULT_BASE_URL).strip())
    if parts.scheme != "https" or not parts.netloc or parts.username or parts.password:
        raise ValueError("Authenticated MCP probe requires an HTTPS origin without URL credentials")
    path = parts.path.rstrip("/")
    if not path.endswith("/mcp"):
        path += "/mcp"
    url = urlunsplit((parts.scheme, parts.netloc, path, "", ""))
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "agent-bom-deployment-probe", "version": "1"},
            },
        }
    ).encode()
    request = urllib.request.Request(
        url,
        data=body,
        headers={
            "Authorization": f"Bearer {bearer_token}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "User-Agent": _USER_AGENT,
        },
    )
    try:
        opener = urllib.request.build_opener(_NoAuthRedirect())
        with opener.open(request, timeout=timeout) as response:  # nosec B310 - HTTPS validated; redirects rejected
            if response.headers.get_content_type() == "text/event-stream":
                chunks: list[str] = []
                consumed = 0
                while consumed <= 1_048_576:
                    line = response.readline(65_537)
                    if not line:
                        break
                    consumed += len(line)
                    if len(line) > 65_536:
                        raise ValueError("Oversized event")
                    if not line.strip() and chunks:
                        break
                    if line.startswith(b"data:"):
                        chunks.append(line[5:].decode().strip())
                if consumed > 1_048_576:
                    raise ValueError("Oversized response")
                payload = json.loads("\n".join(chunks))
            else:
                raw = response.read(1_048_577)
                if len(raw) > 1_048_576:
                    raise ValueError("Oversized response")
                payload = json.loads(raw)
        result = payload.get("result") if isinstance(payload, dict) else None
        info = result.get("serverInfo") if isinstance(result, dict) else None
        if (
            payload.get("jsonrpc") != "2.0"
            or payload.get("id") != 1
            or "error" in payload
            or not isinstance(info, dict)
            or not isinstance(result, dict)
            or not isinstance(result.get("capabilities"), dict)
            or not result.get("protocolVersion")
            or (expected_version and info.get("version") != expected_version)
        ):
            raise ValueError("Invalid initialize response")
        anonymous = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream", "User-Agent": _USER_AGENT},
        )
        try:
            with opener.open(anonymous, timeout=timeout):  # nosec B310 - same validated origin; no credentials
                raise ValueError("Anonymous MCP initialize must be rejected")
        except urllib.error.HTTPError as exc:
            exc.close()
            if exc.code not in {401, 403}:
                raise ValueError("Anonymous MCP rejection could not be verified") from exc
    except (OSError, ValueError, TypeError, AttributeError) as exc:
        # Never print response bodies, headers, request URLs or credential-bearing exceptions.
        raise RuntimeError(_initialize_failure_message(exc)) from exc


_PUBLIC_PROBE_DENIED_TOOL = "scan"
_MAX_RPC_BYTES = 1_048_576


def _secure_mcp_url(base_url: str | None) -> str:
    parts = urlsplit((base_url or DEFAULT_BASE_URL).strip())
    if parts.scheme != "https" or not parts.netloc or parts.username or parts.password:
        raise ValueError("MCP probe requires an HTTPS origin without URL credentials")
    path = parts.path.rstrip("/")
    if not path.endswith("/mcp"):
        path += "/mcp"
    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))


def _read_rpc_body(response: Any) -> Any:
    raw = response.read(_MAX_RPC_BYTES + 1)
    if len(raw) > _MAX_RPC_BYTES:
        raise ValueError("Oversized response")
    if not raw.strip():
        return None
    if response.headers.get_content_type() != "text/event-stream":
        return json.loads(raw)
    chunks = [line[5:].decode().strip() for line in raw.splitlines() if line.startswith(b"data:")]
    return json.loads("\n".join(chunks)) if chunks else None


def _post_rpc(opener: Any, url: str, message: dict[str, Any], session: dict[str, str], timeout: float) -> tuple[Any, Any]:
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream", "User-Agent": _USER_AGENT, **session}
    request = urllib.request.Request(url, data=json.dumps(message).encode(), headers=headers)
    with opener.open(request, timeout=timeout) as response:  # nosec B310 - HTTPS validated; redirects rejected
        return _read_rpc_body(response), response.headers


def _validated_initialize(payload: Any, expected_version: str | None) -> dict[str, Any]:
    result = payload.get("result") if isinstance(payload, dict) else None
    info = result.get("serverInfo") if isinstance(result, dict) else None
    if (
        not isinstance(payload, dict)
        or payload.get("jsonrpc") != "2.0"
        or payload.get("id") != 1
        or "error" in payload
        or not isinstance(result, dict)
        or not isinstance(info, dict)
        or not isinstance(result.get("capabilities"), dict)
        or not result.get("protocolVersion")
        or (expected_version and info.get("version") != expected_version)
    ):
        raise ValueError("Invalid initialize response")
    return result


def _expect_anonymous_rejection(opener: Any, url: str, session: dict[str, str], timeout: float) -> None:
    call = {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": _PUBLIC_PROBE_DENIED_TOOL, "arguments": {}}}
    try:
        _post_rpc(opener, url, call, session, timeout)
    except urllib.error.HTTPError as exc:
        exc.close()
        if exc.code == 401:
            return
        raise ValueError("Anonymous call outside the public tier was not answered with 401") from exc
    raise ValueError("Anonymous call outside the public tier must be rejected")


def verify_public_readonly(base_url: str | None, *, expected_version: str | None, timeout: float) -> list[str]:
    """Prove the anonymous tier answers its lookups and refuses everything else.

    Sends no credential: anonymous initialize and ``tools/list`` must succeed,
    and an anonymous call to a tool outside the tier must be HTTP 401. Returns
    the anonymously listed tool names for comparison with the server card.
    """
    url = _secure_mcp_url(base_url)
    opener = urllib.request.build_opener(_NoAuthRedirect())
    initialize = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": _USER_AGENT, "version": "1"}},
    }
    try:
        payload, headers = _post_rpc(opener, url, initialize, {}, timeout)
        result = _validated_initialize(payload, expected_version)
        session = {"mcp-protocol-version": str(result["protocolVersion"])}
        if headers.get("mcp-session-id"):
            session["mcp-session-id"] = str(headers.get("mcp-session-id"))
        _post_rpc(opener, url, {"jsonrpc": "2.0", "method": "notifications/initialized"}, session, timeout)
        listed, _ = _post_rpc(opener, url, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}, session, timeout)
        tools = listed.get("result", {}).get("tools") if isinstance(listed, dict) else None
        names = sorted(str(tool.get("name")) for tool in tools or [] if isinstance(tool, dict))
        if not names or _PUBLIC_PROBE_DENIED_TOOL in names:
            raise ValueError("Anonymous tools/list must list only the public lookup tools")
        _expect_anonymous_rejection(opener, url, session, timeout)
        return names
    except (OSError, ValueError, TypeError, AttributeError) as exc:
        raise RuntimeError(_initialize_failure_message(exc).replace("Authenticated", "Public read-only")) from exc


def validate_public_readonly_card(payload: dict[str, Any], anonymous_tools: list[str]) -> None:
    authentication = payload.get("authentication")
    if not isinstance(authentication, dict) or authentication.get("public_readonly") is not True:
        raise ValueError("server card does not declare the public read-only tier")
    if sorted(authentication.get("anonymous_tools") or []) != sorted(anonymous_tools):
        raise ValueError("server-card anonymous_tools differ from the anonymously listed tools")


def _initialize_failure_message(exc: BaseException) -> str:
    """Status-only description of a failed initialize: numeric HTTP code or exception class, never server text."""
    if isinstance(exc, urllib.error.HTTPError):
        kind = f"HTTP {exc.code}"
    elif isinstance(exc, urllib.error.URLError):
        kind = f"connection error: {type(exc.reason).__name__}"
    elif isinstance(exc, OSError):
        kind = f"connection error: {type(exc).__name__}"
    elif isinstance(exc, ValueError) and not isinstance(exc, json.JSONDecodeError):
        kind = str(exc)
    else:
        kind = f"malformed response: {type(exc).__name__}"
    return f"Authenticated MCP initialize failed ({kind}); check credential validity and deployed release"


def _fetch_json(
    url: str,
    *,
    bearer_token: str | None,
    attempts: int,
    backoff_seconds: float,
    timeout: float,
    validate_payload: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if attempts < 1:
        raise ValueError("attempts must be >= 1")

    headers = {"Accept": "application/json", "User-Agent": _USER_AGENT}
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"

    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        request = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310 - URL resolvers enforce http/https only
                payload = json.loads(response.read())
            if not isinstance(payload, dict):
                raise ValueError("deployment response must be a JSON object")
            if validate_payload is not None:
                payload = validate_payload(payload)
            return payload
        except (ValueError, json.JSONDecodeError, OSError, urllib.error.URLError) as exc:
            last_error = exc
            if attempt == attempts:
                break
            sleep_seconds = max(backoff_seconds, 0.0) * attempt
            if sleep_seconds:
                sys.stderr.write(f"Attempt {attempt}/{attempts} failed for {url}. Retrying in {sleep_seconds:.0f}s...\n")
                time.sleep(sleep_seconds)

    raise RuntimeError(f"unable to fetch deployment metadata from {url}: {last_error}")


def fetch_health(
    base_url: str | None,
    *,
    bearer_token: str | None = None,
    attempts: int = 1,
    backoff_seconds: float = 0.0,
    timeout: float = 15.0,
) -> tuple[str, dict[str, Any]]:
    """Fetch and parse the MCP health payload with retry support."""

    health_url = resolve_health_url(base_url)
    payload = _fetch_json(
        health_url,
        bearer_token=bearer_token,
        attempts=attempts,
        backoff_seconds=backoff_seconds,
        timeout=timeout,
    )
    return health_url, payload


def fetch_server_card(
    base_url: str | None,
    *,
    bearer_token: str | None = None,
    attempts: int = 1,
    backoff_seconds: float = 0.0,
    timeout: float = 15.0,
    expected_version: str | None = None,
    expected_tool_count: int | None = None,
) -> tuple[str, dict[str, Any]]:
    """Fetch the card, retrying until the optional exact release contract matches.

    A rolling deployment can serve valid JSON from the previous release while
    its replacement starts. Transport errors and contract mismatches share one
    attempt budget; exhaustion still fails closed.
    """

    if (expected_version is None) != (expected_tool_count is None):
        raise ValueError("expected_version and expected_tool_count must be supplied together")
    validate_payload = None
    if expected_version is not None and expected_tool_count is not None:
        validate_payload = partial(
            validate_server_card_release,
            expected_version=expected_version,
            expected_tool_count=expected_tool_count,
        )

    server_card_url = resolve_server_card_url(base_url)
    payload = _fetch_json(
        server_card_url,
        bearer_token=bearer_token,
        attempts=attempts,
        backoff_seconds=backoff_seconds,
        timeout=timeout,
        validate_payload=validate_payload,
    )
    return server_card_url, payload


def validate_health_payload(
    payload: dict[str, Any],
    *,
    forbid_auth_required: bool = False,
) -> dict[str, Any]:
    """Validate parsed health payload contract for deployment checks."""

    if not isinstance(payload, dict):
        raise ValueError("health response must be a JSON object")
    if forbid_auth_required and bool(payload.get("auth_required")):
        raise ValueError("deployment surface requires auth and is not suitable for public registry publishing")
    return payload


def validate_server_card_release(
    payload: dict[str, Any],
    *,
    expected_version: str,
    expected_tool_count: int,
) -> dict[str, Any]:
    """Require exact version, inventory, and usable schemas for a release."""

    server_info = payload.get("serverInfo")
    if not isinstance(server_info, dict) or server_info.get("version") != expected_version:
        deployed = server_info.get("version") if isinstance(server_info, dict) else None
        raise ValueError(f"server-card version mismatch: deployed={deployed!r} expected={expected_version!r}")

    tools = payload.get("tools")
    if not isinstance(tools, list) or len(tools) != expected_tool_count:
        actual = len(tools) if isinstance(tools, list) else None
        raise ValueError(f"server-card tool count mismatch: deployed={actual!r} expected={expected_tool_count}")

    names: list[str] = []
    for tool in tools:
        if not isinstance(tool, dict) or not isinstance(tool.get("name"), str) or not tool["name"].strip():
            raise ValueError("server-card tool schema is missing a non-empty name")
        if not isinstance(tool.get("inputSchema"), dict):
            raise ValueError(f"server-card tool schema is missing inputSchema for {tool['name']!r}")
        names.append(tool["name"])
    if len(set(names)) != len(names):
        raise ValueError("server-card tool schema contains duplicate tool names")
    return payload


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Probe the MCP health endpoint used by CI workflows.")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help="Railway base URL or MCP endpoint URL.")
    parser.add_argument(
        "--bearer-token",
        default=os.environ.get("AGENT_BOM_DEPLOYMENT_BEARER_TOKEN"),
        help="Optional bearer token for authenticated probes.",
    )
    parser.add_argument("--attempts", type=int, default=1, help="Number of probe attempts before failing.")
    parser.add_argument(
        "--backoff-seconds",
        type=float,
        default=0.0,
        help="Linear backoff between attempts. Attempt N sleeps N * backoff seconds.",
    )
    parser.add_argument("--timeout", type=float, default=15.0, help="Per-request timeout in seconds.")
    parser.add_argument(
        "--resolve-only",
        action="store_true",
        help="Print the normalized health URL without making a network request.",
    )
    parser.add_argument(
        "--forbid-auth-required",
        action="store_true",
        help="Fail if the health payload reports auth_required=true.",
    )
    parser.add_argument(
        "--server-card",
        action="store_true",
        help="Probe the public MCP server card instead of /health.",
    )
    parser.add_argument(
        "--require-mcp-auth", action="store_true", help="Also require authenticated MCP initialize; public metadata alone cannot pass."
    )
    parser.add_argument(
        "--require-public-readonly",
        action="store_true",
        help="Require the anonymous read-only tier: lookups answer without a credential, other tools are HTTP 401.",
    )
    parser.add_argument("--expected-version", default=None, help="Exact release version required from the server card.")
    parser.add_argument("--expected-tool-count", type=int, default=None, help="Exact released MCP tool count required.")
    return parser


def _retry_public_probe(args: argparse.Namespace) -> list[str]:
    if args.attempts < 1:
        raise ValueError("attempts must be >= 1")
    for attempt in range(1, args.attempts + 1):
        try:
            return verify_public_readonly(args.base_url, expected_version=args.expected_version, timeout=args.timeout)
        except RuntimeError:
            if attempt == args.attempts:
                raise
            delay = max(args.backoff_seconds, 0.0) * attempt
            if delay:
                time.sleep(delay)
    raise RuntimeError("public read-only probe did not run")


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        if args.resolve_only:
            sys.stdout.write(f"{resolve_health_url(args.base_url)}\n")
            return 0

        if args.require_public_readonly and args.require_mcp_auth:
            raise ValueError("--require-public-readonly and --require-mcp-auth are mutually exclusive")
        anonymous_tools = _retry_public_probe(args) if args.require_public_readonly else None
        if args.require_mcp_auth:
            if args.attempts < 1:
                raise ValueError("attempts must be >= 1")
            # A detached deployment can still serve the previous version.
            # Retry the authenticated contract, retaining fail-closed behavior:
            # public metadata is never accepted after exhausted auth attempts.
            for attempt in range(1, args.attempts + 1):
                try:
                    verify_mcp_auth(
                        args.base_url, bearer_token=args.bearer_token, expected_version=args.expected_version, timeout=args.timeout
                    )
                    break
                except RuntimeError:
                    if attempt == args.attempts:
                        raise
                    delay = max(args.backoff_seconds, 0.0) * attempt
                    if delay:
                        time.sleep(delay)

        if args.server_card:
            if not args.expected_version or args.expected_tool_count is None:
                raise ValueError("--server-card requires --expected-version and --expected-tool-count")
            _, payload = fetch_server_card(
                args.base_url,
                bearer_token=args.bearer_token,
                attempts=args.attempts,
                backoff_seconds=args.backoff_seconds,
                timeout=args.timeout,
                expected_version=args.expected_version,
                expected_tool_count=args.expected_tool_count,
            )
            if anonymous_tools is not None:
                validate_public_readonly_card(payload, anonymous_tools)
        else:
            _, payload = fetch_health(
                args.base_url,
                bearer_token=args.bearer_token,
                attempts=args.attempts,
                backoff_seconds=args.backoff_seconds,
                timeout=args.timeout,
            )
            payload = validate_health_payload(
                payload,
                forbid_auth_required=args.forbid_auth_required,
            )
    except (RuntimeError, ValueError) as exc:
        sys.stderr.write(f"{exc}\n")
        return 1

    json.dump(payload, sys.stdout, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
