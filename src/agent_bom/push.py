"""Hybrid push-to-dashboard — CLI local scan → push results to central dashboard.

Sanitizes results before push:
- Strips local config_path from agents
- Redacts environment variable values
- Adds stable source_id for tracking
"""

from __future__ import annotations

import asyncio
import gzip
import hashlib
import json
import logging
import platform
from typing import Any, Literal, overload

import httpx

from agent_bom import config
from agent_bom.core.settings import env_float, env_list, env_str
from agent_bom.security import (
    sanitize_command_args,
    sanitize_env_vars,
    sanitize_security_warnings,
    sanitize_sensitive_payload,
    sanitize_text,
    sanitize_url,
)

logger = logging.getLogger(__name__)

_LOCAL_CONTROL_PLANE_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
# Finding identities whose names match the secret heuristic. They take the
# server's coordinate policy instead, which still redacts credential-shaped values.
_IDENTITY_KEYS = frozenset({"finding_group_key"})

SCAN_PUSH_PATH = "/v1/results/push"
#: One push is stored as one job result, which must fit PostgreSQL's 255 MiB jsonb value limit even with
#: the result codec off; no configuration accepts a larger decoded push, so the CLI refuses one before uploading.
RESULT_PUSH_JSONB_CEILING_BYTES = 240 * 1024 * 1024


def normalize_scan_push_url(push_url: str) -> str:
    """Resolve a control-plane URL to the scan-report ingest endpoint.

    Mirrors ``agent_bom.fleet.sync_client._default_fleet_sync_url``: a base URL —
    including one behind a reverse-proxy path prefix — grows
    :data:`SCAN_PUSH_PATH`, while a URL that already names a versioned API path
    is left alone so ``/v1/fleet/sync`` inventory pushes keep working. Anything
    that is not an absolute http(s) URL is returned untouched for the outbound
    URL policy to reject with its own message.
    """
    from urllib.parse import urlsplit, urlunsplit

    candidate = (push_url or "").strip()
    parsed = urlsplit(candidate)
    if not parsed.scheme or not parsed.netloc:
        return candidate

    path = parsed.path.rstrip("/")
    segments = [segment for segment in path.split("/") if segment]
    if "v1" not in segments:
        path += SCAN_PUSH_PATH
    elif segments[-1] == "v1":
        path += SCAN_PUSH_PATH[len("/v1") :]
    return urlunsplit(parsed._replace(path=path))


def _validate_push_destination_url(push_url: str) -> None:
    """Validate fleet/scan push URLs with the same local-pilot carve-out as findings push."""
    from urllib.parse import urlparse

    from agent_bom.security import validate_url

    host = (urlparse(push_url).hostname or "").lower()
    allow_local = host in _LOCAL_CONTROL_PLANE_HOSTS
    validate_url(
        push_url,
        allowed_schemes=("https", "http") if allow_local else ("https",),
        allow_private=allow_local,
    )


def _csv_env(name: str) -> list[str]:
    return list(env_list(name))


def _endpoint_identity_from_env() -> dict[str, str | list[str]]:
    return {
        "source_id": generate_source_id(),
        "enrollment_name": env_str("AGENT_BOM_PUSH_ENROLLMENT_NAME"),
        "owner": env_str("AGENT_BOM_PUSH_OWNER"),
        "environment": env_str("AGENT_BOM_PUSH_ENVIRONMENT"),
        "mdm_provider": env_str("AGENT_BOM_PUSH_MDM_PROVIDER"),
        "tags": _csv_env("AGENT_BOM_PUSH_TAGS"),
    }


def generate_source_id() -> str:
    """Generate a stable machine identifier (hostname SHA256[:12])."""
    configured = env_str("AGENT_BOM_PUSH_SOURCE_ID")
    if configured:
        return configured
    hostname = platform.node() or "unknown"
    return hashlib.sha256(hostname.encode()).hexdigest()[:12]


def sanitize_results(
    results: dict, *, source_id: str | None = None, idempotency_key: str | None = None, idempotency_target: str = ""
) -> dict:
    """Deep-copy results and strip sensitive data before push.

    - Removes config_path from agents
    - Redacts env var patterns in metadata
    - Adds source_id: the explicit producer target when given (a connector
      team or project), otherwise this machine's stable endpoint identity
    """
    # The recursive redactor builds new containers; a preliminary deep copy
    # duplicated the entire report without adding isolation.
    sanitized = _redact_nested_secrets(results)

    endpoint_identity = _endpoint_identity_from_env()

    # Strip config_path from agents
    for agent in sanitized.get("agents", []):
        agent.pop("config_path", None)
        for key in ("source_id", "enrollment_name", "owner", "environment", "mdm_provider"):
            value = endpoint_identity.get(key, "")
            if value and not agent.get(key):
                agent[key] = value
        tags = endpoint_identity.get("tags", [])
        if tags and not agent.get("tags"):
            agent["tags"] = tags

    # Add source identifier
    sanitized["source_id"] = source_id or str(endpoint_identity["source_id"])
    sanitized.pop("idempotency_key", None)
    sanitized["idempotency_key"] = idempotency_key or content_idempotency_key(sanitized, target=idempotency_target)

    return sanitized


def content_idempotency_key(sanitized: dict, *, target: str = "") -> str:
    """Stable key for one sanitized report and destination.

    Re-pushing the same report (a retry, or a rerun of the same file) yields
    the same key, so the server dedupes it onto the job it already holds.
    """
    material = {key: value for key, value in sanitized.items() if key != "idempotency_key"}
    digest = hashlib.sha256(target.encode("utf-8") + b"\0")
    digest.update(json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8"))
    return f"report-{digest.hexdigest()}"


def _looks_like_secret(key: str) -> bool:
    """Check if a metadata key name looks like it holds a secret."""
    patterns = ("token", "key", "secret", "password", "credential", "auth")
    lower = key.lower()
    return any(p in lower for p in patterns)


def _redact_nested_secrets(value):
    if isinstance(value, dict):
        redacted: dict[object, object] = {}
        for key, child in value.items():
            key_text = str(key)
            if key_text == "args" and isinstance(child, list):
                redacted[key] = sanitize_command_args(child)
            elif key_text == "command" and isinstance(child, str):
                redacted[key] = sanitize_text(child, max_len=200)
            elif key_text == "url" and isinstance(child, str):
                redacted[key] = sanitize_url(child)
            elif key_text == "env" and isinstance(child, dict):
                redacted[key] = sanitize_env_vars(child)
            elif key_text == "security_warnings" and isinstance(child, list):
                redacted[key] = sanitize_security_warnings(child)
            elif key_text in _IDENTITY_KEYS and isinstance(child, str):
                redacted[key] = sanitize_sensitive_payload(child, key=key_text)
            elif _looks_like_secret(key_text) and isinstance(child, (str, int, float)) and not isinstance(child, bool):
                # A boolean cannot carry a secret value; redacting one corrupts
                # receipts such as ``authenticated``.
                redacted[key] = "***REDACTED***"
            else:
                redacted[key] = _redact_nested_secrets(child)
        return redacted
    if isinstance(value, list):
        return [_redact_nested_secrets(item) for item in value]
    return value


def _serialize_push_payload(sanitized: Any) -> bytes:
    return json.dumps(sanitized, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def _compress_push_payload(payload: bytes) -> tuple[bytes, dict[str, str]]:
    if not config.PUSH_GZIP:
        return payload, {}
    return gzip.compress(payload, compresslevel=1, mtime=0), {"Content-Encoding": "gzip"}


def _encode_push_payload(sanitized: Any) -> tuple[bytes, dict[str, str]]:
    """Serialize a push body once; gzip it (default) and return the matching headers."""
    return _compress_push_payload(_serialize_push_payload(sanitized))


class PushAuthError(Exception):
    """A scan push the control plane refused for authentication; the message names the fix, never the key."""

    def __init__(self, *, status: int, key_sent: bool) -> None:
        self.status = status
        self.key_sent = key_sent
        how = "Pass the key with --push-api-key or the AGENT_BOM_PUSH_API_KEY environment variable"
        dev = 'a local `agent-bom up` or `agent-bom serve` prints its key at startup as "Dev API key" and mints a new one each start'
        if not key_sent:
            message = f"the control plane requires an API key (HTTP {status}). {how}; {dev}"
        elif status == 403:
            message = f"the API key is not permitted to push results (HTTP {status}). {how} using a key allowed to push; {dev}"
        else:
            message = f"the control plane rejected the API key (HTTP {status}). {how}; {dev}"
        super().__init__(message)


class PushTooLargeError(Exception):
    """A scan push the control plane cannot store; carries the numbers to split it by."""

    def __init__(self, *, decoded_bytes: int, max_bytes: int | None, agents: int, server_refused: bool) -> None:
        self.decoded_bytes = decoded_bytes
        self.max_bytes = max_bytes
        self.agents = agents
        per_agent = decoded_bytes / agents if agents else 0
        # 10% margin: agents differ in size, and a split by count is only an estimate.
        self.agents_per_push = int(max_bytes * 0.9 // per_agent) if max_bytes and per_agent else 0
        super().__init__(self._message(server_refused))

    def _message(self, server_refused: bool) -> str:
        size = f"The report is {_size(self.decoded_bytes)} decoded ({self.agents:,} agents)"
        if self.max_bytes is None:
            refused = "the control plane or a proxy in front of it refused it as too large (413)"
            return f"{size}; {refused}. Split the inventory into smaller scans."
        limit = "this control plane accepts at most" if server_refused else "no control plane accepts more than"
        advice = (
            f"Push at most {self.agents_per_push:,} agents per push: split the inventory into files of that many agents "
            "and run one scan per file (agent-bom agents --inventory FILE --push-url ...). Each file is its own target, "
            "so its next push replaces only its own earlier evidence."
            if self.agents_per_push
            else "Split the scan into smaller targets."
        )
        return f"{size}; {limit} {_size(self.max_bytes)} per push, because one push is stored as one scan result. {advice}"


def _size(value: int) -> str:
    return f"{value / (1024 * 1024):,.1f} MiB" if value >= 1024 * 1024 else f"{value / 1024:,.1f} KiB"


def _oversize_before_upload(push_url: str, decoded_bytes: int, agents: int) -> PushTooLargeError | None:
    ceiling = RESULT_PUSH_JSONB_CEILING_BYTES
    if push_url.rstrip("/").endswith(SCAN_PUSH_PATH) and decoded_bytes > ceiling:
        return PushTooLargeError(decoded_bytes=decoded_bytes, max_bytes=ceiling, agents=agents, server_refused=False)
    return None


def _push_tls_cert() -> str | tuple[str, str] | None:
    cert_file = env_str("AGENT_BOM_PUSH_TLS_CERT_FILE")
    key_file = env_str("AGENT_BOM_PUSH_TLS_KEY_FILE")
    if cert_file and key_file:
        return cert_file, key_file
    if cert_file or key_file:
        logger.warning("Ignoring partial collector push TLS config; set both AGENT_BOM_PUSH_TLS_CERT_FILE and AGENT_BOM_PUSH_TLS_KEY_FILE")
    return None


def _push_tls_verify() -> bool | str:
    ca_file = env_str("AGENT_BOM_PUSH_TLS_CA_FILE")
    return ca_file if ca_file else True


_DEFAULT_PUSH_MAX_ATTEMPTS = 3
_DEFAULT_PUSH_BASE_DELAY = 1.0
_DEFAULT_PUSH_MAX_DELAY = 30.0


def _push_retry_delay(attempt: int, base: float, cap: float) -> float:
    """Exponential backoff with small jitter bounded by cap."""
    import random

    exp = base * (2 ** (attempt - 1))
    jitter = random.uniform(0, exp * 0.1)
    return min(cap, exp + jitter)


@overload
async def _push_async(
    push_url: str,
    results: dict,
    api_key: str | None = None,
    *,
    max_attempts: int = _DEFAULT_PUSH_MAX_ATTEMPTS,
    base_delay_seconds: float = _DEFAULT_PUSH_BASE_DELAY,
    max_delay_seconds: float = _DEFAULT_PUSH_MAX_DELAY,
    return_body: Literal[False] = False,
    source_id: str | None = None,
    idempotency_key: str | None = None,
) -> bool:
    """Push results and return only whether delivery succeeded."""


@overload
async def _push_async(
    push_url: str,
    results: dict,
    api_key: str | None = None,
    *,
    max_attempts: int = _DEFAULT_PUSH_MAX_ATTEMPTS,
    base_delay_seconds: float = _DEFAULT_PUSH_BASE_DELAY,
    max_delay_seconds: float = _DEFAULT_PUSH_MAX_DELAY,
    return_body: Literal[True],
    source_id: str | None = None,
    idempotency_key: str | None = None,
) -> tuple[bool, dict[str, Any] | None]:
    """Push results and also return the parsed response body."""


async def _push_async(
    push_url: str,
    results: dict,
    api_key: str | None = None,
    *,
    max_attempts: int = _DEFAULT_PUSH_MAX_ATTEMPTS,
    base_delay_seconds: float = _DEFAULT_PUSH_BASE_DELAY,
    max_delay_seconds: float = _DEFAULT_PUSH_MAX_DELAY,
    return_body: bool = False,
    source_id: str | None = None,
    idempotency_key: str | None = None,
) -> bool | tuple[bool, dict[str, Any] | None]:
    """POST sanitized results to the central dashboard with bounded retries.

    The idempotency key defaults to a hash of the sanitized report and its
    destination, so a rerun or retry of the same report addresses the same
    server job instead of creating a duplicate. Retries cover network errors,
    408/425/429/5xx and a 409 carrying ``Retry-After`` (an identical push still
    committing on an older server). A ``202`` (asynchronous ingest) is followed
    by polling ``status_url``; a push the server accepted is never reported as
    failed. Non-retryable 4xx responses short-circuit.
    """
    from agent_bom.http_client import create_client
    from agent_bom.security import SecurityError

    sanitized = await asyncio.to_thread(
        sanitize_results, results, source_id=source_id, idempotency_key=idempotency_key, idempotency_target=push_url
    )
    try:
        _validate_push_destination_url(push_url)
    except SecurityError as exc:
        logger.error("Push URL rejected by outbound URL policy: %s", exc)
        return (False, None) if return_body else False

    auth_headers: dict[str, str] = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    headers: dict[str, str] = {
        "Content-Type": "application/json",
        "Prefer": "respond-async",
        "Idempotency-Key": str(sanitized["idempotency_key"]),
        **auth_headers,
    }
    # Serialize once and reuse exactly the same bytes and idempotency identity
    # for every retry. Compression is on by default; AGENT_BOM_PUSH_GZIP=0 keeps
    # a receiver that predates gzip push support working.
    decoded = await asyncio.to_thread(_serialize_push_payload, sanitized)
    agents = len(sanitized.get("agents") or []) if isinstance(sanitized, dict) else 0
    if too_large := _oversize_before_upload(push_url, len(decoded), agents):
        return _too_large(too_large, return_body=return_body)
    payload, encoding_headers = await asyncio.to_thread(_compress_push_payload, decoded)
    decoded_bytes = len(decoded)
    del decoded
    headers.update(encoding_headers)
    timeout = _push_timeout_seconds(len(payload), compressed=bool(encoding_headers))

    outcome = _PushOutcome()
    async with create_client(timeout=timeout, cert=_push_tls_cert(), verify=_push_tls_verify()) as client:
        for attempt in range(1, max_attempts + 1):
            retry_after = await _push_attempt(client, push_url, payload, headers, auth_headers, attempt, max_attempts, outcome)
            if outcome.done:
                break
            if attempt < max_attempts:
                await asyncio.sleep(
                    max(_push_retry_delay(attempt, base_delay_seconds, max_delay_seconds), min(retry_after, max_delay_seconds))
                )

    if outcome.ok:
        return (True, outcome.body or {}) if return_body else True
    if outcome.too_large:
        refused = PushTooLargeError(decoded_bytes=decoded_bytes, max_bytes=outcome.max_bytes, agents=agents, server_refused=True)
        return _too_large(refused, return_body=return_body)
    if not outcome.done:
        logger.error("Push failed after %d attempts (last_status=%s, last_error=%s)", max_attempts, outcome.last_status, outcome.last_error)
    if outcome.last_status in (401, 403) and not return_body:
        raise PushAuthError(status=outcome.last_status, key_sent=bool(api_key))
    return (False, None) if return_body else False


def _too_large(error: PushTooLargeError, *, return_body: bool) -> tuple[bool, None]:
    """Scan pushes raise so the CLI can print the split advice; body-returning callers log it and fail."""
    if not return_body:
        raise error
    logger.error("%s", error)
    return False, None


class _PushOutcome:
    def __init__(self) -> None:
        self.ok = False
        self.done = False
        self.too_large = False
        self.max_bytes: int | None = None
        self.body: dict[str, Any] | None = None
        self.last_status: int | None = None
        self.last_error: str | None = None


def _response_json(resp: Any) -> dict[str, Any]:
    try:
        parsed = resp.json()
    except ValueError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


async def _push_attempt(
    client: Any,
    push_url: str,
    payload: bytes,
    headers: dict[str, str],
    auth_headers: dict[str, str],
    attempt: int,
    max_attempts: int,
    outcome: _PushOutcome,
) -> float:
    """Run one POST; record the outcome and return the server's ``Retry-After`` hint."""
    from agent_bom.security import sanitize_error

    try:
        resp = await client.post(push_url, content=payload, headers=headers)
    except (httpx.HTTPError, ValueError, OSError) as exc:
        outcome.last_error = f"{type(exc).__name__}: {sanitize_error(exc)}"
        logger.warning("Push attempt %d/%d failed with %s", attempt, max_attempts, outcome.last_error)
        return 0.0
    outcome.last_status = resp.status_code
    retry_after = _retry_after_seconds(resp)
    if resp.status_code == 202:
        receipt = await _await_push_receipt(client, push_url, _response_json(resp), auth_headers, retry_after)
        if receipt.get("status") == "failed":
            outcome.last_error = "server ingest failed; resubmitting the same report"
            logger.warning("Push attempt %d/%d: server ingest failed; retrying with the same idempotency key", attempt, max_attempts)
            return retry_after
        outcome.ok, outcome.done, outcome.body = True, True, receipt
        logger.info("Results accepted by configured endpoint (status=%s, attempt=%d)", receipt.get("status"), attempt)
        return 0.0
    if resp.status_code < 300:
        outcome.ok, outcome.done = True, True
        outcome.body = _response_json(resp) if resp.status_code != 204 else {}
        logger.info("Results pushed to configured endpoint (status=%d, attempt=%d)", resp.status_code, attempt)
        return 0.0
    if resp.status_code == 413 and push_url.rstrip("/").endswith(SCAN_PUSH_PATH):
        budget = _response_json(resp).get("max_bytes")
        outcome.too_large, outcome.done = True, True
        outcome.max_bytes = budget if isinstance(budget, int) and not isinstance(budget, bool) and budget > 0 else None
        return 0.0
    if resp.status_code in _RETRYABLE_PUSH_STATUS or (resp.status_code == 409 and retry_after > 0):
        outcome.last_error = sanitize_text(resp.text[:200])
        logger.warning("Push attempt %d/%d returned retryable status %d", attempt, max_attempts, resp.status_code)
        return retry_after
    logger.warning("Push rejected with non-retryable status %d — %s", resp.status_code, sanitize_text(resp.text[:200]))
    outcome.done = True
    return 0.0


_RETRYABLE_PUSH_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})


def _retry_after_seconds(resp: Any) -> float:
    headers = getattr(resp, "headers", None)
    raw = headers.get("Retry-After") if isinstance(headers, (dict, httpx.Headers)) else None
    try:
        return max(0.0, float(raw)) if raw is not None else 0.0
    except (TypeError, ValueError):
        return 0.0


def _push_timeout_seconds(wire_bytes: int, *, compressed: bool) -> float:
    """Read timeout sized to the decoded report: large synchronous commits take minutes."""
    decoded_mb = wire_bytes * (17 if compressed else 1) / (1024 * 1024)
    return float(min(_MAX_PUSH_TIMEOUT_SECONDS, max(30.0, 30.0 + 2.0 * decoded_mb)))


_MAX_PUSH_TIMEOUT_SECONDS = 900.0


def _push_status_url(push_url: str, status_url: Any) -> str | None:
    """Resolve the server's relative ``status_url`` against the push URL; never follow another host."""
    if not isinstance(status_url, str) or not status_url.startswith("/v1/") or "//" in status_url or ".." in status_url:
        return None
    base = push_url[: -len(SCAN_PUSH_PATH)] if push_url.rstrip("/").endswith(SCAN_PUSH_PATH) else push_url.rstrip("/")
    return base.rstrip("/") + status_url


async def _await_push_receipt(
    client: Any, push_url: str, accepted: dict[str, Any], auth_headers: dict[str, str], retry_after: float
) -> dict[str, Any]:
    """Poll an accepted push until it is stored or failed, or the wait budget ends.

    Running out of wait budget is not a failure: the server holds the report
    durably and finishes it; the accepted receipt is returned as-is.
    """
    url = _push_status_url(push_url, accepted.get("status_url"))
    if url is None:
        return accepted
    deadline = asyncio.get_running_loop().time() + max(0.0, env_float("AGENT_BOM_PUSH_WAIT_SECONDS", 900.0))
    delay = max(1.0, retry_after or 2.0)
    latest = accepted
    while asyncio.get_running_loop().time() < deadline:
        await asyncio.sleep(delay)
        delay = min(10.0, delay * 1.5)
        try:
            resp = await client.get(url, headers=auth_headers)
        except (httpx.HTTPError, ValueError, OSError):
            continue
        if resp.status_code == 404:
            return latest
        if resp.status_code != 200:
            continue
        receipt = _response_json(resp)
        if receipt.get("status") in {"stored", "failed"}:
            return receipt
        latest = receipt or latest
    logger.info("Push accepted; the server is still ingesting it (status_url=%s)", sanitize_text(str(accepted.get("status_url"))))
    return latest


def _version_url(push_url: str) -> str | None:
    from urllib.parse import urlsplit, urlunsplit

    parsed = urlsplit(push_url)
    if not parsed.scheme or not parsed.path.rstrip("/").endswith(SCAN_PUSH_PATH):
        return None
    base = parsed.path.rstrip("/")[: -len(SCAN_PUSH_PATH)]
    return urlunsplit(parsed._replace(path=f"{base}/version", query="", fragment=""))


async def _server_report_schemas(push_url: str, api_key: str | None) -> list[str]:
    from agent_bom.http_client import create_client
    from agent_bom.security import SecurityError

    url = _version_url(push_url)
    if url is None:
        return []
    try:
        _validate_push_destination_url(url)
    except SecurityError:
        return []
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    try:
        async with create_client(timeout=10.0, cert=_push_tls_cert(), verify=_push_tls_verify()) as client:
            resp = await client.get(url, headers=headers)
    except (httpx.HTTPError, OSError, ValueError):
        return []
    if resp.status_code != 200:
        return []
    versions = _response_json(resp).get("report_schema_versions")
    return [str(item) for item in versions] if isinstance(versions, list) else []


def negotiate_push_report_format(push_url: str, api_key: str | None = None, *, requested: str = "v2") -> str:
    """Report format to push: ``v2`` only when the control plane lists schema 2.0, else ``legacy``.

    A control plane older than 0.115.0 does not advertise the field and would
    store a 2.0 report without expanding it, so any doubt pushes 1.0.
    """
    from agent_bom.output.report_packing import REPORT_SCHEMA_V2

    if requested != "v2":
        return "legacy"
    return "v2" if REPORT_SCHEMA_V2 in asyncio.run(_server_report_schemas(push_url, api_key)) else "legacy"


def push_results(push_url: str, results: dict, api_key: str | None = None) -> bool:
    """Synchronous wrapper for pushing results to a dashboard."""
    result = asyncio.run(_push_async(push_url, results, api_key))
    return bool(result)


def push_json(
    push_url: str, results: dict, api_key: str | None = None, *, source_id: str | None = None, idempotency_key: str | None = None
) -> dict | None:
    """POST sanitized JSON and return the parsed response body on success."""
    pushed = asyncio.run(_push_async(push_url, results, api_key, return_body=True, source_id=source_id, idempotency_key=idempotency_key))
    if not isinstance(pushed, tuple):
        return None
    ok, body = pushed
    return body if ok else None
