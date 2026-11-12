"""Endpoint evidence for self-hosted model-serving runtimes.

One call probes one operator-selected endpoint of one declared runtime with the
runtime's documented, read-only inventory request:

=========  ===========================================  ==============================
runtime    inventory read                               runtime metadata read
=========  ===========================================  ==============================
vllm       ``GET /v1/models``                           ``GET /version``
tgi        ``GET /info``                                (same response)
triton     ``POST /v2/repository/index`` (``{}`` body)  ``GET /v2``
llamacpp   ``GET /v1/models``                           ``GET /props``
lmstudio   ``GET /api/v0/models``                       none documented
=========  ===========================================  ==============================

The result is one of ``success``, ``partial``, ``denied``, ``timeout`` or
``unavailable``. Only ``success`` and ``partial`` produce inventory; every other
outcome produces an explicit incomplete warning and no records, so a failed
endpoint can never read as a verified empty estate. Nothing falls back to local
files. Listing a model proves neither public reachability, authentication,
TLS, load policy, quotas nor logging; those stay ``not_collected``.

A protected endpoint can be paired with a bearer token held in a dedicated
environment variable (see :mod:`agent_bom.cloud.serving_auth`). The token goes
only to that endpoint, redirects are never followed, and evidence records only
whether a token was sent.
"""

from __future__ import annotations

import ipaddress
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

import httpx

from agent_bom.cloud.serving_auth import ServingAuthError, bearer_token, validate_token_env_name
from agent_bom.discovery_envelope import RedactionStatus, ScanMode, attach_envelope_to_agents
from agent_bom.models import Agent, AgentType, MCPServer, Package, ServerSurface
from agent_bom.security import SecurityError, validate_url

logger = logging.getLogger(__name__)

_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
_DEFAULT_TIMEOUT = 5.0

# Every read this module may send. A probe refuses any request missing here.
_SERVING_PERMISSIONS: tuple[str, ...] = (
    "llamacpp:GET /props",
    "llamacpp:GET /v1/models",
    "lmstudio:GET /api/v0/models",
    "tgi:GET /info",
    "triton:GET /v2",
    "triton:POST /v2/repository/index",
    "vllm:GET /v1/models",
    "vllm:GET /version",
)


def _declared(runtime: str, method: str, path: str) -> str:
    permission = f"{runtime}:{method} {path}"
    if permission not in _SERVING_PERMISSIONS:
        raise ValueError(f"undeclared serving read: {permission}")
    return permission


NOT_COLLECTED = (
    "bind_address",
    "public_reachability",
    "tls",
    "authentication",
    "model_load_policy",
    "rate_limits",
    "quotas",
    "logging",
    "persistence",
)


@dataclass(frozen=True)
class ServedModel:
    """One model record exactly as the endpoint reported it."""

    served_name: str
    artifact_ref: str | None = None
    digest: str | None = None
    version: str | None = None
    state: str | None = None


@dataclass
class EndpointObservation:
    """Outcome of probing one endpoint; never mixes in evidence from elsewhere."""

    runtime: str
    endpoint: str
    status: str
    detail: str = ""
    models: list[ServedModel] = field(default_factory=list)
    runtime_version: str | None = None
    runtime_identity: str = "declared"
    request_identity: str = "anonymous"
    permissions_used: tuple[str, ...] = ()
    observed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def completeness(self) -> str:
        return {"success": "complete", "partial": "partial"}.get(self.status, "none")


class _ProbeError(Exception):
    def __init__(self, status: str, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail


Parsed = tuple[list[ServedModel], int, str | None, bool]
"""(models, dropped_record_count, runtime_version, runtime_confirmed)."""


def _text(value: Any) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _openai_list(payload: Any, owner: str) -> Parsed:
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, list):
        raise _ProbeError("unavailable", "response did not match the documented model list")
    models: list[ServedModel] = []
    dropped = 0
    owners: set[str] = set()
    for entry in data:
        name = _text(entry.get("id")) if isinstance(entry, dict) else None
        if name is None:
            dropped += 1
            continue
        owners.add(str(entry.get("owned_by")))
        models.append(ServedModel(served_name=name, artifact_ref=_text(entry.get("root"))))
    return models, dropped, None, bool(models) and owners == {owner}


def _vllm(payload: Any) -> Parsed:
    return _openai_list(payload, "vllm")


def _llamacpp(payload: Any) -> Parsed:
    return _openai_list(payload, "llamacpp")


def _lmstudio(payload: Any) -> Parsed:
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, list):
        raise _ProbeError("unavailable", "response did not match the documented model list")
    models: list[ServedModel] = []
    dropped = 0
    native = False
    for entry in data:
        name = _text(entry.get("id")) if isinstance(entry, dict) else None
        if name is None:
            dropped += 1
            continue
        native = native or "compatibility_type" in entry
        models.append(ServedModel(served_name=name, state=_text(entry.get("state"))))
    return models, dropped, None, native


def _tgi(payload: Any) -> Parsed:
    name = _text(payload.get("model_id")) if isinstance(payload, dict) else None
    if name is None:
        raise _ProbeError("unavailable", "response did not match the documented /info schema")
    version = _text(payload.get("version"))
    model = ServedModel(served_name=name, artifact_ref=name, digest=_text(payload.get("model_sha")))
    # A response without the required ``version`` field is an incomplete record.
    return [model], 0 if version else 1, version, "router" in payload


def _triton(payload: Any) -> Parsed:
    if not isinstance(payload, list):
        raise _ProbeError("unavailable", "response did not match the documented repository index")
    models: list[ServedModel] = []
    dropped = 0
    for entry in payload:
        name = _text(entry.get("name")) if isinstance(entry, dict) else None
        if name is None:
            dropped += 1
            continue
        models.append(ServedModel(served_name=name, version=_text(entry.get("version")), state=_text(entry.get("state"))))
    return models, dropped, None, False


def _version_field(key: str) -> Callable[[Any], str | None]:
    return lambda payload: _text(payload.get(key)) if isinstance(payload, dict) else None


def _triton_metadata(payload: Any) -> str | None:
    if isinstance(payload, dict) and payload.get("name") == "triton":
        return _text(payload.get("version"))
    return None


@dataclass(frozen=True)
class RuntimeSpec:
    method: str
    path: str
    parse: Callable[[Any], Parsed]
    metadata_path: str | None = None
    metadata_version: Callable[[Any], str | None] | None = None


SERVING_RUNTIMES: dict[str, RuntimeSpec] = {
    "vllm": RuntimeSpec("GET", "/v1/models", _vllm, "/version", _version_field("version")),
    "tgi": RuntimeSpec("GET", "/info", _tgi),
    "triton": RuntimeSpec("POST", "/v2/repository/index", _triton, "/v2", _triton_metadata),
    "llamacpp": RuntimeSpec("GET", "/v1/models", _llamacpp, "/props", _version_field("build_info")),
    "lmstudio": RuntimeSpec("GET", "/api/v0/models", _lmstudio),
}


def normalize_endpoint(endpoint: str) -> str:
    """Return ``scheme://host[:port][/path]`` or raise ``_ProbeError`` for an unsafe endpoint."""
    try:
        parts = urlsplit(str(endpoint).strip())
    except ValueError as exc:
        raise _ProbeError("unavailable", "endpoint is not a valid URL") from exc
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise _ProbeError("unavailable", "endpoint must be an http(s) URL with a host")
    if parts.username or parts.password:
        raise _ProbeError("unavailable", "endpoint URLs with embedded credentials are refused")
    if parts.query or parts.fragment:
        raise _ProbeError("unavailable", "endpoint URLs with a query or fragment are refused")
    normalized = f"{parts.scheme}://{parts.netloc}{parts.path.rstrip('/')}"
    try:
        validate_url(normalized, allowed_schemes=("http", "https"), allow_private=True)
    except SecurityError as exc:
        raise _ProbeError("unavailable", "endpoint refused by outbound URL policy") from exc
    return normalized


def _request(client: httpx.Client, method: str, url: str) -> Any:
    try:
        kwargs: dict[str, Any] = {"json": {}} if method == "POST" else {}
        with client.stream(method, url, **kwargs) as response:
            if response.status_code in (401, 403):
                rejected = ": the bearer token was rejected" if "authorization" in client.headers else ""
                raise _ProbeError("denied", f"HTTP {response.status_code}{rejected}")
            if response.status_code != 200:
                raise _ProbeError("unavailable", f"HTTP {response.status_code}")
            body = b""
            for chunk in response.iter_bytes():
                body += chunk
                if len(body) > _MAX_RESPONSE_BYTES:
                    raise _ProbeError("unavailable", "response exceeded the size bound")
    except httpx.TimeoutException as exc:
        raise _ProbeError("timeout", "request timed out") from exc
    except httpx.HTTPError as exc:
        raise _ProbeError("unavailable", type(exc).__name__) from exc
    try:
        return httpx.Response(200, content=body).json()
    except ValueError as exc:
        raise _ProbeError("unavailable", "response was not JSON") from exc


def probe_endpoint(runtime: str, endpoint: str, *, timeout: float = _DEFAULT_TIMEOUT, token_env: str | None = None) -> EndpointObservation:
    """Probe one endpoint of one declared runtime and classify the outcome.

    ``token_env`` names the dedicated variable holding this endpoint's bearer
    token; the value is resolved here and never leaves the request headers.
    """
    spec = SERVING_RUNTIMES.get(runtime)
    if spec is None:
        raise ValueError(f"Unknown serving runtime '{runtime}'. Available: {', '.join(sorted(SERVING_RUNTIMES))}")
    if token_env is not None:
        token_env = validate_token_env_name(token_env)
    request_identity = "bearer" if token_env else "anonymous"
    try:
        base = normalize_endpoint(endpoint)
    except _ProbeError as failure:
        return EndpointObservation(
            runtime=runtime, endpoint="", status=failure.status, detail=failure.detail, request_identity=request_identity
        )
    permissions = [_declared(runtime, spec.method, spec.path)]
    observation = EndpointObservation(runtime=runtime, endpoint=base, status="unavailable", request_identity=request_identity)
    headers: dict[str, str] = {}
    if token_env:
        try:
            headers["Authorization"] = f"Bearer {bearer_token(token_env, base)}"
        except ServingAuthError as failure:
            observation.detail = str(failure)
            return observation
    # A token over plain http (loopback only) must never be relayed through a proxy.
    trust_env = not (headers and urlsplit(base).scheme == "http")
    with httpx.Client(timeout=timeout, follow_redirects=False, headers=headers, trust_env=trust_env) as client:
        try:
            models, dropped, version, confirmed = spec.parse(_request(client, spec.method, base + spec.path))
        except _ProbeError as failure:
            observation.status, observation.detail = failure.status, failure.detail
            observation.permissions_used = tuple(permissions)
            return observation
        metadata_failed = False
        if spec.metadata_path and spec.metadata_version:
            permissions.append(_declared(runtime, "GET", spec.metadata_path))
            try:
                version = spec.metadata_version(_request(client, "GET", base + spec.metadata_path))
                confirmed = confirmed or (runtime == "triton" and version is not None)
            except _ProbeError as failure:
                metadata_failed = True
                observation.detail = f"runtime metadata read {failure.status}: {failure.detail}"
    observation.models = models
    observation.runtime_version = version
    observation.runtime_identity = "confirmed" if confirmed else "declared"
    observation.permissions_used = tuple(permissions)
    if not models and dropped:
        observation.status, observation.detail = "unavailable", "no record matched the documented model shape"
    elif dropped or metadata_failed:
        observation.status = "partial"
        observation.detail = observation.detail or f"{dropped} record(s) did not match the documented model shape"
    else:
        observation.status = "success"
    return observation


def _host_port(endpoint: str) -> tuple[str, int | None]:
    parts = urlsplit(endpoint)
    host = parts.hostname or ""
    try:
        host = str(ipaddress.ip_address(host))
    except ValueError:
        host = host.lower()
    return host, parts.port or {"http": 80, "https": 443}.get(parts.scheme)


def serving_evidence(observation: EndpointObservation, model: ServedModel) -> dict[str, Any]:
    """Per-model evidence keeping runtime, endpoint, artifact and unknown identities separate."""
    host, port = _host_port(observation.endpoint)
    return {
        "runtime": {"name": observation.runtime, "version": observation.runtime_version, "identity": observation.runtime_identity},
        "endpoint": {"url": observation.endpoint, "host": host, "port": port},
        "model": {
            "served_name": model.served_name,
            "artifact_ref": model.artifact_ref,
            "digest": model.digest,
            "version": model.version,
            "state": model.state,
        },
        "unknown_identities": {"container": None, "gpu": None, "calling_agent": None, "principal": None},
        "collection": {
            "status": observation.status,
            "completeness": observation.completeness,
            "observed_at": observation.observed_at,
            "permissions_used": list(observation.permissions_used),
            "request_identity": observation.request_identity,
            "not_collected": list(NOT_COLLECTED),
            "detail": observation.detail,
        },
    }


def outcome_warning(observation: EndpointObservation) -> str | None:
    """Return the warning a non-successful outcome must carry, or ``None`` for success."""
    label = {"timeout": "timed out"}.get(observation.status, observation.status)
    target = observation.endpoint or "the requested endpoint"
    if observation.status == "success":
        return None
    if observation.status == "partial":
        return f"{observation.runtime} inventory at {target} is partial: {observation.detail}"
    return f"{observation.runtime} discovery incomplete: endpoint {target} {label} ({observation.detail}); no inventory was substituted."


def observation_to_agents(observation: EndpointObservation) -> list[Agent]:
    agents: list[Agent] = []
    for model in observation.models:
        server = MCPServer(
            name=f"{observation.runtime}/{model.served_name}",
            url=observation.endpoint,
            surface=ServerSurface.AI_INVENTORY,
            packages=[Package(name=model.served_name, version=model.version or "unknown", ecosystem=observation.runtime)],
        )
        agents.append(
            Agent(
                name=f"{observation.runtime}-model-{model.served_name}",
                agent_type=AgentType.CUSTOM,
                config_path=observation.endpoint,
                source=f"{observation.runtime}-api",
                version=observation.runtime_version,
                mcp_servers=[server],
                metadata={"serving_evidence": serving_evidence(observation, model)},
            )
        )
    attach_envelope_to_agents(
        agents,
        scan_mode=ScanMode.RUNTIME_PROBE,
        discovery_scope=(f"{observation.runtime}:endpoint/{observation.endpoint}",),
        permissions_used=observation.permissions_used,
        redaction_status=RedactionStatus.NOT_APPLICABLE,
    )
    return agents


def discover(runtime: str, endpoint: str, timeout: float = _DEFAULT_TIMEOUT, token_env: str | None = None) -> tuple[list[Agent], list[str]]:
    """Discover served models from one endpoint; failures return no agents and one warning."""
    observation = probe_endpoint(runtime, endpoint, timeout=timeout, token_env=token_env)
    warning = outcome_warning(observation)
    if observation.status not in {"success", "partial"}:
        return [], [warning] if warning else []
    return observation_to_agents(observation), [warning] if warning else []
