"""Shared plumbing for bearer-token REST GPU cloud connectors.

Each connector keeps its own record mapping and its own discovery envelope
(scan mode, scope, permission catalog) so the read-only contract stays
auditable per provider; this module owns only the transport and the
collect-until-failure loop they all share.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping

from agent_bom import http_client
from agent_bom.models import Agent

from .base import CloudDiscoveryError
from .collection_errors import COLLECTION_ERRORS, collection_warning

DEFAULT_API_TIMEOUT = 15


def bearer_json_get(
    base_url: str,
    path: str,
    api_key: str,
    *,
    label: str,
    timeout: int = DEFAULT_API_TIMEOUT,
    extra_headers: Mapping[str, str] | None = None,
) -> dict | list:
    """GET ``base_url + path`` through the resilient client and decode JSON.

    Routing through ``http_client.sync_get`` gives every connector the same
    retry/backoff, 429 Retry-After handling and per-host circuit breaker.
    """
    headers = {"Authorization": f"Bearer {api_key}", **(extra_headers or {})}
    resp = http_client.sync_get(f"{base_url}{path}", timeout=timeout, headers=headers)
    if resp is None:
        raise CloudDiscoveryError(f"{label}: request failed after retries")
    resp.raise_for_status()
    return resp.json()


def collect_gpu_inventory(
    provider: str,
    fetch: Callable[[], list],
    build_agent: Callable[[dict], Agent],
    *,
    resource: str = "instances",
) -> tuple[list[Agent], list[str]]:
    """Fetch records and map each to an agent, stopping at the first failure.

    Agents built before a transport error or malformed record are kept; the
    failure becomes one typed, fixed collection warning so a partial read is
    never mistaken for an authorized empty inventory.
    """
    agents: list[Agent] = []
    warnings: list[str] = []
    try:
        for record in fetch():
            agents.append(build_agent(record))
    except COLLECTION_ERRORS as exc:
        warnings.append(collection_warning(provider, resource, exc))
    return agents, warnings


def missing_api_key_warning(env_var: str, flag: str) -> str:
    return f"{env_var} not set. Provide {flag} or set the {env_var} env var."
