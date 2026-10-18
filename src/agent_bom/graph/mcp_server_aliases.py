"""Frozen historical MCP server ids, kept so stored references still resolve.

Only alias derivation lives here; the current identity is in
:mod:`agent_bom.canonical_ids`. These derivations must never change: each one
reproduces the id an earlier release recorded.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse, urlunparse

from agent_bom.canonical_ids import (
    AGENT_BOM_ID_NAMESPACE,
    CORTEX_AGENT_SOURCE,
    _field,
    agent_graph_id_for,
    agent_identity_scope,
    canonical_fingerprint,
    canonical_id,
    canonical_mcp_server_id,
    legacy_canonical_id_v2,
    mcp_server_graph_id_for,
    mcp_server_identity_kind,
    normalize_command_arg,
    previous_agent_graph_ids,
)


def _legacy_mcp_server_discriminator(
    name: str,
    command: str = "",
    *,
    url: str | None = None,
    args: Sequence[str] | None = None,
) -> str:
    """Frozen pre-instance discriminator, used only for historical aliases."""
    if url and url.strip():
        parsed = urlparse(url.strip())
        netloc = parsed.netloc.lower()
        path = parsed.path.rstrip("/")
        return f"url:{urlunparse((parsed.scheme.lower(), netloc, path, '', '', ''))}"

    cmd = Path(command or "").name.strip()
    normalized_args = tuple(value for value in (normalize_command_arg(arg) for arg in (args or [])) if value)
    if cmd or normalized_args:
        arg_str = " ".join(normalized_args)
        if not normalized_args:
            # A bare command with no args is not distinctive enough on its own;
            # fold in the server name so distinct servers keep distinct identities.
            return f"cmd:{cmd}:{arg_str}:{name.strip().lower()}"
        return f"cmd:{cmd}:{arg_str}"

    return f"name:{name.strip().lower()}"


def _previous_v3_mcp_server_id(
    name: str,
    command: str = "",
    *,
    url: str | None = None,
    args: Sequence[str] | None = None,
    working_dir: str | None = None,
    environment: Mapping[str, Any] | None = None,
) -> str:
    """Frozen v3 instance id (name dropped with args, secrets hashed), for aliases only."""
    if url and url.strip():
        parsed = urlparse(url.strip())
        userinfo, separator, host = parsed.netloc.rpartition("@")
        endpoint = urlunparse((parsed.scheme.lower(), userinfo + separator + host.lower(), parsed.path, parsed.params, parsed.query, ""))
        identifier = canonical_fingerprint("url", endpoint)
    elif command or args:
        identifier = canonical_fingerprint("cmd", command, list(args or []), name if not args else None)
    else:
        identifier = canonical_fingerprint("name", name)
    context = None if url else {"working_dir": working_dir, "environment": dict(environment or {})}
    return canonical_id("mcp_server_instance", identifier, context)


def previous_mcp_server_graph_ids(server: Any, agent: Any) -> list[str]:
    """Ids earlier identity schemes gave this server, so stored references still resolve.

    Before discriminators kept case, the canonical part was lower-cased in
    full; before canonical server ids, every server lived under its agent.
    """
    current = mcp_server_graph_id_for(server, agent)
    label = str(_field(server, "name") or "unknown").strip() or "unknown"
    url, command, args, registry_id = (
        _field(server, "url"),
        _field(server, "command") or "",
        list(_field(server, "args") or []),
        _field(server, "registry_id"),
    )
    kind = mcp_server_identity_kind(url=url, command=command, args=args, registry_id=registry_id)
    agent_ids = [agent_graph_id_for(agent), *previous_agent_graph_ids(agent)]
    previous = {f"server:{agent_id.removeprefix('agent:')}:{label}" for agent_id in agent_ids}
    if (kind != "agent" or registry_id) and _field(agent, "source") != CORTEX_AGENT_SOURCE:
        explicit = _field(server, "canonical_id") or _field(server, "stable_id")
        current_identity = canonical_mcp_server_id(
            label,
            str(command),
            registry_id=registry_id,
            url=url,
            args=args,
            working_dir=_field(server, "working_dir"),
            environment=_field(server, "env"),
        )
        # Only an older explicit receipt can name a previous global node.
        # The new instance fingerprint never existed in that global namespace.
        identities = {str(explicit)} if explicit and str(explicit) != current_identity else set()
        if registry_id:
            identities.update({canonical_id("mcp_server", registry_id), legacy_canonical_id_v2("mcp_server", registry_id)})
        else:
            old = _legacy_mcp_server_discriminator(label, str(command), url=url, args=args)
            identities.update({str(uuid.uuid5(AGENT_BOM_ID_NAMESPACE, f"mcp_server:{old}")), legacy_canonical_id_v2("mcp_server", old)})
        prior_v3 = _previous_v3_mcp_server_id(
            label, str(command), url=url, args=args, working_dir=_field(server, "working_dir"), environment=_field(server, "env")
        )
        if prior_v3 != current_identity:
            # The v3 instance id dropped the configured name and hashed secrets.
            if kind == "host":
                previous.update(f"server:{agent_id.removeprefix('agent:')}:{prior_v3}" for agent_id in agent_ids)
            else:
                previous.add(f"server:{prior_v3}")
        # Frozen pre-v3 spelling: do not run the old scope through new escaping.
        raw_scope = agent_identity_scope(agent).strip()
        scopes = {raw_scope.replace(":", "%3A"), quote(raw_scope, safe="")}
        old_host = not url and any(normalize_command_arg(str(arg or "")) for arg in args)
        previous.update(
            f"server:{scope}:{identity}" if old_host and scope else f"server:{identity}" for identity in identities for scope in scopes
        )
    return sorted(previous - {current})
