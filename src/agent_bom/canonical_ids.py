"""Deterministic canonical identity helpers for scan and graph entities."""

from __future__ import annotations

import json
import os
import uuid
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

from agent_bom.package_utils import canonical_package_key

AGENT_BOM_ID_NAMESPACE = uuid.UUID("7f3e4b2a-9c1d-5f8e-a0b4-12c3d4e5f6a7")
CANONICAL_ID_SCHEMA_VERSION = "2"


def _part_to_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, Mapping):
        return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return json.dumps(list(value), sort_keys=True, separators=(",", ":"), default=str)
    return str(value)


def canonical_fingerprint(*parts: Any) -> str:
    """Return the normalized fingerprint material used for canonical IDs."""
    return ":".join(text.lower().strip() for text in (_part_to_text(part) for part in parts) if text)


def canonical_id(*parts: Any) -> str:
    """Return a deterministic UUID v5 for normalized content parts."""
    return str(uuid.uuid5(AGENT_BOM_ID_NAMESPACE, canonical_fingerprint(*parts)))


def source_ids(**values: Any) -> dict[str, str]:
    """Return source identifiers as provenance without empty values."""
    result: dict[str, str] = {}
    for key, value in values.items():
        if value in (None, "", [], {}):
            continue
        result[str(key)] = _part_to_text(value)
    return result


def canonical_package_id(name: str, version: str, ecosystem: str, purl: str | None = None) -> str:
    return canonical_id("package", canonical_package_key(name, version, ecosystem, purl))


def canonical_agent_id(
    agent_type: str,
    name: str,
    *,
    source_id: str = "",
    device_fingerprint: str = "",
    config_path: str = "",
) -> str:
    """Return a deterministic agent identity.

    A hardware-backed ``device_fingerprint`` (derived from attestation evidence)
    is preferred when present, so the identity is rooted in the physical device
    rather than a mutable hostname/config path. A ``source_id`` is next and
    survives config relocation while remaining scoped by agent name (one source
    can report many agents). Without either, local and inventory agents use
    type + name + config location. The name is retained in that fallback
    because one inventory document can contain many agents at the same location.
    """
    fingerprint = (device_fingerprint or "").strip()
    if fingerprint:
        return canonical_id("agent", agent_type, f"device:{fingerprint}")
    source = (source_id or "").strip()
    if source:
        return canonical_id("agent", agent_type, f"source:{source}", f"name:{name}")
    location = (config_path or "").strip()
    if location:
        return canonical_id("agent", agent_type, f"config:{location}", f"name:{name}")
    return canonical_id("agent", agent_type, name)


def legacy_agent_id_v1(agent_type: str, name: str, *, source: str = "", config_path: str = "") -> str:
    """Return the pre-v2 Agent-model identity for migration/alias matching.

    Version 1 incorrectly treated collector provenance (``source``) as a
    globally unique source identifier. Keep the exact derivation available so
    persisted fleet rows can be upgraded without discarding lifecycle state.
    """
    discriminator = source or config_path or name
    return canonical_id("agent", agent_type, discriminator)


def normalize_command_arg(arg: str) -> str:
    """Normalize a server command argument for identity comparison.

    Case is preserved: on case-sensitive filesystems ``/srv/TeamA`` and
    ``/srv/teama`` are different scripts.
    """
    text = str(arg).strip()
    if not text:
        return ""
    if text.startswith(("/", "~", ".")):
        try:
            return os.path.normpath(os.path.expanduser(text))
        except (OSError, ValueError):
            return text
    return text


def mcp_server_identity_discriminator(
    name: str,
    command: str = "",
    *,
    url: str | None = None,
    args: Sequence[str] | None = None,
) -> str:
    """Non-registry server identity key shared by canonical IDs and discovery dedup.

    Mirrors the url/command/name fallback used by discovery's ``server_identity_key``
    so a server's served canonical id is as fine-grained as its dedup identity:
    remote SSE/HTTP servers (empty command) stay distinct by url, and stdio servers
    fold in their normalized args.
    """
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


def canonical_mcp_server_id(
    name: str,
    command: str = "",
    *,
    registry_id: str | None = None,
    url: str | None = None,
    args: Sequence[str] | None = None,
) -> str:
    if registry_id:
        return canonical_id("mcp_server", registry_id)
    identifier = mcp_server_identity_discriminator(name, command, url=url, args=args).strip()
    # canonical_id lower-cases every part; URL paths and local paths/args are
    # case-sensitive, so only the discriminator's own normalization applies.
    return str(uuid.uuid5(AGENT_BOM_ID_NAMESPACE, f"mcp_server:{identifier}"))


_AGENT_SCOPE_KEYS = ("source_id", "endpoint_id", "device_id")
CORTEX_AGENT_SOURCE = "snowflake-cortex-agent"


def _field(record: Any, key: str) -> Any:
    return record.get(key) if isinstance(record, Mapping) else getattr(record, key, None)


def agent_identity_scope(record: Any) -> str:
    """Endpoint/source scope that keeps same-named fleet agents apart.

    Accepts a serialized agent mapping or an ``Agent`` model, so report,
    graph and export producers derive one scope from either shape.
    """
    for container in (record, _field(record, "metadata")):
        if container is None:
            continue
        for key in _AGENT_SCOPE_KEYS:
            value = str(_field(container, key) or "").strip()
            if value:
                return value
    return ""


def agent_graph_id(name: Any, scope: str = "") -> str:
    """Graph node id of a discovered agent: ``agent:[<scope>:]<name>``."""
    label = str(name or "unknown").strip() or "unknown"
    scope_part = str(scope or "").strip().replace(":", "%3A")
    return f"agent:{scope_part}:{label}" if scope_part else f"agent:{label}"


def agent_graph_id_for(record: Any) -> str:
    """Graph id for an agent record; Cortex Agents keep their account-qualified id."""
    metadata = _field(record, "metadata")
    cortex = metadata.get("snowflake_cortex_agent") if isinstance(metadata, Mapping) else None
    if _field(record, "source") == CORTEX_AGENT_SOURCE and isinstance(cortex, Mapping):
        if all(str(cortex.get(key) or "").strip() for key in ("database", "schema", "name")):
            return snowflake_cortex_agent_node_id(cortex.get("account"), cortex["database"], cortex["schema"], cortex["name"])
    return agent_graph_id(_field(record, "name"), agent_identity_scope(record))


def mcp_server_identity_kind(*, url: Any = None, command: Any = "", args: Sequence[Any] | None = None, registry_id: Any = None) -> str:
    """How far one server identity reaches: ``remote``, ``host`` or ``agent``.

    A url or registry entry names one service for the whole tenant. A launch
    command with arguments names a process that is only the same server on the
    same host. A bare command or a name alone proves nothing beyond the agent
    that declared it: two configs both running ``npx`` are not one server.
    """
    if str(url or "").strip() or (str(registry_id or "").strip() and not str(command or "").strip()):
        return "remote"
    if any(normalize_command_arg(str(arg or "")) for arg in (args or [])):
        return "host"
    return "agent"


def mcp_server_graph_id(
    name: Any,
    *,
    command: Any = "",
    args: Sequence[Any] | None = None,
    url: Any = None,
    registry_id: Any = None,
    canonical_id: Any = "",
    host_scope: str = "",
    agent_key: str = "",
) -> str:
    """Graph node id of an MCP server, shared by every producer.

    Remote servers are one node per tenant (``server:<canonical id>``), stdio
    servers one node per host (``server:<host scope>:<canonical id>``, with an
    unscoped local scan being one host), and name-only servers stay under the
    agent that declared them (``server:<agent key>:<name>``).
    """
    label = str(name or "unknown").strip() or "unknown"
    kind = mcp_server_identity_kind(url=url, command=command, args=args, registry_id=registry_id)
    if kind == "agent":
        return f"server:{agent_key}:{label}" if agent_key else f"server:{label}"
    identity = str(canonical_id or "").strip() or canonical_mcp_server_id(
        label, str(command or ""), registry_id=str(registry_id or "") or None, url=str(url or "") or None, args=list(args or [])
    )
    scope = str(host_scope or "").strip().replace(":", "%3A")
    if kind == "host" and scope:
        return f"server:{scope}:{identity}"
    return f"server:{identity}"


def mcp_server_graph_id_for(server: Any, agent: Any) -> str:
    """Graph id for a server record (mapping or model) under its declaring agent.

    A Cortex Agent's endpoint is the agent itself, so its pseudo-server and
    tools stay agent-scoped and same-named agents in other schemas never merge.
    """
    agent_key = agent_graph_id_for(agent).removeprefix("agent:")
    if _field(agent, "source") == CORTEX_AGENT_SOURCE:
        return f"server:{agent_key}:{str(_field(server, 'name') or 'unknown').strip() or 'unknown'}"
    return mcp_server_graph_id(
        _field(server, "name"),
        command=_field(server, "command") or "",
        args=list(_field(server, "args") or []),
        url=_field(server, "url"),
        registry_id=_field(server, "registry_id"),
        canonical_id=_field(server, "canonical_id") or _field(server, "stable_id") or "",
        host_scope=agent_identity_scope(agent),
        agent_key=agent_key,
    )


def previous_mcp_server_graph_ids(server: Any, agent: Any) -> list[str]:
    """Ids earlier identity schemes gave this server, so stored references still resolve.

    Before discriminators kept case, the canonical part was lower-cased in
    full; before canonical server ids, every server lived under its agent.
    """
    current = mcp_server_graph_id_for(server, agent)
    if _field(agent, "source") == CORTEX_AGENT_SOURCE or _field(server, "canonical_id") or _field(server, "stable_id"):
        return []
    label = str(_field(server, "name") or "unknown").strip() or "unknown"
    url, command, args, registry_id = (
        _field(server, "url"),
        _field(server, "command") or "",
        list(_field(server, "args") or []),
        _field(server, "registry_id"),
    )
    if mcp_server_identity_kind(url=url, command=command, args=args, registry_id=registry_id) == "agent":
        return []
    agent_key = agent_graph_id_for(agent).removeprefix("agent:")
    previous: list[str] = []
    if not registry_id:
        lowered = canonical_id("mcp_server", mcp_server_identity_discriminator(label, str(command), url=str(url or "") or None, args=args))
        legacy = mcp_server_graph_id(
            label, command=command, args=args, url=url, canonical_id=lowered, host_scope=agent_identity_scope(agent), agent_key=agent_key
        )
        previous.append(legacy)
    previous.append(f"server:{agent_key}:{label}")
    return sorted({value for value in previous if value != current})


def canonical_mcp_tool_id(name: str, input_schema: Mapping[str, Any] | bool | None = None, *, server_id: str | None = None) -> str:
    schema = json.dumps({} if input_schema is None else input_schema, sort_keys=True, separators=(",", ":"))
    return canonical_id("mcp_tool", server_id or "", name, schema)


def canonical_mcp_resource_id(uri: str, mime_type: str | None = None, *, server_id: str | None = None) -> str:
    return canonical_id("mcp_resource", server_id or "", uri, mime_type or "")


def canonical_mcp_prompt_id(
    name: str,
    arguments: Sequence[Mapping[str, Any]] | None = None,
    *,
    server_id: str | None = None,
) -> str:
    args = json.dumps(list(arguments or []), sort_keys=True, separators=(",", ":"))
    return canonical_id("mcp_prompt", server_id or "", name, args)


def canonical_finding_id(asset_canonical_id: str, finding_key: str, *qualifiers: Any) -> str:
    return canonical_id(asset_canonical_id, finding_key, *qualifiers)


def canonical_graph_node_id(entity_type: str, graph_id: str) -> str:
    return canonical_id("graph_node", entity_type, graph_id)


def canonical_graph_edge_id(source: str, target: str, relationship: str) -> str:
    return canonical_id("graph_edge", relationship, source, target)


def mcp_server_fingerprint(server: Any) -> str:
    """Stable server evidence hash; absent extension fields retain legacy hashes."""
    import uuid as _uuid

    _ns = _uuid.UUID("7f3e4b2a-9c1d-5f8e-a0b4-12c3d4e5f6a7")
    tool_ids = sorted(t.stable_id for t in server.tools)
    resource_ids = sorted(r.stable_id for r in server.resources)
    prompt_ids = sorted(p.stable_id for p in server.prompts)
    env_keys = sorted(server.credential_names)
    raw = json.dumps(
        {
            "registry_id": server.registry_id,
            "name": server.name,
            "command": server.command,
            "args": server.args,
            "url": server.url,
            "transport": server.transport.value,
            "auth_mode": server.auth_mode,
            "credential_refs": env_keys,
            "tool_ids": tool_ids,
            **(
                {
                    "tool_metadata": sorted(
                        (
                            {"id": t.stable_id, "output_schema": t.output_schema, "annotations": t.annotations, "ui": t.ui_metadata}
                            for t in server.tools
                        ),
                        key=lambda item: item["id"],
                    )
                }
                if any(t.output_schema is not None or t.annotations or t.ui_metadata for t in server.tools)
                else {}
            ),
            **({"connection_metadata": server.connection_metadata} if server.connection_metadata else {}),
            "resource_ids": resource_ids,
            "prompt_ids": prompt_ids,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return str(_uuid.uuid5(_ns, f"mcp_server_fingerprint:{raw}"))


def snowflake_identifier_parts(value: Any) -> list[str]:
    """Split a Snowflake object name into resolved identifier parts.

    Unquoted identifiers resolve to upper case; double-quoted ones keep their
    exact text. ``analytics.public."Mixed"`` -> ``["ANALYTICS", "PUBLIC", "Mixed"]``.
    """
    text = str(value or "").strip()
    parts: list[str] = []
    current: list[str] = []
    quoted = False
    was_quoted = False
    i = 0
    while i < len(text):
        char = text[i]
        if char == '"':
            if quoted and i + 1 < len(text) and text[i + 1] == '"':
                current.append('"')
                i += 2
                continue
            quoted = not quoted
            was_quoted = True
        elif char == "." and not quoted:
            part = "".join(current).strip()
            parts.append(part if was_quoted else part.upper())
            current, was_quoted = [], False
        else:
            current.append(char)
        i += 1
    part = "".join(current).strip()
    parts.append(part if was_quoted else part.upper())
    return [p for p in parts if p]


def snowflake_fqn(*parts: Any) -> str:
    """Resolved, dot-joined Snowflake FQN from a name or its separate parts."""
    resolved: list[str] = []
    for part in parts:
        resolved.extend(snowflake_identifier_parts(part))
    return ".".join(resolved)


def snowflake_stored_fqn(*parts: Any) -> str:
    """Dot-joined FQN from stored identifier names (SHOW / ACCOUNT_USAGE output)."""
    return ".".join(text for text in (str(part or "").strip() for part in parts) if text)


def snowflake_cortex_agent_node_id(account: Any, database: Any, schema: Any, name: Any) -> str:
    """Graph id of one Cortex Agent, shared by discovery, governance and telemetry.

    Parts are stored names as Snowflake reports them. The account is part of
    the id, so the node needs no per-account rescoping and two accounts holding
    ``DB.SCHEMA.AGENT`` never merge.
    """
    fqn = snowflake_stored_fqn(database, schema, name)
    account_part = str(account or "").strip().replace(":", "%3A")
    return f"agent:snowflake:{account_part}:{fqn}" if account_part else f"agent:snowflake:{fqn}"


def snowflake_cortex_agent_server_name(name: Any) -> str:
    return f"cortex-agent:{str(name or '').strip()}"


def snowflake_cortex_tool_node_id(agent_node_id: str, agent_name: Any, tool_name: str) -> str:
    """Tool id matching the agent projection's ``tool:server:<agent>:<server>:<tool>`` form."""
    agent_key = agent_node_id.removeprefix("agent:")
    return f"tool:server:{agent_key}:{snowflake_cortex_agent_server_name(agent_name)}:{tool_name}"
