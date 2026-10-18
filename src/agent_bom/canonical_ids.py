"""Deterministic canonical identity helpers for scan and graph entities."""

from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from collections.abc import Mapping, Sequence
from typing import Any
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse

from agent_bom.constants import is_credential_key
from agent_bom.package_utils import canonical_package_key

AGENT_BOM_ID_NAMESPACE = uuid.UUID("7f3e4b2a-9c1d-5f8e-a0b4-12c3d4e5f6a7")
CANONICAL_ID_SCHEMA_VERSION = "3"


def _part_to_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, Mapping):
        return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return json.dumps(list(value), sort_keys=True, separators=(",", ":"), default=str)
    return str(value)


def canonical_fingerprint(*parts: Any) -> str:
    """Versioned, case-preserving structured identity; callers normalize semantics.

    JSON boundaries retain empty values, types and separators. Lowercasing or
    colon-joining arbitrary source identifiers can merge unrelated resources.
    """
    return "v3:" + json.dumps(parts, sort_keys=True, separators=(",", ":"), default=_part_to_text)


def canonical_id(*parts: Any) -> str:
    """Return a deterministic UUID v5 from the current identity schema."""
    return str(uuid.uuid5(AGENT_BOM_ID_NAMESPACE, canonical_fingerprint(*parts)))


def legacy_canonical_id_v2(*parts: Any) -> str:
    """Reproduce old IDs for explicit compatibility, never for a new identity."""
    fingerprint = ":".join(text.lower().strip() for text in (_part_to_text(part) for part in parts) if text)
    return str(uuid.uuid5(AGENT_BOM_ID_NAMESPACE, fingerprint))


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


def legacy_agent_id_v2(
    agent_type: str,
    name: str,
    *,
    source_id: str = "",
    device_fingerprint: str = "",
    config_path: str = "",
) -> str:
    """Frozen v2 derivation for explicit migration receipts."""
    fingerprint = (device_fingerprint or "").strip()
    if fingerprint:
        return legacy_canonical_id_v2("agent", agent_type, f"device:{fingerprint}")
    source = (source_id or "").strip()
    if source:
        return legacy_canonical_id_v2("agent", agent_type, f"source:{source}", f"name:{name}")
    location = (config_path or "").strip()
    if location:
        return legacy_canonical_id_v2("agent", agent_type, f"config:{location}", f"name:{name}")
    return legacy_canonical_id_v2("agent", agent_type, name)


def legacy_agent_id_v1(agent_type: str, name: str, *, source: str = "", config_path: str = "") -> str:
    """Return the pre-v2 Agent-model identity for migration/alias matching.

    Version 1 incorrectly treated collector provenance (``source``) as a
    globally unique source identifier. Keep the exact derivation available so
    persisted fleet rows can be upgraded without discarding lifecycle state.
    """
    discriminator = source or config_path or name
    return legacy_canonical_id_v2("agent", agent_type, discriminator)


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


_NON_IDENTITY_ENV_KEY = re.compile(
    r"^(?:[A-Z0-9_]*_)?(?:LOG_LEVEL|LOGLEVEL|LOG_FORMAT|DEBUG|VERBOSE|VERBOSITY|NO_COLOR|FORCE_COLOR|TIMEOUT|[A-Z0-9_]*_TIMEOUT(?:_MS|_SECONDS)?)$",
    re.IGNORECASE,
)


def _identity_endpoint(url: str) -> str:
    """Endpoint route without secret material: passwords and credential-named query values."""
    parsed = urlparse(url.strip())
    userinfo, separator, host = parsed.netloc.rpartition("@")
    username = userinfo.split(":", 1)[0]
    authority = username + separator + host.lower()
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    query = parsed.query
    if any(is_credential_key(key) for key, _ in pairs):
        query = urlencode([(key, value) for key, value in pairs if not is_credential_key(key)])
    # Preserve path, parameters and non-secret query: each may select another service.
    return urlunparse((parsed.scheme.lower(), authority, parsed.path, parsed.params, query, ""))


def _identity_environment(environment: Mapping[str, Any] | None) -> dict[str, Any]:
    """Environment that selects an instance; secrets keep only their name, settings drop out."""
    result: dict[str, Any] = {}
    for key, value in (environment or {}).items():
        name = str(key)
        if _NON_IDENTITY_ENV_KEY.match(name):
            continue
        result[name] = None if is_credential_key(name) else value
    return result


def mcp_server_identity_discriminator(name: str, command: str = "", *, url: str | None = None, args: Sequence[str] | None = None) -> str:
    """Retain endpoint routes, exact executable/argv boundaries and the configured name.

    A registry artifact and a launch recipe are not proof of a shared process:
    two configured entries running the same recipe are two instances. Secret
    material never enters the identity, so rotating a credential keeps the id.
    The discriminator is hashed before it is exposed as a canonical identity.
    """
    if url and url.strip():
        return canonical_fingerprint("url", _identity_endpoint(url))
    if command or args:
        return canonical_fingerprint("cmd", command, list(args or []), name)
    return canonical_fingerprint("name", name)


def canonical_mcp_server_id(
    name: str,
    command: str = "",
    *,
    registry_id: str | None = None,
    url: str | None = None,
    args: Sequence[str] | None = None,
    working_dir: str | None = None,
    environment: Mapping[str, Any] | None = None,
) -> str:
    if registry_id and not (url or command or args):
        return canonical_id("mcp_server", registry_id)
    identifier = mcp_server_identity_discriminator(name, command, url=url, args=args).strip()
    context = None if url else {"working_dir": working_dir, "environment": _identity_environment(environment)}
    return canonical_id("mcp_server_instance", identifier, context)


_AGENT_SCOPE_KEYS = ("source_id", "endpoint_id", "device_id")
CORTEX_AGENT_SOURCE = "snowflake-cortex-agent"
PROJECT_CONFIG_SOURCE = "project-config"


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
    scope_part = quote(str(scope or "").strip(), safe="")
    label = quote(label, safe="")
    return f"agent:{scope_part}:{label}" if scope_part else f"agent:{label}"


def agent_graph_id_for(record: Any) -> str:
    """Graph id for an agent record; Cortex Agents keep their account-qualified id."""
    metadata = _field(record, "metadata")
    cortex = metadata.get("snowflake_cortex_agent") if isinstance(metadata, Mapping) else None
    if _field(record, "source") == CORTEX_AGENT_SOURCE and isinstance(cortex, Mapping):
        if all(str(cortex.get(key) or "").strip() for key in ("database", "schema", "name")):
            return snowflake_cortex_agent_node_id(cortex.get("account"), cortex["database"], cortex["schema"], cortex["name"])
    return agent_graph_id(_field(record, "name"), agent_identity_scope(record) or agent_config_scope(record))


def agent_config_scope(record: Any) -> str:
    """Config identity for every agent without a stronger endpoint scope.

    Reports redact config paths to basenames but retain canonical identity.
    Prefer that receipt; a basename alone cannot reconstruct the full path.
    """
    if not str(_field(record, "config_path") or "").strip():
        return ""
    identity = next((str(value) for key in ("canonical_id", "stable_id", "id") if (value := _field(record, key))), "")
    identity = identity or canonical_agent_id(
        str(_field(record, "agent_type") or _field(record, "type") or ""),
        str(_field(record, "name") or ""),
        config_path=str(_field(record, "config_path")),
    )
    return f"cfg-{hashlib.sha256(identity.encode()).hexdigest()[:12]}"


def _legacy_agent_graph_id(name: Any, scope: str = "") -> str:
    """Frozen v2 graph spelling, including its lossy percent escaping."""
    label = str(name or "unknown").strip() or "unknown"
    scope_part = str(scope or "").strip().replace(":", "%3A")
    return f"agent:{scope_part}:{label}" if scope_part else f"agent:{label}"


def _relocated_config_graph_ids(record: Any) -> list[str]:
    """Ids an agent had under the config locations its producer replaced.

    A producer that narrows an ambiguous location (for example, adding the
    kube context to ``namespace/name``) records the old location in
    ``metadata.previous_config_paths`` so stored references keep resolving.
    """
    metadata = _field(record, "metadata")
    paths = metadata.get("previous_config_paths") if isinstance(metadata, Mapping) else None
    if not isinstance(paths, list):
        return []
    kind = _field(record, "agent_type") or _field(record, "type") or ""
    agent_type = str(getattr(kind, "value", kind))
    name = str(_field(record, "name") or "")
    out = []
    for path in paths:
        if isinstance(path, str) and path.strip():
            identity = canonical_agent_id(agent_type, name, config_path=path)
            out.append(agent_graph_id(_field(record, "name"), f"cfg-{hashlib.sha256(identity.encode()).hexdigest()[:12]}"))
    return out


def previous_agent_graph_ids(record: Any) -> list[str]:
    """Candidate old spellings; persistence rejects ambiguous alias bindings."""
    current = agent_graph_id_for(record)
    scope = agent_identity_scope(record)
    previous = {_legacy_agent_graph_id(_field(record, "name"), scope)}
    if isinstance(record, Mapping) and isinstance(record.get("previous_graph_ids"), list):
        previous.update(value for value in record["previous_graph_ids"] if isinstance(value, str) and value)
        return sorted(previous - {current})
    if not scope:
        previous.update(_relocated_config_graph_ids(record))
    if not scope and _field(record, "source") == PROJECT_CONFIG_SOURCE and _field(record, "config_path"):
        # Do not hash a redacted basename as though it were the original path.
        # New exports carry these receipts from the full model before redaction.
        location = str(_field(record, "config_path"))
        identities = []
        if not isinstance(record, Mapping) or os.path.isabs(location):
            identities.append(
                legacy_agent_id_v2(
                    str(_field(record, "agent_type") or _field(record, "type") or ""),
                    str(_field(record, "name") or ""),
                    config_path=location,
                )
            )
        elif prior := _field(record, "canonical_id") or _field(record, "stable_id") or _field(record, "id"):
            identities.append(str(prior))
        for identity in identities:
            old_scope = f"cfg-{hashlib.sha256(identity.encode()).hexdigest()[:12]}"
            previous.add(_legacy_agent_graph_id(_field(record, "name"), old_scope))
    return sorted(previous - {current})


def mcp_server_identity_kind(*, url: Any = None, command: Any = "", args: Sequence[Any] | None = None, registry_id: Any = None) -> str:
    """Remote endpoint, configured launch, or unresolved name-only declaration."""
    if str(url or "").strip():
        return "remote"
    if command or args:
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
    working_dir: str | None = None,
    environment: Mapping[str, Any] | None = None,
) -> str:
    """Keep configured launches scoped to their declaring agent.

    Equal recipes on a host do not establish one running process. Remote
    endpoint nodes may be shared while each declaring agent retains its edge.
    """
    label = str(name or "unknown").strip() or "unknown"
    kind = mcp_server_identity_kind(url=url, command=command, args=args, registry_id=registry_id)
    if kind == "agent":
        return f"server:{agent_key}:{label}" if agent_key else f"server:{label}"
    identity = str(canonical_id or "").strip() or canonical_mcp_server_id(
        label,
        str(command or ""),
        registry_id=str(registry_id or "") or None,
        url=str(url or "") or None,
        args=list(args or []),
        working_dir=working_dir,
        environment=environment,
    )
    scope = quote(str(host_scope or "").strip(), safe="")
    if kind == "host":
        owner = agent_key or scope
        if owner:
            return f"server:{owner}:{identity}"
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
        working_dir=_field(server, "working_dir"),
        environment=_field(server, "env"),
    )


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


def previous_agent_canonical_ids(agent: Any) -> list[str]:
    """Frozen old-version receipts, computed before config-path redaction."""
    kind = agent.agent_type.value if hasattr(agent.agent_type, "value") else str(agent.agent_type)
    prior = [
        legacy_agent_id_v2(
            kind,
            agent.name,
            source_id=agent.source_id or "",
            device_fingerprint=agent.device_fingerprint or "",
            config_path=agent.config_path,
        )
    ]
    if not (agent.source_id or agent.device_fingerprint):
        prior.append(legacy_agent_id_v1(kind, agent.name, source=agent.source or "", config_path=agent.config_path))
    return list(dict.fromkeys(identity for identity in prior if identity != agent.stable_id))


def agent_identity_export(agent: Any) -> dict[str, Any]:
    """The same identity receipts on manifest and scan entity exports."""
    return {
        "id": agent.stable_id,
        "canonical_id": agent.canonical_id,
        "previous_canonical_ids": agent.previous_canonical_ids,
        "previous_graph_ids": agent.previous_graph_ids,
    }
