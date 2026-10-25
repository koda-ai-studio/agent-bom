"""Cross-source discovery identity collapse helpers."""

from __future__ import annotations

from pathlib import Path

from agent_bom.canonical_ids import agent_graph_id_for
from agent_bom.models import Agent, AgentStatus, AgentType, MCPResource, MCPServer, MCPTool, Package


def server_identity_key(server: MCPServer) -> str:
    """Use the served instance identity, including endpoint and argv boundaries."""
    return server.canonical_id


def deduplicate_discovered_agents(agents: list[Agent]) -> list[Agent]:
    """Merge repeated declarations only within the same agent identity.

    Equal URLs may describe a shared remote endpoint, but must not discard
    another agent's relationship to it. Equal launch recipes do not prove the
    same process across configuration, container and runtime observations.
    """
    seen: dict[tuple[str, str, str], MCPServer] = {}
    merged_agents: list[Agent] = []

    for agent in agents:
        deduped_servers: list[MCPServer] = []
        for server in agent.mcp_servers:
            _record_source(server, agent)
            key = (agent.stable_id, agent_graph_id_for(agent), server_identity_key(server))
            existing = seen.get(key)
            if existing is None:
                seen[key] = server
                deduped_servers.append(server)
                continue
            _merge_server(existing, server)

        if deduped_servers or not agent.mcp_servers:
            agent.mcp_servers = deduped_servers
            merged_agents.append(agent)

    # Merging can append children and mutate command/url/registry_id, so re-scope
    # every surviving server's child identities to its final canonical id.
    for server in seen.values():
        server.stamp_child_identities()

    return merged_agents


def _record_source(server: MCPServer, agent: Agent) -> None:
    sources = _source_list(server)
    source = agent.source or agent.agent_type.value
    marker = f"{source}:{server.config_path or agent.config_path}"
    if marker not in sources:
        sources.append(marker)


def _source_list(server: MCPServer) -> list[str]:
    current = getattr(server, "discovery_sources", None)
    if isinstance(current, list):
        return current
    server.discovery_sources = []
    return server.discovery_sources


def _merge_server(target: MCPServer, incoming: MCPServer) -> None:
    target.tools = _merge_by_stable_id(target.tools, incoming.tools)
    target.resources = _merge_by_stable_id(target.resources, incoming.resources)
    target.packages = _merge_by_stable_id(target.packages, incoming.packages)
    target.env = {**incoming.env, **target.env}
    target.security_blocked = target.security_blocked or incoming.security_blocked
    target.security_warnings = _merge_strings(target.security_warnings, incoming.security_warnings)
    existing_intel = {
        (str(item.get("entry_id")), str(item.get("matched_value"))) for item in target.security_intelligence if isinstance(item, dict)
    }
    for item in incoming.security_intelligence:
        if not isinstance(item, dict):
            continue
        key = (str(item.get("entry_id")), str(item.get("matched_value")))
        if key not in existing_intel:
            target.security_intelligence.append(item)
            existing_intel.add(key)
    target.discovery_sources = _merge_strings(_source_list(target), _source_list(incoming))
    if not target.working_dir:
        target.working_dir = incoming.working_dir
    if not target.url:
        target.url = incoming.url
    if not target.registry_id:
        target.registry_id = incoming.registry_id
    target.registry_verified = target.registry_verified or incoming.registry_verified


def _merge_by_stable_id(items: list[MCPTool] | list[MCPResource] | list[Package], incoming: list) -> list:
    merged = list(items)
    seen = {getattr(item, "stable_id", repr(item)) for item in merged}
    for item in incoming:
        key = getattr(item, "stable_id", repr(item))
        if key not in seen:
            merged.append(item)
            seen.add(key)
    return merged


def _merge_strings(existing: list[str], incoming: list[str]) -> list[str]:
    merged = list(existing)
    seen = set(merged)
    for item in incoming:
        if item not in seen:
            merged.append(item)
            seen.add(item)
    return merged


# Discovery sources that describe one local project directory rather than a
# host-level AI client. Several of them fire for the same ``-p`` target, and each
# used to emit its own agent, so one project surfaced as three to five agents.
PROJECT_LOCAL_SOURCES = frozenset({"project", "project-config", "ai-inventory", "python-agents", "filesystem", "sast"})
PROJECT_ROOT_METADATA_KEY = "project_root"


def project_root_for(agent: Agent) -> str | None:
    """Resolved project directory an agent was discovered from, if it is project-local."""
    if agent.source not in PROJECT_LOCAL_SOURCES:
        return None
    # A shared directory is weaker evidence than an explicit device/source
    # identity. Keep these agents intact instead of replacing their identities
    # with the synthetic project wrapper's path-derived identity.
    if agent.source_id or agent.device_fingerprint:
        return None
    explicit = (agent.metadata or {}).get(PROJECT_ROOT_METADATA_KEY)
    if isinstance(explicit, str) and explicit:
        return str(Path(explicit).resolve())
    if not agent.config_path:
        return None
    path = Path(agent.config_path)
    definition_root = _definition_root(path, (agent.metadata or {}).get("definition_file"))
    if definition_root is not None:
        return definition_root
    if not path.is_dir():
        return None
    return str(path.resolve())


def _definition_root(config_path: Path, definition_file: object) -> str | None:
    """Project root of a code-defined agent whose config path is its defining file.

    The scanner records the file relative to the project root, so the root is
    the config path with that relative suffix removed.
    """
    if not isinstance(definition_file, str) or not definition_file:
        return None
    relative = Path(definition_file).parts
    if not relative or ".." in relative or len(config_path.parts) <= len(relative):
        return None
    if config_path.parts[-len(relative) :] != relative or not config_path.is_file():
        return None
    return str(Path(*config_path.parts[: -len(relative)]).resolve())


def consolidate_project_agents(agents: list[Agent]) -> list[Agent]:
    """Collapse every project-local discovery source for one root into one agent.

    The canonical identity is ``project:<root name>`` rooted at the project
    directory, matching the manifest-scan agent so its canonical id is stable.
    Each contributing source stays visible as evidence on the merged agent
    (``evidence_sources``), code-defined agent constructs are recorded as
    ``code_agents``, and every server/package/tool is kept. Host-level agents
    and single-source projects are returned unchanged.
    """
    groups: dict[str, list[int]] = {}
    for index, agent in enumerate(agents):
        root = project_root_for(agent)
        if root is not None:
            groups.setdefault(root, []).append(index)

    merged_at: dict[int, Agent] = {}
    absorbed: set[int] = set()
    for root, indexes in groups.items():
        if len(indexes) < 2:
            continue
        members = [agents[index] for index in indexes]
        merged_at[indexes[0]] = _merge_project_members(root, members, Path(root).name or root)
        absorbed.update(indexes[1:])

    return [merged_at.get(index, agent) for index, agent in enumerate(agents) if index not in absorbed]


def _code_agent_definitions(member: Agent, seen: list[dict[str, str]]) -> list[dict[str, str]]:
    member_metadata = member.metadata or {}
    prior = member_metadata.get("code_agent_definitions")
    if isinstance(prior, list):
        candidates = [item for item in prior if isinstance(item, dict)]
    elif member.source == "python-agents" and member_metadata.get("definition_file"):
        candidates = [
            {
                "name": member.name,
                "file": str(member_metadata.get("definition_file") or ""),
                "scope": str(member_metadata.get("definition_scope") or ""),
            }
        ]
    else:
        candidates = []
    return [item for item in candidates if item not in seen]


def _merge_project_members(root: str, members: list[Agent], label: str) -> Agent:
    name = f"project:{label}"
    manifest = next((member for member in members if member.source == "project" and member.name == name), None)

    servers: list[MCPServer] = []
    by_key: dict[str, MCPServer] = {}
    for member in members:
        for server in member.mcp_servers:
            key = server_identity_key(server)
            existing = by_key.get(key)
            if existing is None:
                by_key[key] = server
                servers.append(server)
            else:
                _merge_server(existing, server)

    metadata: dict[str, object] = {}
    evidence: set[str] = set()
    code_agents: list[str] = []
    definitions: list[dict[str, str]] = []
    for member in members:
        member_metadata = member.metadata or {}
        for key, value in member_metadata.items():
            metadata.setdefault(key, value)
        prior_evidence = member_metadata.get("evidence_sources")
        if isinstance(prior_evidence, list):
            evidence.update(str(item) for item in prior_evidence)
        elif member.source:
            evidence.add(member.source)
        prior_code = member_metadata.get("code_agents")
        candidates = [str(item) for item in prior_code] if isinstance(prior_code, list) else []
        if not candidates and member.source == "python-agents":
            candidates = [member.name]
        code_agents.extend(item for item in candidates if item not in code_agents)
        definitions.extend(_code_agent_definitions(member, definitions))
    metadata[PROJECT_ROOT_METADATA_KEY] = root
    metadata["evidence_sources"] = sorted(evidence)
    if code_agents:
        metadata["code_agents"] = code_agents
    if definitions:
        # Names alone collide (two "assistant" agents in two files); the
        # definition file and scope keep each code-level agent distinct.
        metadata["code_agent_definitions"] = definitions

    discovered = sorted(member.discovered_at for member in members if member.discovered_at)
    last_seen = sorted(member.last_seen for member in members if member.last_seen)
    configured = any(member.status == AgentStatus.CONFIGURED for member in members)
    return Agent(
        name=name,
        agent_type=AgentType.CUSTOM,
        config_path=manifest.config_path if manifest is not None else root,
        mcp_servers=servers,
        source="project",
        status=AgentStatus.CONFIGURED if configured else members[0].status,
        discovered_at=discovered[0] if discovered else "",
        last_seen=last_seen[-1] if last_seen else None,
        metadata=metadata,
        automation_settings=[setting for member in members for setting in member.automation_settings],
        discovery_provenance=next((member.discovery_provenance for member in members if member.discovery_provenance), None),
        discovery_envelope=next((member.discovery_envelope for member in members if member.discovery_envelope), None),
    )
