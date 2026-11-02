"""Continue (continue.dev) MCP config shapes that differ from the ``mcpServers`` map."""

from __future__ import annotations

_REMOTE_TRANSPORTS = frozenset({"sse", "http", "streamable-http"})


def continue_legacy_servers(config_data: dict) -> list[dict]:
    """Flatten the deprecated ``experimental.modelContextProtocolServers[].transport`` shape.

    Each entry becomes a standard server dict (``name``, ``command``, ``args``,
    ``env``, ``url``/``type``); unnamed entries are numbered so the servers stay
    distinguishable in reports.
    """
    experimental = config_data.get("experimental")
    entries = experimental.get("modelContextProtocolServers") if isinstance(experimental, dict) else None
    if not isinstance(entries, list):
        return []
    servers: list[dict] = []
    for index, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            continue
        transport = entry.get("transport")
        if not isinstance(transport, dict):
            continue
        server = {key: value for key, value in transport.items() if key != "type"}
        transport_type = str(transport.get("type") or "stdio").lower()
        if transport_type in _REMOTE_TRANSPORTS or "url" in server:
            server["type"] = "sse" if transport_type == "sse" else "http"
        server["name"] = str(entry.get("name") or f"continue-mcp-{index}")
        servers.append(server)
    return servers
