"""Distinct advisory/package review counts shared by scan and ingest surfaces."""

from __future__ import annotations

from typing import Any

from agent_bom.core.packages import canonical_package_key


def _field(value: Any, name: str, default: Any = None) -> Any:
    return value.get(name, default) if isinstance(value, dict) else getattr(value, name, default)


def count_possibly_affected(agents: list[Any]) -> int:
    """Count unique package/advisory pairs, independently of confirmed findings."""
    pairs: set[tuple[str, str]] = set()
    for agent in agents:
        for server in _field(agent, "mcp_servers", []) or []:
            for package in _field(server, "packages", []) or []:
                candidates = _field(package, "possibly_affected", []) or []
                if not candidates:
                    continue
                key = canonical_package_key(
                    str(_field(package, "name", "")),
                    str(_field(package, "version", "") or ""),
                    str(_field(package, "ecosystem", "") or ""),
                    _field(package, "purl"),
                )
                for entry in candidates:
                    advisory_id = _field(entry, "id")
                    if isinstance(advisory_id, str) and advisory_id.strip():
                        pairs.add((key, advisory_id.strip()))
    return len(pairs)
