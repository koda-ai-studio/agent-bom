"""Which inventory servers host a vulnerability, found through an index instead of a full scan per finding.

At 5,000 agents the context graph matched 9,360 vulnerability rows against
about 30,000 servers each. The index narrows each row to the servers of its
named agents or named servers first, then applies the same package rules.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable

from agent_bom.package_utils import canonical_package_identity

Inventory = dict[str, tuple[str, str, list]]
Identity = tuple[str, str, str]


def finding_package_identity(row: dict) -> Identity:
    reference = str(row.get("package") or "")
    name, version = reference, ""
    if reference.rfind("@") > 0:
        name, version = reference.rsplit("@", 1)
    return canonical_package_identity(
        str(row.get("package_name") or name),
        str(row.get("package_version") or version),
        str(row.get("ecosystem") or ""),
        row.get("package_purl") or row.get("purl"),
    )


class InventoryHosts:
    """Server inventory indexed by agent and by server name, with package identities computed once."""

    def __init__(self, inventory: Inventory) -> None:
        self._inventory = inventory
        self._by_agent: dict[str, list[str]] = defaultdict(list)
        self._by_server: dict[str, list[str]] = defaultdict(list)
        for server_id, (agent, server, _packages) in inventory.items():
            self._by_agent[agent].append(server_id)
            self._by_server[server].append(server_id)
        self._identities: dict[str, list[Identity]] = {}

    def _candidates(self, agents: set[str], servers: set[str]) -> Iterable[str]:
        if agents:
            ids = (server_id for agent in agents for server_id in self._by_agent.get(agent, ()))
            return [server_id for server_id in ids if not servers or self._inventory[server_id][1] in servers]
        if servers:
            return [server_id for server in servers for server_id in self._by_server.get(server, ())]
        return list(self._inventory)

    def _package_identities(self, server_id: str) -> list[Identity]:
        if (cached := self._identities.get(server_id)) is None:
            cached = [
                canonical_package_identity(
                    package.get("name", ""), package.get("version", ""), package.get("ecosystem", ""), package.get("purl")
                )
                for package in self._inventory[server_id][2]
            ]
            self._identities[server_id] = cached
        return cached

    def hosts(self, row: dict) -> list[str]:
        """Narrow real owners; never invent ownership from two independent lists."""
        agents = set(row.get("affected_agent_graph_ids") or ()) or {f"agent:{name}" for name in row.get("affected_agents") or []}
        servers = set(row.get("affected_servers") or [])
        candidates = list(self._candidates(agents, servers))
        ecosystem, name, version = finding_package_identity(row)
        matched: dict[str, set[Identity]] = {}
        for server_id in candidates:
            for identity in self._package_identities(server_id):
                if name and identity[1] == name and (not version or identity[2] == version) and (not ecosystem or identity[0] == ecosystem):
                    matched.setdefault(server_id, set()).add(identity)
        identities = set().union(*matched.values()) if matched else set()
        if identities:
            # Missing ecosystem/version is acceptable only if it resolves uniquely.
            return sorted(matched) if len(identities) == 1 else []
        if any(self._inventory[server_id][2] for server_id in candidates):
            return []  # Inventory contradicts the finding: do not fall back to names.
        # Legacy payloads without package inventory can identify one dimension
        # exactly; two multi-valued lists cannot establish individual ownership.
        return sorted(candidates) if agents and servers and (len(agents) == 1 or len(servers) == 1) else []


__all__ = ["InventoryHosts", "finding_package_identity"]
