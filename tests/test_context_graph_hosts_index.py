"""Vulnerability hosts come from an inventory index, not a scan of every server per finding.

At 5,000 agents the context graph matched 9,360 vulnerability rows against
about 30,000 servers each, which made it the largest cost of posture evidence
after a push. The indexed lookup must give exactly the old answer.
"""

from __future__ import annotations

import random
import time

from agent_bom.context_graph import _finding_package_identity
from agent_bom.graph.context_hosts import InventoryHosts
from agent_bom.package_utils import canonical_package_identity


def _reference(row: dict, inventory: dict[str, tuple[str, str, list]]) -> list[str]:
    agents = set(row.get("affected_agent_graph_ids") or ()) or {f"agent:{name}" for name in row.get("affected_agents") or []}
    servers = set(row.get("affected_servers") or [])
    candidates = {
        server_id: packages
        for server_id, (agent, server, packages) in inventory.items()
        if (not agents or agent in agents) and (not servers or server in servers)
    }
    ecosystem, name, version = _finding_package_identity(row)
    matched: dict[str, set[tuple[str, str, str]]] = {}
    for server_id, packages in candidates.items():
        for package in packages:
            identity = canonical_package_identity(
                package.get("name", ""), package.get("version", ""), package.get("ecosystem", ""), package.get("purl")
            )
            if name and identity[1] == name and (not version or identity[2] == version) and (not ecosystem or identity[0] == ecosystem):
                matched.setdefault(server_id, set()).add(identity)
    identities = set().union(*matched.values()) if matched else set()
    if identities:
        return sorted(matched) if len(identities) == 1 else []
    if any(candidates.values()):
        return []
    return sorted(candidates) if agents and servers and (len(agents) == 1 or len(servers) == 1) else []


def _estate(rng: random.Random, *, agents: int, servers_per_agent: int, legacy_rate: float) -> dict[str, tuple[str, str, list]]:
    inventory: dict[str, tuple[str, str, list]] = {}
    names = [f"pkg-{index}" for index in range(40)]
    for agent in range(agents):
        for server in range(servers_per_agent):
            shared = rng.random() < 0.3
            server_name = f"shared-{server}" if shared else f"server-{agent}-{server}"
            packages = (
                []
                if rng.random() < legacy_rate
                else [
                    {"name": rng.choice(names), "version": rng.choice(["1.0.0", "2.0.0"]), "ecosystem": rng.choice(["npm", "pypi"])}
                    for _ in range(rng.randint(1, 4))
                ]
            )
            inventory[f"server:{agent}:{server}"] = (f"agent:a{agent}", server_name, packages)
    return inventory


def _rows(rng: random.Random, count: int, *, agents: int, servers_per_agent: int) -> list[dict]:
    rows = []
    for _ in range(count):
        row: dict = {"package": f"pkg-{rng.randrange(40)}@{rng.choice(['1.0.0', '2.0.0', ''])}".rstrip("@")}
        if rng.random() < 0.5:
            row["ecosystem"] = rng.choice(["npm", "pypi"])
        shape = rng.random()
        if shape < 0.4:
            row["affected_agents"] = [f"a{rng.randrange(agents)}" for _ in range(rng.randint(1, 3))]
        elif shape < 0.6:
            row["affected_agent_graph_ids"] = [f"agent:a{rng.randrange(agents)}"]
        if rng.random() < 0.6:
            row["affected_servers"] = [
                rng.choice(
                    [f"shared-{rng.randrange(servers_per_agent)}", f"server-{rng.randrange(agents)}-{rng.randrange(servers_per_agent)}"]
                )
                for _ in range(rng.randint(1, 2))
            ]
        rows.append(row)
    return rows


def test_indexed_hosts_equal_the_full_scan() -> None:
    rng = random.Random(2145)
    for legacy_rate in (0.0, 0.2, 1.0):
        inventory = _estate(rng, agents=40, servers_per_agent=4, legacy_rate=legacy_rate)
        hosts = InventoryHosts(inventory)
        for row in _rows(rng, 600, agents=40, servers_per_agent=4) + [{}, {"package": ""}, {"affected_servers": ["shared-0"]}]:
            assert hosts.hosts(row) == _reference(row, inventory), row


def test_empty_inventory_has_no_hosts() -> None:
    assert InventoryHosts({}).hosts({"package": "pkg-1@1.0.0", "affected_agents": ["a1"], "affected_servers": ["s"]}) == []


def test_estate_scale_lookup_stays_within_budget() -> None:
    # 9,000 rows against 30,000 servers, the shape of a 5,000-agent estate:
    # about 8 s as a full scan per row before, well under a second indexed.
    rng = random.Random(7)
    inventory = _estate(rng, agents=5000, servers_per_agent=6, legacy_rate=0.0)
    rows = [
        row
        for row in _rows(rng, 9000, agents=5000, servers_per_agent=6)
        if row.get("affected_agents") or row.get("affected_agent_graph_ids")
    ]
    started = time.perf_counter()
    hosts = InventoryHosts(inventory)
    for row in rows:
        hosts.hosts(row)
    assert time.perf_counter() - started < 2.0
