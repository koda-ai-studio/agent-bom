"""Which containment parent a roll-up child is listed under.

The roll-up nests every node under the scopes that contain it. Two rules keep
those listings to the nearest recorded owner without changing any descendant
set: a provider parents an org or account only when nothing else does, and a
parent that is also an ancestor of another of the child's parents is dropped.
"""

from __future__ import annotations

from collections import Counter, defaultdict, deque

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.path_derivation import _node_type_value
from agent_bom.graph.types import EntityType


def drop_fallback_provider_parents(graph: UnifiedGraph, children: dict[str, set[str]]) -> None:
    """A provider parents an org/account only when nothing else does.

    Inventory records ``provider HOSTS account`` for every collected account,
    including one an organization already contains. Kept as a second parent it
    makes the provider an overlapping top-level root that counts the same
    findings twice; the organization is the nearer, recorded owner.
    """
    provider_value = EntityType.PROVIDER.value
    providers = {pid for pid in children if (node := graph.nodes.get(pid)) is not None and _node_type_value(node) == provider_value}
    if not providers:
        return
    owned_elsewhere = {kid for parent, kids in children.items() if parent not in providers for kid in kids}
    for provider_id in providers:
        children[provider_id] -= owned_elsewhere


def drop_redundant_parents(children: dict[str, set[str]]) -> int:
    """Keep each child under its nearest containment parents only; return edges dropped.

    A parent P of child C is redundant when P is an ancestor of another parent
    Q of C: C stays reachable from P through Q, so every descendant set (and
    every aggregate built from one) is unchanged, while P's direct children
    stop listing C a second time beside the scope that actually holds it.
    A parent that sits in a cycle through C reaches C only via C itself, so it
    is never the witness; and when every parent would go (parents that are
    each other's ancestors) the child keeps them all rather than being orphaned.
    Mutates ``children`` in place; ancestor sets are cached per parent and the
    walk is bounded by a visited set, so cycles terminate.
    """
    parents: dict[str, set[str]] = defaultdict(set)
    for parent, kids in children.items():
        for kid in kids:
            parents[kid].add(parent)
    ancestors_cache: dict[str, frozenset[str]] = {}

    def ancestors(node: str) -> frozenset[str]:
        cached = ancestors_cache.get(node)
        if cached is None:
            seen: set[str] = set()
            queue: deque[str] = deque(parents.get(node, ()))
            while queue:
                current = queue.popleft()
                if current in seen:
                    continue
                seen.add(current)
                queue.extend(parents.get(current, ()))
            cached = ancestors_cache[node] = frozenset(seen)
        return cached

    dropped = 0
    for child, owners in parents.items():
        if len(owners) < 2:
            continue
        # A parent inside a cycle through the child only reaches it via the child itself; it is no witness.
        # One pass over the witnesses' ancestors, not a pairwise check: a package
        # shared by a thousand servers would otherwise cost a million lookups.
        above: Counter[str] = Counter()
        for other in owners:
            lineage = ancestors(other)
            if child in lineage:
                continue
            above.update(owner for owner in lineage & owners if owner != other)
        redundant = set(above)
        if not redundant or redundant == owners:
            continue
        for owner in redundant:
            children[owner].discard(child)
            dropped += 1
    return dropped
