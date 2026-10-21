"""Which vendors an attack path starts and ends in, read from recorded node attributes.

A node's vendor is the ``cloud_provider`` (or ``provider``) a collector recorded
on it. Agent-runtime surfaces (MCP, local) are not vendors. A path is
cross-vendor when its own source and target nodes both carry a vendor and the
two differ; vendors on middle hops never qualify a path (a CVE reached through
a cloud workload is not a vendor crossing). Nothing is inferred from ids.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from typing import Any

_VENDOR_FIELDS = ("cloud_provider", "provider")
_NOT_VENDORS = frozenset({"", "mcp", "local", "unknown", "none", "agent", "runtime", "framework", "sensor"})


def node_vendor(node: Any) -> str:
    attributes = getattr(node, "attributes", None) or {}
    dimensions = getattr(node, "dimensions", None)
    candidates = [attributes.get(field) for field in _VENDOR_FIELDS] + [getattr(dimensions, "cloud_provider", "")]
    for candidate in candidates:
        value = str(candidate or "").strip().lower()
        if value and value not in _NOT_VENDORS:
            return value
    return ""


def path_vendor_pair(path: Any, nodes_by_id: Mapping[str, Any]) -> tuple[str, str] | None:
    """``(source vendor, target vendor)`` when the path's endpoints are in different vendors, else ``None``."""
    source = node_vendor(nodes_by_id.get(path.hops[0] if path.hops else path.source))
    target = node_vendor(nodes_by_id.get(path.hops[-1] if path.hops else path.target))
    if not source or not target or source == target:
        return None
    return source, target


def vendor_pair_facets(pairs: Iterable[tuple[str, str] | None]) -> list[dict[str, Any]]:
    counts = Counter(pair for pair in pairs if pair is not None)
    ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return [{"source_vendor": source, "target_vendor": target, "paths": count} for (source, target), count in ordered]


__all__ = ["node_vendor", "path_vendor_pair", "vendor_pair_facets"]
