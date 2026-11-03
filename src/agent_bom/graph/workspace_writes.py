"""Bounded write batches for one tenant's private graph build workspace."""

from __future__ import annotations

from agent_bom.graph.build_workspace import WorkspaceBackend, _batch_size


class WorkspaceWrites:
    """Keep insertion order and latest serialized values until a read boundary.

    Rows are serialized before enqueueing: buffering does not make later edge
    object mutations observable. Cached node mutations still use the container's
    existing dirty tracking. Successful backend calls alone clear pending rows.
    """

    def __init__(self, backend: WorkspaceBackend, tenant: str) -> None:
        self.backend = backend
        self.tenant = tenant
        # This live container also owns an LRU and a read page. The bulk import
        # setting is an upper bound, not permission to duplicate a whole page
        # of serialized rows alongside those objects.
        self.limit = min(256, _batch_size())
        self.nodes: dict[str, tuple[str, str, str]] = {}
        self.edges: dict[str, tuple[str, str, str, str]] = {}

    def node_payload(self, node_id: str) -> str | None:
        row = self.nodes.get(node_id)
        return row[1] if row is not None else None

    def edge_payload(self, edge_key: str) -> str | None:
        row = self.edges.get(edge_key)
        return row[1] if row is not None else None

    def add_node(self, row: tuple[str, str, str]) -> None:
        self.nodes[row[0]] = row
        if len(self.nodes) >= self.limit:
            self.flush_nodes()

    def add_edge(self, row: tuple[str, str, str, str]) -> None:
        self.edges[row[0]] = row
        if len(self.edges) >= self.limit:
            self.flush_edges()

    def flush_nodes(self) -> None:
        if self.nodes:
            self.backend.add_node_payloads(self.tenant, tuple(self.nodes.values()))
            self.nodes.clear()

    def flush_edges(self) -> None:
        if self.edges:
            self.backend.add_edge_payloads(self.tenant, tuple(self.edges.values()))
            self.edges.clear()

    def flush(self) -> None:
        self.flush_nodes()
        self.flush_edges()
