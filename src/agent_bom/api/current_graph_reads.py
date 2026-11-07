"""Graph store reads the current-estate wrapper answers from its projection; every other method passes through."""

_READS = frozenset(
    {
        "load_graph",
        "load_rollup_graph",
        "iter_nodes",
        "iter_edges",
        "snapshot_identity",
        "snapshot_stats",
        "page_nodes",
        "edges_for_node_ids",
        "search_nodes",
        "query_inventory",
        "nodes_by_ids",
        "bfs_paths",
        "impact_of",
        "traverse_subgraph",
        "attack_paths_for_sources",
        "longest_path_to",
        "attack_paths",
        "snapshot_attack_paths",
        "snapshot_queue_page",
        "snapshot_path_summary",
        "snapshot_cross_vendor_page",
        "incident_edges_page",
        "node_context",
        "resolve_node_aliases",
        "compliance_summary",
        "evidence_manifest",
    }
)
