"""Structured field names whose values still require component-level secret checks."""

_REPORT_COORDINATE_KEYS = {
    "id",
    "canonical_id",
    "node_id",
    "node_ids",
    "nodeids",
    "edge_id",
    "edge_ids",
    "edgeids",
    "source",
    "target",
    "source_id",
    "target_id",
    "source_node_id",
    "target_node_id",
    "agent_ref",
    "target_ref",
    "upstream_ref",
    "purl",
    "identifier",
    "finding_group_key",
    "finding_node_id",
}
_REPORT_AUTH_MODES = {
    "env-credentials",
    "url-embedded-credentials",
    "network-no-auth-observed",
    "local-stdio",
    "managed_identity",
    "workload_identity",
}
