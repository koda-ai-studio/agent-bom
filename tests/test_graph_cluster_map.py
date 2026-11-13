"""Grouped full map: clusters by estate tier and type, bundled edges with exact counts."""

from __future__ import annotations

from collections import Counter

import pytest

from agent_bom.graph import UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.cluster_index import ClusterIndex
from agent_bom.graph.cluster_map import FIRST_FRAME_ELEMENT_BUDGET, cluster_map_view
from agent_bom.graph.path_records import AttackPath
from agent_bom.graph.types import EntityType, RelationshipType

pytestmark = pytest.mark.graph_contract("warn")

E = EntityType
R = RelationshipType


def _node(graph: UnifiedGraph, node_id: str, kind: EntityType, label: str = "", severity: str = "", **attributes: object) -> None:
    graph.add_node(UnifiedNode(id=node_id, entity_type=kind, label=label or node_id, severity=severity, attributes=dict(attributes)))


def _edge(graph: UnifiedGraph, source: str, target: str, rel: RelationshipType) -> None:
    graph.add_edge(UnifiedEdge(source=source, target=target, relationship=rel))


def estate() -> UnifiedGraph:
    """provider → account → resources; two agents → three servers → npm/pypi packages → findings."""
    g = UnifiedGraph(scan_id="cluster-scan", tenant_id="default")
    _node(g, "provider:aws", E.PROVIDER, "AWS")
    _node(g, "account:prod", E.ACCOUNT, "prod")
    _node(g, "res:vm", E.CLOUD_RESOURCE, "vm-1", resource_type="instance")
    _node(g, "res:bucket", E.CLOUD_RESOURCE, "bucket-1", resource_type="s3")
    _node(g, "agent:a", E.AGENT, "Claude Desktop")
    _node(g, "agent:b", E.AGENT, "Cursor")
    for server in ("s1", "s2", "s3"):
        _node(g, f"server:{server}", E.SERVER, server)
    for i in range(1, 11):
        _node(g, f"pkg:n{i}", E.PACKAGE, f"npm-{i:02d}", ecosystem="npm")
    _node(g, "pkg:p1", E.PACKAGE, "pypi-1", ecosystem="pypi")
    _node(g, "pkg:p2", E.PACKAGE, "pypi-2", ecosystem="pypi")
    _node(g, "vuln:crit", E.VULNERABILITY, "CVE-crit", "critical")
    _node(g, "vuln:high", E.VULNERABILITY, "CVE-high", "high")
    _node(g, "vuln:low", E.VULNERABILITY, "CVE-low", "low")
    _node(g, "cred:key", E.CREDENTIAL, "API_KEY")
    _edge(g, "provider:aws", "account:prod", R.HOSTS)
    _edge(g, "account:prod", "res:vm", R.CONTAINS)
    _edge(g, "account:prod", "res:bucket", R.CONTAINS)
    _edge(g, "agent:a", "server:s1", R.USES)
    _edge(g, "agent:a", "server:s2", R.USES)
    _edge(g, "agent:b", "server:s3", R.USES)
    for i in range(1, 7):
        _edge(g, "server:s1", f"pkg:n{i}", R.DEPENDS_ON)
    for i in range(7, 11):
        _edge(g, "server:s2", f"pkg:n{i}", R.DEPENDS_ON)
    _edge(g, "server:s3", "pkg:p1", R.DEPENDS_ON)
    _edge(g, "server:s3", "pkg:p2", R.DEPENDS_ON)
    _edge(g, "pkg:n1", "vuln:crit", R.VULNERABLE_TO)
    _edge(g, "pkg:n2", "vuln:low", R.VULNERABLE_TO)
    _edge(g, "pkg:p1", "vuln:high", R.VULNERABLE_TO)
    _edge(g, "server:s1", "cred:key", R.EXPOSES_CRED)
    _edge(g, "agent:a", "res:vm", R.HOSTED_ON)
    g.attack_paths.append(AttackPath(source="agent:a", target="vuln:crit", hops=["agent:a", "server:s1", "pkg:n1", "vuln:crit"], edges=[]))
    return g


def _by_id(view: dict) -> dict[str, dict]:
    return {node["id"]: node for node in view["nodes"]}


def _cluster(view: dict, key: str) -> dict:
    return next(node for node in view["nodes"] if node["kind"] == "cluster" and node["cluster_key"] == key)


def _assert_edges_conserved(view: dict, graph: UnifiedGraph) -> None:
    summary = view["summary"]
    drawn = sum(edge["count"] for edge in view["edges"])
    assert drawn + summary["hidden_bundle_edge_count"] + summary["internal_edge_count"] + summary["filtered_edge_count"] == len(graph.edges)
    for edge in view["edges"]:
        assert edge["count"] == sum(item["count"] for item in edge["relationships"])
        assert edge["count"] > 0


def test_clusters_follow_tier_and_type_and_cover_every_node_once() -> None:
    graph = estate()
    view = cluster_map_view(ClusterIndex.from_graph(graph))
    keys = {node["cluster_key"] for node in view["nodes"] if node["kind"] == "cluster"}
    assert {"type:provider", "type:account", "type:agent", "type:server", "package:npm", "package:pypi"} <= keys
    assert {"finding:critical", "finding:high", "finding:low", "type:credential"} <= keys
    assert {"cloud_resource:instance", "cloud_resource:s3"} <= keys
    assert _cluster(view, "package:npm")["member_count"] == 10
    assert _cluster(view, "package:npm")["label"] == "Packages · npm"
    assert _cluster(view, "finding:critical")["label"] == "Findings · critical"
    # Every node belongs to exactly one cluster, and the per-type totals equal the inventory.
    by_type: Counter[str] = Counter()
    for cluster in view["clusters"]:
        by_type.update(cluster["entity_types"])
    assert sum(cluster["member_count"] for cluster in view["clusters"]) == len(graph.nodes)
    assert dict(by_type) == dict(Counter(node.entity_type.value for node in graph.nodes.values()))


def test_cluster_summary_carries_worst_severity_in_words_and_attack_path_membership() -> None:
    view = cluster_map_view(ClusterIndex.from_graph(estate()))
    npm = _cluster(view, "package:npm")
    # A package that is vulnerable to a critical finding makes its group critical.
    assert npm["worst_severity"] == "critical"
    assert npm["on_attack_path_count"] == 1
    assert npm["risky"] is True
    pypi = _cluster(view, "package:pypi")
    assert pypi["worst_severity"] == "high"
    cred = _cluster(view, "type:credential")
    assert cred["worst_severity"] == "none"
    assert cred["risky"] is False


def test_risky_clusters_are_ordered_first() -> None:
    view = cluster_map_view(ClusterIndex.from_graph(estate()))
    order = [node["cluster_key"] for node in view["clusters"]]
    risky = [node["risky"] for node in view["clusters"]]
    assert risky == sorted(risky, reverse=True)
    assert order.index("package:npm") < order.index("type:credential")


def test_bundled_edge_counts_equal_the_underlying_edges() -> None:
    graph = estate()
    view = cluster_map_view(ClusterIndex.from_graph(graph))
    ids = {node["cluster_key"]: node["id"] for node in view["nodes"] if node["kind"] == "cluster"}
    bundle = next(edge for edge in view["edges"] if edge["source"] == ids["type:server"] and edge["target"] == ids["package:npm"])
    assert bundle["count"] == 10
    assert bundle["relationships"] == [{"relationship": "depends_on", "count": 10}]
    uses = next(edge for edge in view["edges"] if edge["source"] == ids["type:agent"] and edge["target"] == ids["type:server"])
    assert uses["count"] == 3
    _assert_edges_conserved(view, graph)


def test_expand_shows_top_members_by_risk_plus_more_and_collapse_returns_the_group() -> None:
    graph = estate()
    index = ClusterIndex.from_graph(graph)
    collapsed = cluster_map_view(index)
    npm_id = _cluster(collapsed, "package:npm")["id"]
    expanded = cluster_map_view(index, expanded=[npm_id], member_limit=3)
    nodes = _by_id(expanded)
    members = [node for node in expanded["nodes"] if node["kind"] == "member" and node["cluster_id"] == npm_id]
    assert [node["id"] for node in members][0] == "pkg:n1"  # on the attack path, critical
    assert members[1]["id"] == "pkg:n2"  # low finding beats no finding
    assert len(members) == 3
    more = next(node for node in expanded["nodes"] if node["kind"] == "more" and node["cluster_id"] == npm_id)
    assert more["count"] == 7
    assert more["next_offset"] == 3
    assert nodes[npm_id]["expanded"] is True
    _assert_edges_conserved(expanded, graph)
    # The member edge is drawn from the member itself, with the remainder on "+K more".
    server = _cluster(expanded, "type:server")["id"]
    to_n1 = [edge for edge in expanded["edges"] if edge["source"] == server and edge["target"] == "pkg:n1"]
    assert to_n1 and to_n1[0]["count"] == 1
    to_more = next(edge for edge in expanded["edges"] if edge["source"] == server and edge["target"] == more["id"])
    assert to_more["count"] == 7
    # Collapse is the absence of the expansion: the same frame as before.
    assert cluster_map_view(index) == collapsed


def test_more_node_pages_through_members() -> None:
    graph = estate()
    index = ClusterIndex.from_graph(graph)
    npm_id = _cluster(cluster_map_view(index), "package:npm")["id"]
    page2 = cluster_map_view(index, expanded=[npm_id], pages={npm_id: 3}, member_limit=3)
    members = [node["id"] for node in page2["nodes"] if node["kind"] == "member"]
    assert len(members) == 3 and "pkg:n1" not in members
    more = next(node for node in page2["nodes"] if node["kind"] == "more")
    assert more["offset"] == 3 and more["prev_offset"] == 0 and more["next_offset"] == 6 and more["count"] == 7
    last = cluster_map_view(index, expanded=[npm_id], pages={npm_id: 9}, member_limit=3)
    assert next(node for node in last["nodes"] if node["kind"] == "more")["next_offset"] is None
    _assert_edges_conserved(page2, graph)
    _assert_edges_conserved(last, graph)


def test_expanding_two_connected_groups_keeps_counts_exact() -> None:
    graph = estate()
    index = ClusterIndex.from_graph(graph)
    first = cluster_map_view(index)
    server = _cluster(first, "type:server")["id"]
    npm = _cluster(first, "package:npm")["id"]
    view = cluster_map_view(index, expanded=[server, npm], member_limit=2)
    _assert_edges_conserved(view, graph)
    s1_n1 = [edge for edge in view["edges"] if edge["source"] == "server:s1" and edge["target"] == "pkg:n1"]
    assert s1_n1 and s1_n1[0]["count"] == 1


def _wide_estate(resource_types: int = 40, per_type: int = 30) -> UnifiedGraph:
    g = UnifiedGraph(scan_id="wide", tenant_id="default")
    _node(g, "account:a", E.ACCOUNT, "a")
    kinds = [E.ROLE, E.POLICY, E.SERVICE_ACCOUNT, E.DATASET, E.MODEL, E.TOOL, E.CI_JOB, E.SOURCE_FILE, E.CONFIG_FILE, E.USER]
    for kind in kinds:
        for i in range(5):
            _node(g, f"{kind.value}:{i}", kind)
            _edge(g, "account:a", f"{kind.value}:{i}", R.OWNS)
    for t in range(resource_types):
        for i in range(per_type):
            node_id = f"res:{t}:{i}"
            _node(g, node_id, E.CLOUD_RESOURCE, resource_type=f"type-{t:02d}")
            _edge(g, "account:a", node_id, R.CONTAINS)
            if i % 3 == 0:
                _edge(g, f"role:{i % 5}", node_id, R.CAN_ACCESS)
    return g


def test_first_frame_never_draws_more_than_the_element_budget() -> None:
    graph = _wide_estate()
    view = cluster_map_view(ClusterIndex.from_graph(graph))
    assert view["summary"]["element_count"] == len(view["nodes"]) + len(view["edges"])
    assert view["summary"]["element_count"] <= FIRST_FRAME_ELEMENT_BUDGET
    other = next(node for node in view["nodes"] if node["kind"] == "cluster" and node["cluster_key"] == "other")
    assert other["folded_cluster_count"] > 0
    _assert_edges_conserved(view, graph)
    # Expanding the folded group reveals its groups, still with exact counts.
    opened = cluster_map_view(ClusterIndex.from_graph(graph), expanded=[other["id"]])
    assert any(node["kind"] == "cluster" and node["cluster_key"].startswith("cloud_resource:") for node in opened["nodes"])
    assert not any(node["kind"] == "cluster" and node["cluster_key"] == "other" for node in opened["nodes"])
    _assert_edges_conserved(opened, graph)


def test_risky_only_keeps_risky_groups_and_reports_what_it_hides() -> None:
    graph = estate()
    view = cluster_map_view(ClusterIndex.from_graph(graph), risky_only=True)
    keys = {node["cluster_key"] for node in view["clusters"]}
    assert "package:npm" in keys and "finding:critical" in keys and "type:agent" in keys
    assert "type:credential" not in keys and "cloud_resource:s3" not in keys
    assert view["summary"]["filtered_node_count"] > 0
    _assert_edges_conserved(view, graph)


def test_focus_expands_the_group_holding_a_node_and_shows_it() -> None:
    graph = estate()
    view = cluster_map_view(ClusterIndex.from_graph(graph), focus="pkg:n9", member_limit=2)
    nodes = _by_id(view)
    assert "pkg:n9" in nodes
    assert nodes["pkg:n9"]["focused"] is True
    assert view["focus"] == {"node_id": "pkg:n9", "cluster_id": nodes["pkg:n9"]["cluster_id"], "found": True}
    assert nodes[nodes["pkg:n9"]["cluster_id"]]["expanded"] is True
    _assert_edges_conserved(view, graph)
    missing = cluster_map_view(ClusterIndex.from_graph(graph), focus="pkg:none")
    assert missing["focus"]["found"] is False


def test_rows_and_graph_build_the_same_index() -> None:
    graph = estate()
    rows = ClusterIndex.rows_from_graph(graph)
    assert cluster_map_view(ClusterIndex.from_rows(*rows)) == cluster_map_view(ClusterIndex.from_graph(graph))


def _fleet(agents: int) -> UnifiedGraph:
    g = UnifiedGraph(scan_id=f"fleet-{agents}", tenant_id="default")
    for a in range(agents):
        _node(g, f"agent:{a}", E.AGENT)
        for s in range(2):
            server = f"server:{a}:{s}"
            _node(g, server, E.SERVER)
            _edge(g, f"agent:{a}", server, R.USES)
            for p in range(5):
                pkg = f"pkg:{a}:{s}:{p}"
                _node(g, pkg, E.PACKAGE, ecosystem="npm" if p % 2 else "pypi")
                _edge(g, server, pkg, R.DEPENDS_ON)
    return g


def test_a_view_costs_what_it_draws_not_the_size_of_the_estate() -> None:
    small, large = ClusterIndex.from_graph(_fleet(50)), ClusterIndex.from_graph(_fleet(1000))
    for index in (small, large):
        agents = next(node for node in cluster_map_view(index)["nodes"] if node.get("cluster_key") == "type:agent")
        view = cluster_map_view(index, expanded=[agents["id"]], member_limit=8)
        # Each shown agent has two edges; the rest of the estate is answered from the per-snapshot aggregation.
        assert view["cost"]["edges_scanned"] == 8 * 2
        assert view["cost"]["bundles_considered"] <= 16
    assert len(small.edge_source) * 10 < len(large.edge_source)


def test_bundles_that_carry_an_attack_path_hop_are_marked() -> None:
    view = cluster_map_view(ClusterIndex.from_graph(estate()))
    ids = {node["cluster_key"]: node["id"] for node in view["nodes"] if node["kind"] == "cluster"}
    flags = {(edge["source"], edge["target"]): edge["on_attack_path"] for edge in view["edges"]}
    assert flags[(ids["type:agent"], ids["type:server"])] is True
    assert flags[(ids["type:server"], ids["package:npm"])] is True
    assert flags[(ids["package:npm"], ids["finding:critical"])] is True
    assert flags[(ids["type:server"], ids["type:credential"])] is False
    assert flags[(ids["type:provider"], ids["type:account"])] is False
    # Expanding keeps the flag exact: the hop moves to the member that carries it.
    opened = cluster_map_view(ClusterIndex.from_graph(estate()), expanded=[ids["package:npm"]], member_limit=3)
    on_path = {(edge["source"], edge["target"]) for edge in opened["edges"] if edge["on_attack_path"]}
    assert (ids["type:server"], "pkg:n1") in on_path
    assert (ids["type:server"], "@more:package:npm") not in on_path


def test_only_the_highest_risk_paths_mark_bundles() -> None:
    from agent_bom.graph.cluster_index import TOP_PATHS_FOR_BUNDLES

    graph = estate()
    graph.attack_paths[0].composite_risk = 90.0
    for i in range(TOP_PATHS_FOR_BUNDLES):
        graph.attack_paths.append(
            AttackPath(source="agent:a", target="pkg:n1", hops=["agent:a", "server:s1", "pkg:n1"], edges=[], composite_risk=80.0 - i)
        )
    graph.attack_paths.append(
        AttackPath(source="server:s1", target="cred:key", hops=["server:s1", "cred:key"], edges=[], composite_risk=1.0)
    )
    view = cluster_map_view(ClusterIndex.from_graph(graph))
    ids = {node["cluster_key"]: node["id"] for node in view["nodes"] if node["kind"] == "cluster"}
    flags = {(edge["source"], edge["target"]): edge["on_attack_path"] for edge in view["edges"]}
    assert flags[(ids["type:server"], ids["type:credential"])] is False
    assert flags[(ids["type:agent"], ids["type:server"])] is True
    # Membership of nodes still counts every stored path.
    assert next(node for node in view["nodes"] if node.get("cluster_key") == "type:credential")["on_attack_path_count"] == 1
