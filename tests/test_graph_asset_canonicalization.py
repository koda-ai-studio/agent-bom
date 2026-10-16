"""One node per real-world asset across inventory, audit, workload and finding sources."""

from __future__ import annotations

import os

import pytest

from agent_bom.graph.asset_canonicalize import canonicalize_assets
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.correlation import CorrelationSnapshot, merge_graph_snapshots
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.store_backed import open_store_backed_unified_graph
from agent_bom.graph.types import EntityType, RelationshipType

ACCOUNT = "210987654321"
OTHER_ACCOUNT = "123450000999"
REGION = "us-east-1"
INSTANCE = "i-0a1b2c3d4e5f60718"
ARN = f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/{INSTANCE}"
CANONICAL = f"cloud_resource:aws:aws_instance:{ACCOUNT}/{REGION}/{INSTANCE}"
HOST = "ip-10-0-1-15.ec2.internal"


def _vm_report(*, hostname: str = HOST) -> dict:
    """One EC2 instance reported by inventory, CloudTrail, a side scan and a posture finding."""
    return {
        "scan_id": "vm-five-sources",
        "cloud_inventory": {
            "status": "ok",
            "provider": "aws",
            "account_id": ACCOUNT,
            "region": REGION,
            "instances": [
                {
                    "instance_id": INSTANCE,
                    "name": "billing-api",
                    "region": REGION,
                    "private_ip": "10.0.1.15",
                    "vpc_id": "vpc-0demo",
                    "private_dns_name": hostname,
                }
            ],
            "side_scan_targets": [
                {"target_id": INSTANCE, "target_type": "instance", "account_id": ACCOUNT, "location": REGION, "provider": "aws"}
            ],
        },
        "cloud_audit_trail": {
            "status": "ok",
            "provider": "aws",
            "account": ACCOUNT,
            "behavioral_edges": [
                {
                    "principal": "deploy-bot",
                    "principal_arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/deploy-role/session-1",
                    "resource": ARN,
                    "action": "StopInstances",
                    "relationship": "invoked",
                    "count": 2,
                    "last_seen": "2026-10-01T00:00:00Z",
                }
            ],
        },
        "findings": [
            {
                "id": "sechub-1",
                "finding_type": "CLOUD_MISCONFIGURATION",
                "source": "CLOUD_SECURITY",
                "severity": "high",
                "title": "Instance metadata v1 enabled",
                "asset": {"name": "billing-api", "asset_type": "cloud_resource", "identifier": ARN, "provider": "aws"},
            }
        ],
    }


def _nodes(graph: UnifiedGraph, entity_type: EntityType) -> list[UnifiedNode]:
    return list(graph.nodes_by_type(entity_type))


def _resource(node_id: str, *, data_source: str, **attributes: object) -> UnifiedNode:
    return UnifiedNode(
        id=node_id,
        entity_type=EntityType.CLOUD_RESOURCE,
        label=node_id,
        attributes={"cloud_provider": "aws", **attributes},
        data_sources=[data_source],
        dimensions=NodeDimensions(cloud_provider="aws"),
    )


def test_one_vm_in_every_source_is_one_node_with_every_observation() -> None:
    graph = build_unified_graph_from_report(_vm_report())

    vm = graph.nodes.get(CANONICAL)
    assert vm is not None
    identity = vm.attributes["identity"]
    assert identity["basis"] == "aws_instance"
    assert {item["key_basis"] for item in identity["observations"]} >= {"aws_instance"}
    assert len(identity["aliases"]) == 3
    assert not [alias for alias in identity["aliases"] if alias in graph.nodes]
    # Inventory, CloudTrail and the side scan each minted a node; the posture
    # finding named the inventory node directly and is recorded as a source.
    assert {"cloud-inventory:aws", "cloud-audit-trail", "cwpp-side-scan", "cloud-security"} <= set(vm.data_sources)
    assert len({record["node_id"] for record in identity["observations"]}) == 3
    assert {record["native_id"] for record in identity["observations"]} == {INSTANCE, ARN}
    instance_like = [node for node in _nodes(graph, EntityType.CLOUD_RESOURCE) if INSTANCE in node.id or INSTANCE in str(node.attributes)]
    assert [node.id for node in instance_like] == [CANONICAL]
    # Edges from every source now meet on the canonical node.
    relationships = {edge.relationship for edge in graph.edges_to(CANONICAL)} | {edge.relationship for edge in graph.edges_from(CANONICAL)}
    assert RelationshipType.INVOKED in relationships


def test_cloudtrail_assumed_role_principal_is_a_role() -> None:
    graph = build_unified_graph_from_report(_vm_report())

    roles = [node for node in _nodes(graph, EntityType.ROLE) if node.attributes.get("arn") == f"arn:aws:iam::{ACCOUNT}:role/deploy-role"]
    assert len(roles) == 1
    assert not [node for node in _nodes(graph, EntityType.USER) if "deploy" in node.id]


def test_inventory_vm_and_hostname_only_sensor_are_two_nodes_and_one_candidate() -> None:
    graph = UnifiedGraph()
    graph.add_node(_resource("vm", data_source="inventory", resource_id=INSTANCE, account_id=ACCOUNT, location=REGION, hostname=HOST))
    graph.add_node(_resource("sensor", data_source="sensor", hostname=HOST.upper() + "."))

    canonicalize_assets(graph)

    assert set(graph.nodes) == {"vm", "sensor"}
    candidates = [edge for edge in graph.edges if edge.relationship == RelationshipType.POSSIBLY_CORRELATES_WITH]
    assert len(candidates) == 1
    assert candidates[0].evidence["matched_signals"] == ["hostname"]
    assert candidates[0].traversable is False


def test_two_inventory_vms_with_one_hostname_are_two_nodes_and_no_candidate() -> None:
    graph = UnifiedGraph()
    graph.add_node(_resource("vm-a", data_source="inventory", resource_id=INSTANCE, account_id=ACCOUNT, location=REGION, hostname=HOST))
    graph.add_node(
        _resource("vm-b", data_source="inventory", resource_id="i-0ffffffffffffffff", account_id=ACCOUNT, location=REGION, hostname=HOST)
    )

    canonicalize_assets(graph)

    assert set(graph.nodes) == {"vm-a", "vm-b"}
    assert not [edge for edge in graph.edges if edge.relationship == RelationshipType.POSSIBLY_CORRELATES_WITH]


def test_azure_arm_ids_merge_case_insensitively() -> None:
    arm = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/RG/providers/Microsoft.Compute/virtualMachines/vm1"
    graph = UnifiedGraph()
    for node_id, value in (("inventory", arm), ("activity", arm.lower())):
        graph.add_node(
            UnifiedNode(
                id=node_id,
                entity_type=EntityType.CLOUD_RESOURCE,
                label=node_id,
                attributes={"cloud_provider": "azure", "resource_id": value},
                data_sources=[node_id],
            )
        )

    mapping = canonicalize_assets(graph)

    assert len(graph.nodes) == 1
    assert set(mapping) == {"inventory", "activity"}
    assert next(iter(graph.nodes)) == f"cloud_resource:azure:azure_arm:{arm.lower()}"


def test_same_name_in_two_accounts_never_merges() -> None:
    graph = UnifiedGraph()
    graph.add_node(_resource("a", data_source="inventory", resource_id=INSTANCE, account_id=ACCOUNT, location=REGION))
    graph.add_node(_resource("b", data_source="inventory", resource_id=INSTANCE, account_id=OTHER_ACCOUNT, location=REGION))
    graph.add_node(_resource("c", data_source="inventory", resource_name="logs", resource_type="bucket", account_id=ACCOUNT))
    graph.add_node(_resource("d", data_source="inventory", resource_name="logs", resource_type="bucket", account_id=OTHER_ACCOUNT))

    assert canonicalize_assets(graph) == {}
    assert set(graph.nodes) == {"a", "b", "c", "d"}


def test_snowflake_accounts_differing_only_in_case_never_merge() -> None:
    graph = UnifiedGraph()
    for node_id, account in (("upper", "ACCT1"), ("lower", "acct1")):
        graph.add_node(
            UnifiedNode(
                id=node_id,
                entity_type=EntityType.ROLE,
                label="ANALYST",
                attributes={"cloud_provider": "snowflake", "account_id": account, "snowflake_local_id": "role:snowflake:ANALYST"},
                data_sources=["snowflake"],
                dimensions=NodeDimensions(cloud_provider="snowflake"),
            )
        )

    assert canonicalize_assets(graph) == {}
    assert {graph.nodes[node_id].attributes["account_id"] for node_id in graph.nodes} == {"ACCT1", "acct1"}


def test_conflicting_strong_keys_do_not_merge() -> None:
    graph = UnifiedGraph()
    graph.add_node(_resource("a", data_source="x", resource_arn=ARN, resource_id=INSTANCE, account_id=ACCOUNT, location=REGION))
    graph.add_node(
        _resource("b", data_source="y", resource_arn=ARN, resource_id="i-0ffffffffffffffff", account_id=ACCOUNT, location=REGION)
    )

    canonicalize_assets(graph)

    assert graph.analysis_status["asset_canonicalization"].reason_codes == ("conflicting_strong_keys",)


def _edges(graph: UnifiedGraph) -> set[tuple[str, str, str]]:
    return {(edge.source, edge.target, edge.relationship.value) for edge in graph.edges}


def _rekey_fixture(graph: UnifiedGraph) -> None:
    for node_id in ("a", "b", "c", "x"):
        graph.add_node(UnifiedNode(id=node_id, entity_type=EntityType.CLOUD_RESOURCE, label=node_id, data_sources=[node_id]))
    graph.add_node(UnifiedNode(id="cve", entity_type=EntityType.VULNERABILITY, label="CVE", data_sources=["scan"]))
    for source, target, rel, evidence in (
        ("a", "cve", RelationshipType.VULNERABLE_TO, {"source": "s1", "tier": "static_scan"}),
        ("b", "cve", RelationshipType.VULNERABLE_TO, {"source": "s2", "tier": "static_scan", "detail": "b"}),
        ("a", "b", RelationshipType.DEPENDS_ON, {"source": "s", "tier": "static_scan"}),
        ("x", "c", RelationshipType.DEPENDS_ON, {"source": "s", "tier": "static_scan"}),
        ("a", "x", RelationshipType.LATERAL_PATH, {"source": "s", "tier": "derived", "derived_via": "t"}),
    ):
        graph.add_stored_edge(
            UnifiedEdge(
                source=source,
                target=target,
                relationship=rel,
                evidence=evidence,
                direction="bidirectional" if rel == RelationshipType.LATERAL_PATH else "directed",
            )
        )


@pytest.mark.parametrize("backend", ["memory", "sqlite", "postgres"])
def test_rekey_repoints_edges_merges_duplicates_and_keeps_reverse_adjacency(backend: str) -> None:
    if backend == "postgres" and not os.environ.get("AGENT_BOM_POSTGRES_URL"):
        pytest.skip("AGENT_BOM_POSTGRES_URL not set")
    store_backed = backend != "memory"
    graph: UnifiedGraph = (
        open_store_backed_unified_graph(backend=backend, tenant_id="rekey-tenant", capacity=2, page_size=2)
        if store_backed
        else UnifiedGraph()
    )
    try:
        _rekey_fixture(graph)

        dropped = graph.rekey_nodes({"a": "m", "b": "m", "c": "n"})

        assert dropped == 1
        assert set(graph.nodes) == {"m", "n", "x", "cve"}
        assert set(graph.nodes["m"].data_sources) == {"a", "b"}
        assert _edges(graph) == {("m", "cve", "vulnerable_to"), ("x", "n", "depends_on"), ("m", "x", "lateral_path")}
        merged = next(edge for edge in graph.edges if edge.source == "m" and edge.target == "cve")
        assert merged.evidence["source"] in {"s1", "s2"} and merged.evidence["detail"] == "b"
        assert {edge.source for edge in graph.reverse_adjacency.get("cve", [])} == {"m"}
        assert {edge.target for edge in graph.adjacency.get("x", [])} == {"n", "m"}
        assert graph.adjacency.get("a", []) == [] and graph.reverse_adjacency.get("b", []) == []
        assert len(graph.edges) == 3
    finally:
        if store_backed:
            graph.close()  # type: ignore[attr-defined]


def test_store_backed_build_matches_in_memory_build() -> None:
    report = _vm_report()
    memory = build_unified_graph_from_report(report)
    with open_store_backed_unified_graph(backend="sqlite", capacity=8, page_size=3) as stored:
        build_unified_graph_from_report(report, container=stored)
        assert set(stored.nodes) == set(memory.nodes)
        assert _edges(stored) == _edges(memory)
        assert stored.nodes[CANONICAL].attributes["identity"] == memory.nodes[CANONICAL].attributes["identity"]


def test_build_time_and_snapshot_merge_agree_on_one_vm() -> None:
    inventory = build_unified_graph_from_report({**_vm_report(), "cloud_audit_trail": None, "findings": []}, scan_id="inv", tenant_id="t")
    audit_report = _vm_report()
    audit_report["cloud_inventory"] = {"status": "ok", "provider": "aws", "account_id": ACCOUNT, "region": REGION, "instances": []}
    audit = build_unified_graph_from_report(audit_report, scan_id="audit", tenant_id="t")
    audit.created_at = "2026-10-02T00:00:00+00:00"
    inventory.created_at = "2026-10-01T00:00:00+00:00"

    merged = merge_graph_snapshots(
        correlation_id="corr",
        tenant_id="t",
        snapshots=[CorrelationSnapshot.from_graph(inventory), CorrelationSnapshot.from_graph(audit)],
    ).graph
    together = build_unified_graph_from_report(_vm_report(), tenant_id="t")

    merged_vms = [node.id for node in merged.nodes.values() if INSTANCE in node.id or INSTANCE in str(node.attributes.get("resource_id"))]
    built_vms = [node.id for node in together.nodes.values() if INSTANCE in node.id or INSTANCE in str(node.attributes.get("resource_id"))]
    assert merged_vms == built_vms == [CANONICAL]


def test_cloudtrail_reader_keeps_the_recorded_caller_identity_only() -> None:
    import json

    from agent_bom.cloud.audit_trail import AuditEvent, aggregate_events
    from agent_bom.cloud.audit_trail_aws import aws_event_fields

    raw = {
        "EventName": "StopInstances",
        "Username": "session-1",
        "Resources": [{"ResourceName": ARN}],
        "CloudTrailEvent": json.dumps(
            {
                "userIdentity": {"type": "AssumedRole", "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/deploy-role/session-1"},
                "awsRegion": REGION,
                "requestParameters": {"instancesSet": {"items": [{"instanceId": INSTANCE}]}},
            }
        ),
    }

    fields = aws_event_fields(raw)
    record = aggregate_events([AuditEvent(**fields)])[0]

    assert record["principal_arn"] == f"arn:aws:sts::{ACCOUNT}:assumed-role/deploy-role/session-1"
    assert record["principal_type"] == "AssumedRole" and record["region"] == REGION
    assert "requestParameters" not in json.dumps(record)


def _conflicting_exposure_graph(graph: UnifiedGraph) -> UnifiedGraph:
    graph.add_node(_resource("a-security", data_source="security", arn=ARN, internet_exposed=True, owner="security"))
    graph.add_node(
        _resource("z-inventory", data_source="inventory", arn=ARN, internet_exposed=False, owner="platform", description="richer inventory")
    )
    return graph


def _assert_risky_value_kept(node: UnifiedNode, status: dict) -> None:
    from agent_bom.graph.rollup import _is_exposed

    assert node.attributes["internet_exposed"] is True
    assert _is_exposed(node)
    competing = node.attributes["identity"]["conflicts"]["internet_exposed"]
    assert {(record["value"], record["source"]) for record in competing} == {(True, "security"), (False, "inventory")}
    assert "owner" not in node.attributes["identity"]["conflicts"]  # non-security fields keep precedence, no receipt bloat
    assert set(node.attributes["identity"]["conflict_fields"]) >= {"internet_exposed", "owner"}
    assert node.attributes["owner"] == "platform"
    # Competing security assertions limit the analysis; descriptive differences are reported, not counted.
    assert status["observed"]["conflicts"] == 1
    assert status["observed"]["security_assertion_conflicts"] == 1
    assert status["observed"]["attribute_conflicts"] == 2
    assert "conflicting_security_assertions" in status["reason_codes"]


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_conflicting_exposure_keeps_the_risky_assertion_and_counts_it(backend: str) -> None:
    graph: UnifiedGraph = (
        UnifiedGraph(scan_id="conflict", tenant_id="t")
        if backend == "memory"
        else open_store_backed_unified_graph(backend=backend, tenant_id="t", capacity=2, page_size=2)
    )
    try:
        canonicalize_assets(_conflicting_exposure_graph(graph))
        assert len(graph.nodes) == 1
        node = next(iter(graph.nodes.values()))
        _assert_risky_value_kept(node, graph.analysis_status["asset_canonicalization"].to_dict())
    finally:
        if backend != "memory":
            graph.close()  # type: ignore[attr-defined]


def test_second_canonicalization_pass_keeps_the_recorded_conflict() -> None:
    graph = _conflicting_exposure_graph(UnifiedGraph(scan_id="conflict", tenant_id="t"))
    canonicalize_assets(graph)
    graph.add_node(_resource("finding-row", data_source="findings", arn=ARN))
    canonicalize_assets(graph)
    node = next(iter(graph.nodes.values()))
    assert node.attributes["internet_exposed"] is True
    assert {record["source"] for record in node.attributes["identity"]["conflicts"]["internet_exposed"]} == {"security", "inventory"}


def test_snapshot_correlation_keeps_the_risky_assertion() -> None:
    from agent_bom.graph.rollup import _is_exposed

    exposed = UnifiedGraph(scan_id="sec", tenant_id="t", created_at="2026-10-01T00:00:00+00:00")
    exposed.add_node(_resource(CANONICAL, data_source="security", arn=ARN, internet_exposed=True))
    later = UnifiedGraph(scan_id="inv", tenant_id="t", created_at="2026-10-02T00:00:00+00:00")
    later.add_node(_resource(CANONICAL, data_source="inventory", arn=ARN, internet_exposed=False))

    result = merge_graph_snapshots(
        correlation_id="corr", tenant_id="t", snapshots=[CorrelationSnapshot.from_graph(exposed), CorrelationSnapshot.from_graph(later)]
    )
    node = result.graph.nodes[CANONICAL]
    assert node.attributes["internet_exposed"] is True and _is_exposed(node)
    competing = node.attributes["correlation"]["conflicts"]["internet_exposed"]
    assert {(record["value"], record["source"]) for record in competing} == {(True, "sec"), (False, "inv")}


def test_repeated_merge_does_not_invent_claims_or_double_count_conflicts() -> None:
    graph = _conflicting_exposure_graph(UnifiedGraph(scan_id="source-scan", tenant_id="t"))
    canonicalize_assets(graph)
    node = next(iter(graph.nodes.values()))
    assertions = node.attributes["identity"]["conflicts"]
    for index in range(3):
        graph.add_node(_resource(f"finding-{index}", data_source="findings", arn=ARN))
        canonicalize_assets(graph)
        node = next(iter(graph.nodes.values()))
        assert node.attributes["identity"]["conflicts"] == assertions
        assert graph.analysis_status["asset_canonicalization"].observed["conflicts"] == 1
    records = assertions["internet_exposed"]
    assert {record["scan_id"] for record in records} == {"source-scan"}
    assert {record["node_id"] for record in records} == {"a-security", "z-inventory"}
    assert {record["source"] for record in records} == {"security", "inventory"}


@pytest.mark.parametrize("positive", [True, "true", "yes", 1])
def test_positive_security_flags_survive_unknown_or_negative_inventory(positive: object) -> None:
    graph = UnifiedGraph(scan_id="conflict", tenant_id="t")
    graph.add_node(_resource("security", data_source="posture", arn=ARN, internet_exposed=positive))
    graph.add_node(_resource("inventory", data_source="inventory", arn=ARN, internet_exposed=False, description="richer"))
    canonicalize_assets(graph)
    assert next(iter(graph.nodes.values())).attributes["internet_exposed"] is True


def test_security_assertion_receipts_survive_snapshot_recorrelation() -> None:
    graph = _conflicting_exposure_graph(UnifiedGraph(scan_id="original", tenant_id="t", created_at="2026-10-01T00:00:00+00:00"))
    canonicalize_assets(graph)
    receipts = next(iter(graph.nodes.values())).attributes["identity"]["conflicts"]
    later = UnifiedGraph(scan_id="later", tenant_id="t", created_at="2026-10-02T00:00:00+00:00")
    later.add_node(_resource(CANONICAL, data_source="inventory", arn=ARN))
    snapshots = [CorrelationSnapshot.from_graph(graph), CorrelationSnapshot.from_graph(later)]
    kwargs = {"correlation_id": "corr", "tenant_id": "t", "created_at": "2026-10-03T00:00:00+00:00"}
    result = merge_graph_snapshots(snapshots=snapshots, **kwargs)
    reverse = merge_graph_snapshots(snapshots=list(reversed(snapshots)), **kwargs)
    node = result.graph.nodes[CANONICAL]
    assert node.attributes["internet_exposed"] is True
    assert node.attributes["correlation"]["conflicts"] == receipts
    assert result.graph.to_dict() == reverse.graph.to_dict()


def test_recanonicalization_retains_legacy_strong_key_conflict_counts() -> None:
    from agent_bom.graph.analysis import GraphAnalysisState, GraphAnalysisStatus

    graph = UnifiedGraph(scan_id="legacy", tenant_id="t")
    graph.add_node(_resource("resource", data_source="inventory", arn=ARN))
    graph.analysis_status["asset_canonicalization"] = GraphAnalysisStatus(
        status=GraphAnalysisState.LIMITED, reason_codes=("conflicting_strong_keys",), observed={"conflicts": 2}
    )
    canonicalize_assets(graph)
    status = graph.analysis_status["asset_canonicalization"]
    assert status.observed["strong_key_conflicts"] == 2
    assert status.status is GraphAnalysisState.LIMITED
