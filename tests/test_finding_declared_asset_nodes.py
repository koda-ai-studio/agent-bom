"""A finding row that declares its asset's graph node lands on that node, in every projection."""

from __future__ import annotations

from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.types import EntityType, RelationshipType

_ROLE = "aws:iam_role:111111111111:claims-etl"
_BUCKET = "aws:bucket:111111111111:claims-archive"
_ARN = "arn:aws:ec2:us-east-1:111122223333:instance/i-0de00000000000000"
_MERGED = "cloud_resource:aws:aws_instance:111122223333/us-east-1/i-0de00000000000000"


_BUCKET_CHECK = {
    "provider": "aws",
    "checks": [{"check_id": "2.1.1", "title": "bucket encryption", "status": "fail", "severity": "high", "resource_ids": [_BUCKET]}],
}


def _row(identifier: str, *, node_id: str | None, entity_type: str | None, finding_id: str, source: str = "CLOUD_CIS") -> dict:
    row = {
        "id": finding_id,
        "finding_type": "CIS_FAIL",
        "source": source,
        "severity": "high",
        "title": f"check on {identifier}",
        "asset": {"name": identifier.rsplit(":", 1)[-1], "asset_type": "cloud_resource", "identifier": identifier, "provider": "aws"},
    }
    if node_id is not None:
        row["node_id"] = node_id
    if entity_type is not None:
        row["entity_type"] = entity_type
    return row


def _affected(graph, finding_node_id: str) -> set[str]:
    return {edge.target for edge in graph.edges_from(finding_node_id) if edge.relationship == RelationshipType.AFFECTS} | {
        edge.source for edge in graph.edges_to(finding_node_id) if edge.relationship == RelationshipType.VULNERABLE_TO
    }


def _finding_node(graph, finding_id: str) -> str:
    (node_id,) = [node.id for node in graph.nodes.values() if node.attributes.get("finding_id") == finding_id]
    return node_id


def test_row_declaring_its_asset_node_mints_that_id_and_type():
    graph = build_unified_graph_from_report(
        {"findings": [_row(_ROLE, node_id=_ROLE, entity_type="role", finding_id="f-role", source="IAC_SCAN")]}
    )
    assert graph.nodes[_ROLE].entity_type == EntityType.ROLE
    assert f"cloud_resource:aws:{_ROLE}" not in graph.nodes
    assert _affected(graph, _finding_node(graph, "f-role")) == {_ROLE}


def test_row_declaring_a_canonical_cloud_id_keeps_the_arn_as_native_key():
    graph = build_unified_graph_from_report(
        {"findings": [_row(_ARN, node_id=_MERGED, entity_type="cloud_resource", finding_id="f-imds", source="CLOUD_SECURITY")]}
    )
    node = graph.nodes[_MERGED]
    assert node.entity_type == EntityType.CLOUD_RESOURCE
    assert node.attributes["resource_id"] == _ARN
    assert f"cloud_resource:aws:{_ARN}" not in graph.nodes


def test_benchmark_resource_a_row_declares_lands_on_the_declared_node():
    report = {
        "findings": [_row(_BUCKET, node_id=_BUCKET, entity_type="data_store", finding_id="f-bucket")],
        "cis_benchmark": _BUCKET_CHECK,
    }
    graph = build_unified_graph_from_report(report)
    assert graph.nodes[_BUCKET].entity_type == EntityType.DATA_STORE
    assert not [node_id for node_id in graph.nodes if node_id.endswith(_BUCKET) and node_id != _BUCKET]
    misconfigs = [node.id for node in graph.nodes.values() if node.entity_type == EntityType.MISCONFIGURATION]
    assert misconfigs
    assert all(_affected(graph, node_id) <= {_BUCKET} for node_id in misconfigs)
    assert {_BUCKET} == set().union(*(_affected(graph, node_id) for node_id in misconfigs))


def test_row_without_a_declared_node_keeps_the_derived_stub():
    graph = build_unified_graph_from_report({"findings": [_row(_ROLE, node_id=None, entity_type=None, finding_id="f-plain")]})
    assert graph.nodes[f"cloud_resource:aws:{_ROLE}"].entity_type == EntityType.CLOUD_RESOURCE
    assert _ROLE not in graph.nodes


def test_declared_node_of_another_kind_is_not_minted_from_a_cloud_row():
    # A blast-radius style declaration (package node, no matching identifier) never renames a cloud asset.
    row = _row(_ROLE, node_id="pkg:pypi:langchain@0.0.150", entity_type="role", finding_id="f-pkg")
    graph = build_unified_graph_from_report({"findings": [row]})
    assert "pkg:pypi:langchain@0.0.150" not in graph.nodes
    assert f"cloud_resource:aws:{_ROLE}" in graph.nodes


def test_conflicting_declarations_for_one_benchmark_resource_fall_back():
    report = {
        "findings": [
            _row(_BUCKET, node_id=_BUCKET, entity_type="data_store", finding_id="f-a"),
            _row(_BUCKET, node_id=f"cloud_resource:aws:s3:bucket:{_BUCKET}", entity_type="cloud_resource", finding_id="f-b"),
        ],
        "cis_benchmark": _BUCKET_CHECK,
    }
    graph = build_unified_graph_from_report(report)
    assert f"cloud_resource:aws:{_BUCKET}" in graph.nodes
