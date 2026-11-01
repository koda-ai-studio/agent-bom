"""Snowflake storage integrations join AWS roles and buckets on recorded identifiers only.

``DESC INTEGRATION`` records ``STORAGE_AWS_ROLE_ARN``, ``STORAGE_AWS_IAM_USER_ARN``,
``STORAGE_AWS_EXTERNAL_ID`` and ``STORAGE_ALLOWED_LOCATIONS``; IAM records the
role ARN and its trust policy (principal and ``sts:ExternalId``); S3 records the
bucket ARN. The integration assumes the role only when the ARN matches AND the
role's trust names the integration's IAM user (and external id, when recorded);
it can access a bucket only through such a role, and only for an allowed
location naming that bucket's ARN. Nothing is matched by name.
"""

from __future__ import annotations

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.storage_integration_correlation import correlate_storage_integrations
from agent_bom.graph.types import EntityType, RelationshipType

_ROLE_ARN = "arn:aws:iam::111122223333:role/snowflake-s3-reader"
_USER_ARN = "arn:aws:iam::999988887777:user/abc1-s-ssca"


def _graph(
    *, trust_principals=(_USER_ARN,), trust_external_ids=("EXT_123",), role_arn=_ROLE_ARN, locations=("s3://claims-exports/raw/",)
) -> UnifiedGraph:
    graph = UnifiedGraph(scan_id="sic", tenant_id="t")
    graph.add_node(
        UnifiedNode(
            id="cloud_resource:snowflake:integration:S3_INT",
            entity_type=EntityType.CLOUD_RESOURCE,
            label="S3_INT",
            attributes={
                "cloud_provider": "snowflake",
                "storage_aws_role_arn": _ROLE_ARN,
                "storage_aws_iam_user_arn": _USER_ARN,
                "storage_aws_external_id": "EXT_123",
                "storage_allowed_locations": list(locations),
            },
        )
    )
    graph.add_node(
        UnifiedNode(
            id="role:aws:reader",
            entity_type=EntityType.ROLE,
            label="snowflake-s3-reader",
            attributes={
                "cloud_provider": "aws",
                "arn": role_arn,
                "trust_principals": list(trust_principals),
                "trust_external_ids": list(trust_external_ids),
            },
        )
    )
    graph.add_node(
        UnifiedNode(
            id="cloud_resource:aws:s3:bucket:claims-exports",
            entity_type=EntityType.CLOUD_RESOURCE,
            label="claims-exports",
            attributes={"cloud_provider": "aws", "resource_id": "arn:aws:s3:::claims-exports"},
        )
    )
    # Same name, different recorded ARN: must never be joined.
    graph.add_node(
        UnifiedNode(
            id="cloud_resource:aws:s3:bucket:claims-exports-copy",
            entity_type=EntityType.CLOUD_RESOURCE,
            label="claims-exports",
            attributes={"cloud_provider": "aws", "resource_id": "arn:aws:s3:::claims-exports-archive"},
        )
    )
    return graph


def _edges(graph: UnifiedGraph) -> dict[tuple[str, str, RelationshipType], object]:
    return {(e.source, e.target, e.relationship): e for e in graph.edges}


def test_recorded_arn_and_trust_join_integration_role_and_bucket() -> None:
    graph = _graph()
    assert correlate_storage_integrations(graph) == 2
    edges = _edges(graph)
    integration, bucket = "cloud_resource:snowflake:integration:S3_INT", "cloud_resource:aws:s3:bucket:claims-exports"
    assumes = edges[(integration, "role:aws:reader", RelationshipType.ASSUMES)]
    access = edges[(integration, bucket, RelationshipType.CAN_ACCESS)]
    assert assumes.evidence["derived_via"] == "recorded_identifier_match"
    assert set(assumes.evidence["basis"]) == {
        "storage_aws_role_arn_matches_role_arn",
        "role_trust_names_integration_user",
        "role_trust_names_external_id",
    }
    assert access.evidence["basis"] == ["storage_allowed_location_names_bucket_arn", "via_assumed_role"]
    assert access.evidence["via_role"] == "role:aws:reader"
    assert (integration, f"{bucket}-copy", RelationshipType.CAN_ACCESS) not in edges


def test_no_join_without_the_trust_principal() -> None:
    graph = _graph(trust_principals=("arn:aws:iam::999988887777:user/someone-else",))
    assert correlate_storage_integrations(graph) == 0


def test_no_join_on_external_id_mismatch() -> None:
    graph = _graph(trust_external_ids=("OTHER",))
    assert correlate_storage_integrations(graph) == 0


def test_no_join_on_a_different_role_arn_even_with_the_same_name() -> None:
    graph = _graph(role_arn="arn:aws:iam::111122223333:role/snowflake-s3-reader-v2")
    assert correlate_storage_integrations(graph) == 0


def test_unrecorded_bucket_gets_no_edge_and_rerun_is_idempotent() -> None:
    graph = _graph(locations=("s3://not-inventoried/",))
    assert correlate_storage_integrations(graph) == 1
    assert correlate_storage_integrations(graph) == 1
    assert sum(e.relationship is RelationshipType.ASSUMES for e in graph.edges) == 1


def test_the_graph_builder_runs_the_correlation() -> None:
    from agent_bom.graph.build_analysis import _identity_analysis

    graph = _graph()
    _identity_analysis(graph, {})
    sources = {e.evidence.get("source") for e in graph.edges if e.relationship is RelationshipType.ASSUMES}
    assert sources == {"storage-integration-correlation"}


def test_an_identifier_two_nodes_claim_joins_nothing() -> None:
    graph = _graph()
    graph.add_node(
        UnifiedNode(
            id="cloud_resource:aws:s3:bucket:claims-exports-dup",
            entity_type=EntityType.CLOUD_RESOURCE,
            label="dup",
            attributes={"cloud_provider": "aws", "arn": "arn:aws:s3:::claims-exports"},
        )
    )
    assert correlate_storage_integrations(graph) == 1
    assert not [e for e in graph.edges if e.relationship is RelationshipType.CAN_ACCESS]


def _correlation_peak_bytes(node_count: int, *, materialize: bool = False) -> int:
    import tracemalloc

    from agent_bom.graph.store_backed import open_store_backed_unified_graph

    with open_store_backed_unified_graph(scan_id="stream", tenant_id="t", backend="sqlite", capacity=128, page_size=64) as graph:
        for index in range(node_count):
            graph.add_node(
                UnifiedNode(
                    id=f"cloud_resource:filler:{index}",
                    entity_type=EntityType.CLOUD_RESOURCE,
                    label=f"filler-{index}",
                    attributes={"region": "us-east-1", "notes": "x" * 200},
                )
            )
        graph.flush()
        tracemalloc.start()
        try:
            if materialize:
                retained = list(graph.nodes.values())
                assert len(retained) == node_count
            else:
                correlate_storage_integrations(graph)
            return tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()


def test_correlation_streams_a_store_backed_graph_instead_of_loading_every_node() -> None:
    """Measure only this collector, not allocations from other tests' background threads."""
    import json
    import subprocess
    import sys
    from pathlib import Path

    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import json, runpy, sys; "
            + "measure = runpy.run_path(sys.argv[1])['_correlation_peak_bytes']; "
            + "print(json.dumps([[measure(n, materialize=m) for n in (500, 4000)] for m in (False, True)]))",
            str(Path(__file__).resolve()),
        ],
        capture_output=True,
        text=True,
        check=True,
        timeout=120,
    )
    streaming, materialized = json.loads(result.stdout)
    # Preserve the same 8x input and 2x bound. The negative control proves this
    # measurement still rejects retaining every node rather than streaming pages.
    assert streaming[1] < streaming[0] * 2, streaming
    assert materialized[1] > materialized[0] * 2, materialized
