"""A Snowflake → AWS bucket attack path exists only when every recorded key matches.

The storage-integration correlator joins an integration to an AWS role and an
S3 bucket on the role ARN, the role's trust principal and its external id. The
served attack-path set must carry that chain, from the Snowflake objects that
depend on the integration to the bucket, and must carry nothing when any one of
those recorded keys is missing or different, or when the cross-vendor edge was
not produced by the correlator.
"""

from __future__ import annotations

import pytest

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.path_derivation import _derived_attack_paths
from agent_bom.graph.storage_integration_correlation import correlate_storage_integrations
from agent_bom.graph.types import EntityType, RelationshipType

_ROLE_ARN = "arn:aws:iam::111122223333:role/snowflake-s3-reader"
_USER_ARN = "arn:aws:iam::999988887777:user/abc1-s-ssca"
_EXTERNAL_ID = "EXT_123"
INTEGRATION = "cloud_resource:snowflake:integration:S3_INT"
STAGE = "cloud_resource:snowflake:stage:RAW_STAGE"
TABLE = "cloud_resource:snowflake:table:CLAIMS_EXT"
ROLE = "role:aws:reader"
BUCKET = "cloud_resource:aws:s3:bucket:claims-exports"


def _graph(
    *,
    integration_user: str | None = _USER_ARN,
    integration_external_id: str | None = _EXTERNAL_ID,
    integration_role_arn: str = _ROLE_ARN,
    trust_principals: tuple[str, ...] = (_USER_ARN,),
    trust_external_ids: tuple[str, ...] = (_EXTERNAL_ID,),
    dependents: bool = True,
) -> UnifiedGraph:
    graph = UnifiedGraph(scan_id="xv", tenant_id="t")
    integration_attrs: dict[str, object] = {
        "cloud_provider": "snowflake",
        "storage_aws_role_arn": integration_role_arn,
        "storage_allowed_locations": ["s3://claims-exports/raw/"],
    }
    if integration_user is not None:
        integration_attrs["storage_aws_iam_user_arn"] = integration_user
    if integration_external_id is not None:
        integration_attrs["storage_aws_external_id"] = integration_external_id
    graph.add_node(UnifiedNode(id=INTEGRATION, entity_type=EntityType.CLOUD_RESOURCE, label="S3_INT", attributes=integration_attrs))
    for node_id, label in ((STAGE, "RAW_STAGE"), (TABLE, "CLAIMS_EXT")):
        graph.add_node(
            UnifiedNode(id=node_id, entity_type=EntityType.CLOUD_RESOURCE, label=label, attributes={"cloud_provider": "snowflake"})
        )
    graph.add_node(
        UnifiedNode(
            id=ROLE,
            entity_type=EntityType.ROLE,
            label="snowflake-s3-reader",
            attributes={
                "cloud_provider": "aws",
                "arn": _ROLE_ARN,
                "trust_principals": list(trust_principals),
                "trust_external_ids": list(trust_external_ids),
            },
        )
    )
    graph.add_node(
        UnifiedNode(
            id=BUCKET,
            entity_type=EntityType.CLOUD_RESOURCE,
            label="claims-exports",
            attributes={"cloud_provider": "aws", "resource_id": "arn:aws:s3:::claims-exports"},
        )
    )
    if dependents:
        graph.add_edge(UnifiedEdge(source=TABLE, target=STAGE, relationship=RelationshipType.DEPENDS_ON))
        graph.add_edge(UnifiedEdge(source=STAGE, target=INTEGRATION, relationship=RelationshipType.DEPENDS_ON))
    correlate_storage_integrations(graph)
    return graph


def _cross_vendor(graph: UnifiedGraph) -> list:
    return [path for path in _derived_attack_paths(graph) if path.target == BUCKET]


def test_all_recorded_keys_matching_put_the_snowflake_to_bucket_chain_in_attack_paths() -> None:
    paths = _cross_vendor(_graph())

    assert len(paths) == 1
    path = paths[0]
    assert path.source == TABLE
    assert path.hops == [TABLE, STAGE, INTEGRATION, BUCKET]
    assert path.edges == ["depends_on", "depends_on", "can_access"]
    # Configured access is modeled evidence: hop receipts may qualify it, nothing confirms it.
    assert path.reachability in {"likely", "unknown"}
    assert "recorded_identifier_match" in path.reachability_basis
    assert "snowflake-s3-reader" in path.summary
    assert "external id" in path.summary


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({"integration_role_arn": "arn:aws:iam::111122223333:role/snowflake-s3-reader-v2"}, id="role-arn-differs"),
        pytest.param({"integration_user": None}, id="trust-principal-unrecorded"),
        pytest.param({"trust_principals": ("arn:aws:iam::999988887777:user/someone-else",)}, id="trust-principal-differs"),
        pytest.param({"trust_external_ids": ("OTHER",)}, id="external-id-differs"),
        pytest.param({"trust_external_ids": ()}, id="external-id-missing-from-trust"),
        # The correlator still draws traversal edges without a recorded external id;
        # an attack path claims all three keys, so it needs that third match.
        pytest.param({"integration_external_id": None, "trust_external_ids": ()}, id="external-id-unrecorded"),
    ],
)
def test_any_missing_or_different_recorded_key_yields_no_cross_vendor_path(overrides) -> None:
    assert _cross_vendor(_graph(**overrides)) == []


def test_a_cross_vendor_edge_the_correlator_did_not_draw_yields_no_path() -> None:
    graph = _graph(trust_principals=())
    graph.add_edge(UnifiedEdge(source=INTEGRATION, target=ROLE, relationship=RelationshipType.ASSUMES))
    graph.add_edge(
        UnifiedEdge(
            source=INTEGRATION,
            target=BUCKET,
            relationship=RelationshipType.CAN_ACCESS,
            evidence={"source": "hand-drawn", "via_role": ROLE},
        )
    )
    assert _cross_vendor(graph) == []


def test_an_integration_nothing_depends_on_is_its_own_path_source() -> None:
    paths = _cross_vendor(_graph(dependents=False))
    assert [(path.hops, path.edges) for path in paths] == [([INTEGRATION, BUCKET], ["can_access"])]
