"""Snowflake external stages over AWS S3: the estate's cross-vendor data lineage.

A Snowflake external stage reads an S3 location through a storage integration,
and the integration authenticates by assuming an AWS IAM role created for it,
whose trust policy names the Snowflake account. The generated estate recorded stages,
buckets and roles but never that wiring, so no path crossed a vendor.

:func:`record_external_stages` adds it as labelled synthetic recorded data
(``integration_source``). Per Snowflake account it inventories one storage
integration, points one stage at it and at its S3 location, and records one
table in the same account and environment as an external table over that stage.
:func:`project_external_stages` draws the record with existing relationship
types: the table and stage ``depends_on`` what they read, the integration
``assumes`` the IAM role, the role ``trusts`` the Snowflake account and
``can_access`` the bucket. The chain is one directed traversal from Snowflake
into AWS.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence

from agent_bom.demo_estate.enterprise import EstateAsset
from agent_bom.demo_estate.estate_edges import ESTATE_DATA_SOURCE, add_estate_edge
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.types import RelationshipType

INTEGRATION_SOURCE = "synthetic-demo-integration"
STORAGE_INTEGRATION_TYPE = "storage_integration"


def _pick(seed: str, candidates: Sequence[EstateAsset]) -> EstateAsset | None:
    if not candidates:
        return None
    ordered = sorted(candidates, key=lambda asset: asset.asset_id)
    return ordered[int.from_bytes(hashlib.sha256(seed.encode()).digest()[:4], "big") % len(ordered)]


def _with_tags(asset: EstateAsset, **tags: str) -> EstateAsset:
    return asset.model_copy(update={"tags": {**asset.tags, **tags}})


def _integration(stage: EstateAsset, bucket: EstateAsset, role: EstateAsset) -> EstateAsset:
    name = f"{stage.display_name}-s3-integration"
    return EstateAsset(
        asset_id=f"snowflake:{STORAGE_INTEGRATION_TYPE}:{stage.account_scope}:{name}",
        tenant_id=stage.tenant_id,
        provider="snowflake",
        resource_type=STORAGE_INTEGRATION_TYPE,
        native_id=f"snowflake://{stage.account_scope}/integration/{name}",
        display_name=name,
        environment=stage.environment,
        account_scope=stage.account_scope,
        region=stage.region,
        owner=stage.owner,
        cost_center=stage.cost_center,
        tags={
            "synthetic": "true",
            "environment": stage.environment,
            "storage_provider": "S3",
            "storage_aws_role_arn": f"arn:aws:iam::{role.account_scope}:role/{role.display_name}",
            "storage_allowed_locations": f"s3://{bucket.display_name}/",
            "integration_role": role.asset_id,
            "integration_location": bucket.asset_id,
            "integration_source": INTEGRATION_SOURCE,
        },
    )


def _integration_role(stage: EstateAsset, bucket: EstateAsset) -> EstateAsset:
    """The IAM role created for this integration, in the bucket's account and the stage's environment."""
    name = f"snowflake-{stage.account_scope.lower()}-s3-{stage.environment}"
    return EstateAsset(
        asset_id=f"aws:iam_role:{bucket.account_scope}:{name}",
        tenant_id=bucket.tenant_id,
        provider="aws",
        resource_type="iam_role",
        native_id=f"arn:aws:iam::{bucket.account_scope}:role/{name}",
        display_name=name,
        environment=stage.environment,
        account_scope=bucket.account_scope,
        region=bucket.region,
        owner=bucket.owner,
        cost_center=bucket.cost_center,
        tags={
            "synthetic": "true",
            "environment": stage.environment,
            "trusted_snowflake_account": stage.account_scope,
            "integration_source": INTEGRATION_SOURCE,
        },
    )


def record_external_stages(assets: Sequence[EstateAsset]) -> tuple[EstateAsset, ...]:
    """Return ``assets`` with one S3 storage integration, stage and external table per Snowflake account.

    Nothing is linked across environments: a stage whose environment holds no
    S3 bucket records why instead (``integration_unlinked_reason``).
    """
    buckets = [a for a in assets if a.provider == "aws" and a.resource_type == "bucket"]
    updates: dict[str, EstateAsset] = {}
    added: list[EstateAsset] = []
    for scope in sorted({a.account_scope for a in assets if a.provider == "snowflake" and a.resource_type == "stage"}):
        stage = min((a for a in assets if a.resource_type == "stage" and a.account_scope == scope), key=lambda a: a.asset_id)
        bucket = _pick(f"stage-bucket|{stage.asset_id}", [b for b in buckets if b.environment == stage.environment])
        if bucket is None:
            updates[stage.asset_id] = _with_tags(stage, integration_unlinked_reason="no_same_environment_s3_bucket")
            continue
        role = _integration_role(stage, bucket)
        integration = _integration(stage, bucket, role)
        added.extend((integration, role))
        updates[stage.asset_id] = _with_tags(
            stage,
            storage_integration=integration.asset_id,
            external_location=bucket.asset_id,
            integration_source=INTEGRATION_SOURCE,
        )
        tables = [a for a in assets if a.provider == "snowflake" and a.resource_type == "table" and a.account_scope == scope]
        reader = _pick(f"stage-reader|{stage.asset_id}", [t for t in tables if t.environment == stage.environment])
        if reader is not None:
            updates[reader.asset_id] = _with_tags(reader, external_stage=stage.asset_id, integration_source=INTEGRATION_SOURCE)
    return (*(updates.get(asset.asset_id, asset) for asset in assets), *added)


def project_external_stages(graph: UnifiedGraph, assets: Sequence[EstateAsset], account_node_id: dict[str, str]) -> int:
    """Draw recorded external-table, stage and storage-integration edges; returns edges drawn."""
    drawn = 0

    def edge(source: str, target: str, relationship: RelationshipType, reason: str) -> None:
        nonlocal drawn
        if source in graph.nodes and target in graph.nodes:
            add_estate_edge(graph, source, target, relationship, evidence={"reason": reason}, provenance={"source": ESTATE_DATA_SOURCE})
            drawn += 1

    for asset in assets:
        tags = asset.tags
        if tags.get("external_stage"):
            edge(asset.asset_id, tags["external_stage"], RelationshipType.DEPENDS_ON, "estate_external_table")
        if tags.get("storage_integration"):
            edge(asset.asset_id, tags["storage_integration"], RelationshipType.DEPENDS_ON, "estate_external_stage")
        if asset.resource_type == STORAGE_INTEGRATION_TYPE:
            role, location = tags.get("integration_role", ""), tags.get("integration_location", "")
            edge(asset.asset_id, role, RelationshipType.ASSUMES, "estate_storage_integration_role")
            edge(role, account_node_id.get(asset.account_scope, ""), RelationshipType.TRUSTS, "estate_storage_integration_trust")
            edge(role, location, RelationshipType.CAN_ACCESS, "estate_storage_integration_access")
    return drawn


__all__ = ["INTEGRATION_SOURCE", "STORAGE_INTEGRATION_TYPE", "project_external_stages", "record_external_stages"]
