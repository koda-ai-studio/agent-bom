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
from agent_bom.demo_estate.estate_edges import add_estate_edge
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.types import RelationshipType

INTEGRATION_SOURCE = "synthetic-demo-integration"
# Snowflake's own AWS account, as DESC INTEGRATION reports it; fictional.
_SNOWFLAKE_AWS_ACCOUNT = "444455556666"
_SCALAR_IDENTIFIERS = ("arn", "storage_aws_role_arn", "storage_aws_iam_user_arn", "storage_aws_external_id")
_LIST_IDENTIFIERS = ("storage_allowed_locations", "trust_principals", "trust_external_ids")
STORAGE_INTEGRATION_TYPE = "storage_integration"


def _pick(seed: str, candidates: Sequence[EstateAsset]) -> EstateAsset | None:
    if not candidates:
        return None
    ordered = sorted(candidates, key=lambda asset: asset.asset_id)
    return ordered[int.from_bytes(hashlib.sha256(seed.encode()).digest()[:4], "big") % len(ordered)]


def _with_tags(asset: EstateAsset, **tags: str) -> EstateAsset:
    return asset.model_copy(update={"tags": {**asset.tags, **tags}})


def _snowflake_trust(stage: EstateAsset) -> tuple[str, str]:
    """The IAM user and external id Snowflake reports for an integration (``DESC INTEGRATION``)."""
    digest = hashlib.sha256(stage.asset_id.encode()).hexdigest()[:8].upper()
    return f"arn:aws:iam::{_SNOWFLAKE_AWS_ACCOUNT}:user/{stage.account_scope.lower()}-s3-int", f"{stage.account_scope}_SFCRole=2_{digest}"


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
            "storage_aws_role_arn": role.native_id,
            "storage_aws_iam_user_arn": _snowflake_trust(stage)[0],
            "storage_aws_external_id": _snowflake_trust(stage)[1],
            "storage_allowed_locations": f"s3://{bucket.display_name}/",
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
            # The trust policy the role was created with: Snowflake's IAM user and external id.
            "trust_principals": _snowflake_trust(stage)[0],
            "trust_external_ids": _snowflake_trust(stage)[1],
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
        # The bucket's ARN, as an S3 collection records it.
        updates[bucket.asset_id] = _with_tags(updates.get(bucket.asset_id, bucket), arn=f"arn:aws:s3:::{bucket.display_name}")
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


def project_external_stages(graph: UnifiedGraph, assets: Sequence[EstateAsset]) -> int:
    """Draw the Snowflake-internal lineage the stage and table record; returns edges drawn.

    The cross-vendor edges are not drawn here: the graph's storage-integration
    correlation derives them from the recorded identifiers.
    """
    drawn = 0
    for asset in assets:
        for tag, reason in (("external_stage", "estate_external_table"), ("storage_integration", "estate_external_stage")):
            target = asset.tags.get(tag, "")
            if target and asset.asset_id in graph.nodes and target in graph.nodes:
                add_estate_edge(graph, asset.asset_id, target, RelationshipType.DEPENDS_ON, evidence={"reason": reason})
                drawn += 1
    return drawn


def recorded_identifier_attributes(tags: dict[str, str]) -> dict[str, object]:
    """Recorded identifiers lifted onto a node, where the graph's correlation reads them."""
    lifted: dict[str, object] = {key: tags[key] for key in _SCALAR_IDENTIFIERS if tags.get(key)}
    lifted.update({key: [part for part in tags[key].split(",") if part] for key in _LIST_IDENTIFIERS if tags.get(key)})
    return lifted


__all__ = [
    "INTEGRATION_SOURCE",
    "STORAGE_INTEGRATION_TYPE",
    "project_external_stages",
    "record_external_stages",
    "recorded_identifier_attributes",
]
