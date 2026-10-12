"""Shared AWS workload origin, timestamps and configured execution-role metadata."""

from __future__ import annotations

from typing import Any

from .normalization import build_cloud_origin, build_cloud_principal, build_cloud_timestamps


def build_aws_workload_metadata(
    *,
    service: str,
    resource_type: str,
    resource_id: str,
    resource_name: str,
    region: str,
    account_id: str | None,
    role_arn: str,
    role_field: str,
    raw_identity: dict[str, Any],
    updated_at: Any = None,
    created_at: Any = None,
    updated_source: str | None = None,
    created_source: str | None = None,
) -> dict[str, Any]:
    metadata = {
        "cloud_origin": build_cloud_origin(
            provider="aws",
            service=service,
            resource_type=resource_type,
            resource_id=resource_id,
            resource_name=resource_name,
            location=region,
            account_id=account_id,
            raw_identity=raw_identity,
        )
    }
    timestamps = build_cloud_timestamps(
        provider="aws",
        service=service,
        resource_type=resource_type,
        updated_at=updated_at,
        created_at=created_at,
        updated_source=updated_source,
        created_source=created_source,
    )
    if timestamps:
        metadata["cloud_timestamps"] = timestamps
    principal = build_cloud_principal(
        provider="aws",
        service=service,
        resource_type=resource_type,
        principal_type="iam-role",
        principal_id=role_arn or None,
        source_field=role_field,
        raw_identity={"role_arn": role_arn},
    )
    if principal:
        metadata["cloud_principal"] = principal
    return metadata
