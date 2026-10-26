"""AWS data, compute, secrets and registry service discovery for the inventory facade."""

from __future__ import annotations

import importlib
from typing import Any

from ..gpu_node_pools import eks_node_group_pool
from ._base import _iso, record_discovery_failure

_FACADE = "agent_bom.cloud.aws_inventory"


def _seams() -> Any:
    """Resolve patchable collaborators through the public facade at call time."""
    return importlib.import_module(_FACADE)


def _discover_rds(
    session: Any, region: str, *, account_id: str | None, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate RDS database instances (read-only). Become ``DATABASE`` data stores."""
    out: list[dict[str, Any]] = []
    try:
        client = session.client("rds", region_name=region)
        paginator = client.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page.get("DBInstances", []):
                name = str(db.get("DBInstanceIdentifier", "") or "")
                if not name:
                    continue
                out.append(
                    {
                        "name": name,
                        "arn": str(db.get("DBInstanceArn", "") or ""),
                        "engine": str(db.get("Engine", "") or ""),
                        "publicly_accessible": bool(db.get("PubliclyAccessible")),
                        "encrypted": bool(db.get("StorageEncrypted")),
                        "endpoint": str((db.get("Endpoint") or {}).get("Address", "") or ""),
                        "account_id": account_id or "",
                        "location": region,
                    }
                )
    except Exception as exc:  # noqa: BLE001 — one failed RDS list must not sink the scan
        record_discovery_failure(
            exc=exc, resource_type="RDS instances", permission="rds:DescribeDBInstances", cloud="aws", warnings=warnings, missing=missing
        )
    return out


def _discover_lambda(
    session: Any, region: str, *, account_id: str | None, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate Lambda functions (read-only). Become ``SERVERLESS_FUNCTION`` resources."""
    from agent_bom.cloud.aws import _AI_RUNTIMES, _extract_lambda_packages

    out: list[dict[str, Any]] = []
    try:
        client = session.client("lambda", region_name=region)
        paginator = client.get_paginator("list_functions")
        for page in paginator.paginate():
            for fn in page.get("Functions", []):
                name = str(fn.get("FunctionName", "") or "")
                if not name:
                    continue
                runtime = str(fn.get("Runtime", "") or "")
                vpc = fn.get("VpcConfig") or {}
                entry: dict[str, Any] = {
                    "name": name,
                    "arn": str(fn.get("FunctionArn", "") or ""),
                    "runtime": runtime,
                    "role": str(fn.get("Role", "") or ""),
                    "in_vpc": bool(vpc.get("VpcId")),
                    "account_id": account_id or "",
                    "location": region,
                }
                if runtime in _AI_RUNTIMES:
                    arn = entry["arn"]
                    if arn:
                        packages = _extract_lambda_packages(session, arn, region, warnings)
                        if packages:
                            entry["packages"] = [{"name": pkg.name, "version": pkg.version, "ecosystem": pkg.ecosystem} for pkg in packages]
                            entry["package_count"] = len(packages)
                out.append(entry)
    except Exception as exc:  # noqa: BLE001 — one failed Lambda list must not sink the scan
        record_discovery_failure(
            exc=exc, resource_type="Lambda functions", permission="lambda:ListFunctions", cloud="aws", warnings=warnings, missing=missing
        )
    return out


def _discover_dynamodb(
    session: Any, region: str, *, account_id: str | None, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate DynamoDB tables (read-only). Become ``DATABASE`` data stores."""
    out: list[dict[str, Any]] = []
    try:
        client = session.client("dynamodb", region_name=region)
        paginator = client.get_paginator("list_tables")
        for page in paginator.paginate():
            for name in page.get("TableNames", []):
                if not name:
                    continue
                encrypted = False
                try:
                    desc = client.describe_table(TableName=name).get("Table", {})
                    encrypted = bool((desc.get("SSEDescription") or {}).get("Status") == "ENABLED")
                except Exception:  # noqa: BLE001 — table metadata is best-effort
                    desc = {}
                out.append(
                    {
                        "name": str(name),
                        "arn": str(desc.get("TableArn", "") or f"arn:aws:dynamodb:{region}:{account_id or ''}:table/{name}"),
                        "encrypted": encrypted,
                        "item_count": int(desc.get("ItemCount", 0) or 0),
                        "account_id": account_id or "",
                        "location": region,
                    }
                )
    except Exception as exc:  # noqa: BLE001 — one failed DynamoDB list must not sink the scan
        record_discovery_failure(
            exc=exc, resource_type="DynamoDB tables", permission="dynamodb:ListTables", cloud="aws", warnings=warnings, missing=missing
        )
    return out


def _discover_eks(
    session: Any, region: str, *, account_id: str | None, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate EKS clusters (read-only). Become ``CONTAINER_CLUSTER`` resources."""
    out: list[dict[str, Any]] = []
    try:
        client = session.client("eks", region_name=region)
        names: list[str] = []
        paginator = client.get_paginator("list_clusters")
        for page in paginator.paginate():
            names.extend(page.get("clusters", []))
        for name in names:
            try:
                c = client.describe_cluster(name=name).get("cluster", {})
            except Exception:  # noqa: BLE001
                c = {"name": name}
            endpoint_public = bool((c.get("resourcesVpcConfig") or {}).get("endpointPublicAccess"))
            arn = str(c.get("arn", "") or "")
            node_pools, complete = _discover_eks_node_groups(client, name, arn, warnings=warnings, missing=missing)
            out.append(
                {
                    "name": str(c.get("name", name) or name),
                    "arn": arn,
                    "version": str(c.get("version", "") or ""),
                    "endpoint_public": endpoint_public,
                    "internet_exposed": endpoint_public,
                    "account_id": account_id or "",
                    "location": region,
                    "node_pools": node_pools,
                    "node_pools_complete": complete,
                }
            )
    except Exception as exc:  # noqa: BLE001 — one failed EKS list must not sink the scan
        record_discovery_failure(
            exc=exc, resource_type="EKS clusters", permission="eks:ListClusters", cloud="aws", warnings=warnings, missing=missing
        )
    return out


def _discover_eks_node_groups(
    client: Any, cluster_name: str, cluster_arn: str, *, warnings: list[str], missing: list[dict[str, str]] | None
) -> tuple[list[dict[str, Any]], bool]:
    """Managed node groups of one EKS cluster (read-only), GPU capacity flagged per group."""
    pools: list[dict[str, Any]] = []
    try:
        names = [
            n for page in client.get_paginator("list_nodegroups").paginate(clusterName=cluster_name) for n in page.get("nodegroups", [])
        ]
        for ng_name in names:
            nodegroup = client.describe_nodegroup(clusterName=cluster_name, nodegroupName=ng_name).get("nodegroup", {})
            pools.append(eks_node_group_pool(nodegroup, cluster_arn=cluster_arn))
    except Exception as exc:  # noqa: BLE001 — node-group denial keeps the cluster, marks pools incomplete
        record_discovery_failure(
            exc=exc, resource_type="EKS node groups", permission="eks:ListNodegroups", cloud="aws", warnings=warnings, missing=missing
        )
        return pools, False
    return pools, True


def _discover_kms(
    session: Any, region: str, *, account_id: str | None, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate customer-managed KMS keys (read-only). Metadata only, never key material."""
    out: list[dict[str, Any]] = []
    try:
        client = session.client("kms", region_name=region)
        paginator = client.get_paginator("list_keys")
        for page in paginator.paginate():
            for key in page.get("Keys", []):
                key_id = str(key.get("KeyId", "") or "")
                if not key_id:
                    continue
                manager, enabled, rotation = "", True, None
                try:
                    meta = client.describe_key(KeyId=key_id).get("KeyMetadata", {})
                    manager = str(meta.get("KeyManager", "") or "")
                    enabled = bool(meta.get("Enabled", True))
                    if manager == "AWS":  # skip AWS-managed keys — not customer's responsibility
                        continue
                    try:
                        rotation = bool(client.get_key_rotation_status(KeyId=key_id).get("KeyRotationEnabled"))
                    except Exception:  # noqa: BLE001
                        rotation = None
                except Exception:  # noqa: BLE001
                    meta = {}
                out.append(
                    {
                        "name": key_id,
                        "arn": str(key.get("KeyArn", "") or ""),
                        "enabled": enabled,
                        "rotation_enabled": rotation,
                        "account_id": account_id or "",
                        "location": region,
                    }
                )
    except Exception as exc:  # noqa: BLE001 — one failed KMS list must not sink the scan
        record_discovery_failure(
            exc=exc, resource_type="KMS keys", permission="kms:ListKeys", cloud="aws", warnings=warnings, missing=missing
        )
    return out


def _discover_secrets(
    session: Any, region: str, *, account_id: str | None, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate Secrets Manager secrets (read-only). Metadata only — never secret values."""
    out: list[dict[str, Any]] = []
    try:
        client = session.client("secretsmanager", region_name=region)
        paginator = client.get_paginator("list_secrets")
        for page in paginator.paginate():
            for sec in page.get("SecretList", []):
                name = str(sec.get("Name", "") or "")
                if not name:
                    continue
                out.append(
                    {
                        "name": name,
                        "arn": str(sec.get("ARN", "") or ""),
                        "rotation_enabled": bool(sec.get("RotationEnabled")),
                        "last_changed": _iso(sec.get("LastChangedDate")),
                        "account_id": account_id or "",
                        "location": region,
                    }
                )
    except Exception as exc:  # noqa: BLE001 — one failed Secrets list must not sink the scan
        record_discovery_failure(
            exc=exc,
            resource_type="Secrets Manager secrets",
            permission="secretsmanager:ListSecrets",
            cloud="aws",
            warnings=warnings,
            missing=missing,
        )
    return out


def _latest_ecr_image_ref(client: Any, repo_name: str, repo_uri: str) -> str | None:
    """Return the newest tagged image reference for an ECR repository."""
    from datetime import datetime

    best_ref: str | None = None
    best_pushed: datetime | None = None
    try:
        paginator = client.get_paginator("describe_images")
        for page in paginator.paginate(repositoryName=repo_name):
            for detail in page.get("imageDetails", []):
                tags = [str(t) for t in (detail.get("imageTags") or []) if t]
                if not tags:
                    continue
                pushed = detail.get("imagePushedAt")
                pushed_at = pushed if isinstance(pushed, datetime) else None
                if best_pushed is not None and pushed_at is not None and pushed_at <= best_pushed:
                    continue
                tag = sorted(tags)[0]
                best_ref = f"{repo_uri}:{tag}"
                best_pushed = pushed_at
    except Exception:
        return None
    return best_ref


def _discover_ecr(
    session: Any, region: str, *, account_id: str | None, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate ECR container registries (read-only). Become container-registry resources."""
    out: list[dict[str, Any]] = []
    try:
        client = session.client("ecr", region_name=region)
        paginator = client.get_paginator("describe_repositories")
        for page in paginator.paginate():
            for repo in page.get("repositories", []):
                name = str(repo.get("repositoryName", "") or "")
                if not name:
                    continue
                repo_uri = str(repo.get("repositoryUri", "") or "")
                row: dict[str, Any] = {
                    "name": name,
                    "arn": str(repo.get("repositoryArn", "") or ""),
                    "uri": repo_uri,
                    "scan_on_push": bool((repo.get("imageScanningConfiguration") or {}).get("scanOnPush")),
                    "tag_immutable": str(repo.get("imageTagMutability", "")) == "IMMUTABLE",
                    "account_id": account_id or "",
                    "location": region,
                }
                image_ref = _seams()._latest_ecr_image_ref(client, name, repo_uri)
                if image_ref:
                    try:
                        from agent_bom.cloud.sbom_pull import pull_cloud_sbom

                        sbom = pull_cloud_sbom("ecr", image_ref, region=region)
                        row["packages"] = sbom.packages
                        row["package_count"] = len(sbom.packages)
                        row["vulnerabilities"] = sbom.vulnerabilities
                        row["vulnerability_count"] = len(sbom.vulnerabilities)
                        row["sbom_image_ref"] = image_ref
                        for warning in sbom.warnings:
                            warnings.append(f"ECR {name}: {warning}")
                    except Exception as exc:  # noqa: BLE001
                        warnings.append(f"ECR {name}: SBOM pull failed: {exc}")
                out.append(row)
    except Exception as exc:  # noqa: BLE001 — one failed ECR list must not sink the scan
        record_discovery_failure(
            exc=exc,
            resource_type="ECR repositories",
            permission="ecr:DescribeRepositories",
            cloud="aws",
            warnings=warnings,
            missing=missing,
        )
    return out


def _discover_redshift(
    session: Any, region: str, *, account_id: str | None, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate Redshift clusters (read-only). Data warehouses → ``DATA_STORE``."""
    out: list[dict[str, Any]] = []
    try:
        client = session.client("redshift", region_name=region)
        paginator = client.get_paginator("describe_clusters")
        for page in paginator.paginate():
            for c in page.get("Clusters", []):
                name = str(c.get("ClusterIdentifier", "") or "")
                if not name:
                    continue
                out.append(
                    {
                        "name": name,
                        "engine": "redshift",
                        "publicly_accessible": bool(c.get("PubliclyAccessible")),
                        "encrypted": bool(c.get("Encrypted")),
                        "endpoint": str((c.get("Endpoint") or {}).get("Address", "") or ""),
                        "node_type": str(c.get("NodeType", "") or ""),
                        "account_id": account_id or "",
                        "location": region,
                    }
                )
    except Exception as exc:  # noqa: BLE001 — one failed Redshift list must not sink the scan
        record_discovery_failure(
            exc=exc,
            resource_type="Redshift clusters",
            permission="redshift:DescribeClusters",
            cloud="aws",
            warnings=warnings,
            missing=missing,
        )
    return out
