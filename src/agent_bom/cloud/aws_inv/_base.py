"""Shared AWS inventory payload, permission and error-classification helpers."""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, NamedTuple

from agent_bom.discovery_envelope import DiscoveryEnvelope, RedactionStatus, ScanMode

from ..normalization import sanitize_discovery_warning

_MAX_ACCESS_ADVISOR_POLLS = 3


_MAX_ACCESS_ADVISOR_PAGES = 5


# Read-only IAM actions this scanner is allowed to exercise, by resource class.
# Kept here so the per-run discovery envelope `permissions_used` stays honest:
# the producer owns the catalog, not external docs.
_AWS_S3_PERMISSIONS: tuple[str, ...] = (
    "s3:ListAllMyBuckets",
    "s3:GetBucketLocation",
    "s3:GetBucketPolicyStatus",
    "s3:GetBucketPublicAccessBlock",
    "s3:GetBucketTagging",
)


_AWS_EC2_PERMISSIONS: tuple[str, ...] = (
    "ec2:DescribeInstances",
    "ec2:DescribeSecurityGroups",
)


_AWS_IAM_PERMISSIONS: tuple[str, ...] = (
    "iam:ListRoles",
    "iam:GetRole",
    "iam:ListUsers",
    "iam:ListGroups",
    "iam:GetGroup",
    "iam:ListGroupsForUser",
    "iam:ListAttachedRolePolicies",
    "iam:ListAttachedUserPolicies",
    "iam:ListAttachedGroupPolicies",
    "iam:ListRolePolicies",
    "iam:ListUserPolicies",
    "iam:ListGroupPolicies",
    "iam:GetRolePolicy",
    "iam:GetUserPolicy",
    "iam:GetGroupPolicy",
    "iam:GetPolicy",
    "iam:GetPolicyVersion",
    "iam:GenerateServiceLastAccessedDetails",
    "iam:GetServiceLastAccessedDetails",
)


_AWS_DATA_PERMISSIONS: tuple[str, ...] = (
    "rds:DescribeDBInstances",
    "dynamodb:ListTables",
    "dynamodb:DescribeTable",
    "redshift:DescribeClusters",
)


_AWS_COMPUTE_PERMISSIONS: tuple[str, ...] = (
    "lambda:ListFunctions",
    "lambda:GetFunction",
    "eks:ListClusters",
    "eks:DescribeCluster",
    "ecr:DescribeRepositories",
    "ecr:DescribeImages",
    "ecr:DescribeImageScanFindings",
)


_AWS_NETWORK_PERMISSIONS: tuple[str, ...] = (
    "elasticloadbalancing:DescribeLoadBalancers",
    "elasticloadbalancing:DescribeTargetGroups",
    "elasticloadbalancing:DescribeTargetHealth",
    "ec2:DescribeVpcs",
    "cloudfront:ListDistributions",
    "sns:ListTopics",
    "sqs:ListQueues",
)


_AWS_SECURITY_PERMISSIONS: tuple[str, ...] = (
    "kms:ListKeys",
    "kms:DescribeKey",
    "kms:GetKeyRotationStatus",
    "secretsmanager:ListSecrets",
)


# Network-edge read-only actions: WAF, API Gateway, and the VPC plumbing
# (ENIs, NAT/internet gateways, subnets, route tables, network ACLs, VPC
# endpoints) plus IP enumeration (Elastic IPs). All inside SecurityAudit /
# ViewOnlyAccess; no new grant.
_AWS_EDGE_PERMISSIONS: tuple[str, ...] = (
    "wafv2:ListWebACLs",
    "wafv2:ListResourcesForWebACL",
    "wafv2:GetWebACLForResource",
    "apigateway:GET",
    "ec2:DescribeNetworkInterfaces",
    "ec2:DescribeNatGateways",
    "ec2:DescribeInternetGateways",
    "ec2:DescribeEgressOnlyInternetGateways",
    "ec2:DescribeVpcEndpoints",
    "ec2:DescribeSubnets",
    "ec2:DescribeRouteTables",
    "ec2:DescribeNetworkAcls",
    "ec2:DescribeAddresses",
)


_AWS_BASELINE_PERMISSIONS: tuple[str, ...] = ("sts:GetCallerIdentity",)


# Open-to-the-world CIDR / ipv6 ranges that mark a security-group ingress rule
# as internet-facing. The CNAPP overlay keys off this `network_exposure` shape.
_INTERNET_CIDRS = {"0.0.0.0/0"}


_INTERNET_IPV6 = {"::/0"}


# Substrings that mark an exception as an access/permission failure, matched
# case-insensitively against the SDK error code / message. Covers AWS botocore
# (AccessDenied / UnauthorizedOperation / AccessDeniedException), Azure
# (AuthorizationFailed / Forbidden / 403), and GCP (PermissionDenied / 403).
_ACCESS_DENIED_MARKERS: tuple[str, ...] = (
    "accessdenied",
    "access denied",
    "unauthorizedoperation",
    "authorizationfailed",
    "permissiondenied",
    "permission denied",
    "forbidden",
    "notauthorized",
    "not authorized",
    "insufficient permission",
    "insufficient_permission",
    "iam.serviceaccounts.actas",
)


def _error_code(exc: BaseException) -> str:
    """Best-effort SDK error code extraction across botocore / Azure / GCP.

    - botocore ``ClientError`` exposes ``response["Error"]["Code"]``.
    - Azure ``HttpResponseError`` exposes ``.error.code`` and ``.status_code``.
    - GCP ``GoogleAPICallError`` exposes ``.code`` (a grpc status or int).

    Never raises — a provider that does not expose these attributes returns "".
    """
    code = ""
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        err = response.get("Error")
        if isinstance(err, dict):
            code = str(err.get("Code", "") or "")
    if not code:
        inner = getattr(exc, "error", None)
        inner_code = getattr(inner, "code", None)
        if inner_code is not None:
            code = str(inner_code)
    if not code:
        direct = getattr(exc, "code", None)
        if direct is not None:
            code = str(direct)
    return code


def _status_code(exc: BaseException) -> int | None:
    """Best-effort HTTP status extraction (Azure ``status_code`` / botocore 403)."""
    status = getattr(exc, "status_code", None)
    if isinstance(status, int):
        return status
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        meta = response.get("ResponseMetadata")
        if isinstance(meta, dict):
            http_status = meta.get("HTTPStatusCode")
            if isinstance(http_status, int):
                return http_status
    return None


def is_access_denied_error(exc: BaseException) -> bool:
    """Return whether *exc* is an access/permission failure (any cloud SDK).

    Detection is layered so it works without importing every provider SDK:
    a 401/403 HTTP status, a known error code, or an access-denied marker in the
    error code / message text. Type name is also checked so SDK-specific
    permission exceptions (e.g. GCP ``PermissionDenied`` / ``Forbidden``) are
    caught even when the message text is sparse.
    """
    status = _status_code(exc)
    if status in (401, 403):
        return True
    haystacks = [
        _error_code(exc).lower(),
        type(exc).__name__.lower(),
        str(exc).lower(),
    ]
    return any(marker in field for field in haystacks for marker in _ACCESS_DENIED_MARKERS)


_BILLING_DISABLED_MARKERS = (
    "billing_disabled",
    "requires billing to be enabled",
    "billing account for the owning project is disabled",
    "billing is disabled",
)


_SERVICE_DISABLED_MARKERS = (
    "service_disabled",
    "accessnotconfigured",
    "has not been used in project",
    "api is not enabled",
)


def classify_project_disabled_error(exc: BaseException) -> str:
    """Return ``billing_disabled`` / ``service_disabled`` for GCP project-state 403s.

    GCP answers a call against a project whose billing is disabled, or whose
    API is not enabled, with HTTP 403 — the same status as a missing IAM
    permission. These are project-state problems (``ErrorInfo.reason`` of
    ``BILLING_DISABLED`` / ``SERVICE_DISABLED``) that no read-only role grant
    can fix, so they must not be reported as a permission gap. Returns ``""``
    for anything else.
    """
    # google-api-core exposes the ErrorInfo reason as ``.reason``; the
    # discovery client (googleapiclient HttpError) carries it in
    # ``.error_details``. Neither is guaranteed to appear in ``str(exc)``.
    text = f"{_error_code(exc)} {getattr(exc, 'reason', '') or ''} {getattr(exc, 'error_details', '') or ''} {exc}".lower()
    if any(marker in text for marker in _BILLING_DISABLED_MARKERS):
        return "billing_disabled"
    if any(marker in text for marker in _SERVICE_DISABLED_MARKERS):
        return "service_disabled"
    return ""


def build_missing_permission(*, cloud: str, permission: str, resource_type: str) -> dict[str, str]:
    """Return one structured ``missing_permissions`` entry.

    The tuple ``(cloud, permission, resource_type)`` is the dedup key so the same
    grant surfaced from two regions/subscriptions collapses to a single row.
    """
    return {
        "cloud": cloud,
        "permission": permission,
        "resource_type": resource_type,
    }


def dedupe_missing_permissions(items: list[dict[str, str]]) -> list[dict[str, str]]:
    """Return a sorted, de-duplicated ``missing_permissions`` list.

    Deterministic + idempotent: same failures (in any order) always produce the
    same set of rows, sorted by (cloud, resource_type, permission), so report
    output is byte-stable across runs.
    """
    seen: set[tuple[str, str, str]] = set()
    unique: list[dict[str, str]] = []
    for item in items:
        key = (
            str(item.get("cloud", "") or ""),
            str(item.get("permission", "") or ""),
            str(item.get("resource_type", "") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append({"cloud": key[0], "permission": key[1], "resource_type": key[2]})
    unique.sort(key=lambda row: (row["cloud"], row["resource_type"], row["permission"]))
    return unique


def record_discovery_failure(
    *,
    exc: BaseException,
    resource_type: str,
    permission: str,
    cloud: str,
    warnings: list[str],
    missing: list[dict[str, str]] | None = None,
) -> None:
    """Translate a failed discovery call into operator-facing diagnostics.

    On an access/permission error this emits a SPECIFIC, actionable warning that
    names the missing permission and the resource type being skipped, and records
    a structured ``missing_permissions`` entry (when *missing* is provided). On
    any other failure it emits a generic, sanitized warning. Either way the
    skipped resource type ALWAYS produces a warning — never a silent empty
    result. Secrets are stripped via ``sanitize_discovery_warning``.
    """
    detail = sanitize_discovery_warning(exc)
    project_state = classify_project_disabled_error(exc)
    if project_state == "billing_disabled":
        warnings.append(
            f"Skipped {resource_type}: billing is disabled for this project — enable billing (or exclude the project) "
            f"to cover this resource type; no role change is needed. ({detail})"
        )
    elif project_state == "service_disabled":
        warnings.append(
            f"Skipped {resource_type}: the service API is not enabled in this project — nothing to inventory unless it is "
            f"enabled; no role change is needed. ({detail})"
        )
    elif is_access_denied_error(exc):
        warnings.append(
            f"Skipped {resource_type}: role lacks {permission} — add it to the read-only policy to cover this resource type. ({detail})"
        )
        if missing is not None:
            missing.append(build_missing_permission(cloud=cloud, permission=permission, resource_type=resource_type))
    else:
        warnings.append(f"Could not list {resource_type}: {detail}")


# Sentinel a stored connection carries in ``regions`` to request an estate-wide
# multi-region scan (the explicit "All regions" wizard toggle), instead of a
# single default region. Case-insensitive.
ALL_REGIONS_SENTINEL = "all"


def is_all_regions(regions: list[str] | None) -> bool:
    """Whether a connection's ``regions`` requests the all-enabled-regions fan-out."""
    if not regions:
        return False
    return any(str(r).strip().lower() == ALL_REGIONS_SENTINEL for r in regions)


def _empty_payload(*, region: str) -> dict[str, Any]:
    """Return a fully-populated empty inventory payload (every list key present).

    Shared by the single-region and multi-region paths so the payload shape the
    graph builder consumes is defined in exactly one place.
    """
    return {
        "provider": "aws",
        "status": "disabled",
        "account_id": None,
        "region": region,
        "buckets": [],
        "instances": [],
        "security_groups": [],
        "roles": [],
        "users": [],
        "groups": [],
        "rds_instances": [],
        "lambda_functions": [],
        "dynamodb_tables": [],
        "eks_clusters": [],
        "elb_load_balancers": [],
        "vpcs": [],
        "kms_keys": [],
        "secrets": [],
        "cloudfront_distributions": [],
        "ecr_repositories": [],
        "redshift_clusters": [],
        "messaging": [],
        "web_acls": [],
        "api_gateways": [],
        "network_interfaces": [],
        "subnets": [],
        "nat_gateways": [],
        "internet_gateways": [],
        "vpc_endpoints": [],
        "route_tables": [],
        "network_acls": [],
        "ip_addresses": [],
        "warnings": [],
        "missing_permissions": [],
        "discovery_envelope": None,
    }


# Region-scoped resource lists. These are concatenated across regions: each
# item already carries its own ``location``/``region`` so the merge is a simple
# extend, never a dedupe.
_REGION_SCOPED_KEYS: tuple[str, ...] = (
    "instances",
    "security_groups",
    "rds_instances",
    "lambda_functions",
    "dynamodb_tables",
    "eks_clusters",
    "elb_load_balancers",
    "vpcs",
    "kms_keys",
    "secrets",
    "ecr_repositories",
    "redshift_clusters",
    "messaging",
    "web_acls",
    "api_gateways",
    "network_interfaces",
    "subnets",
    "nat_gateways",
    "internet_gateways",
    "vpc_endpoints",
    "route_tables",
    "network_acls",
    "ip_addresses",
)


def _enabled_regions(session: Any, default_region: str, warnings: list[str]) -> list[str]:
    """Resolve the region list to fan out over (read-only ``describe_regions``).

    Resolution order: explicit ``AGENT_BOM_AWS_REGIONS`` env override (handled by
    the caller) → enumerate enabled regions via ``ec2:DescribeRegions`` → fall
    back to the single default region. Never raises: a failed enumeration
    degrades to the single default region plus a warning.
    """
    try:
        client = session.client("ec2", region_name=default_region)
        resp = client.describe_regions(AllRegions=False)
        regions = [
            str(r.get("RegionName", "") or "").strip() for r in resp.get("Regions", []) or [] if str(r.get("RegionName", "") or "").strip()
        ]
        if regions:
            return sorted(set(regions))
    except Exception as exc:  # noqa: BLE001 — region enumeration must never sink a scan
        warnings.append(f"Could not enumerate enabled AWS regions; scanning {default_region} only: {sanitize_discovery_warning(exc)}")
    return [default_region]


_PAYLOAD_META_KEYS = frozenset({"provider", "status", "account_id", "region", "warnings", "missing_permissions", "discovery_envelope"})


_BOTO3_MISSING_WARNING = "boto3 is required for AWS inventory. Install with: pip install 'agent-bom[aws]'"


class _ServiceGroups(NamedTuple):
    """Which service groups a scan enumerates (mirrors the ``include_*`` flags)."""

    s3: bool
    ec2: bool
    iam: bool
    data: bool
    compute: bool
    network: bool


def _open_session(boto3: Any, *, region: str | None, profile: str | None) -> tuple[Any, str | None]:
    """Build a boto3 session from the profile/default chain; ``(None, warning)`` on config errors."""
    session_kwargs: dict[str, Any] = {}
    if region:
        session_kwargs["region_name"] = region
    if profile:
        session_kwargs["profile_name"] = profile
    try:
        return boto3.Session(**session_kwargs), None
    except Exception as exc:  # noqa: BLE001 — boto profile/config errors must not crash a scan
        return None, sanitize_discovery_warning(exc)


def _permissions_used(groups: _ServiceGroups, extra: tuple[str, ...] = ()) -> tuple[str, ...]:
    """Sorted, deduped read-only permission set for the enabled service groups."""
    permissions: list[str] = [*_AWS_BASELINE_PERMISSIONS, *extra]
    for enabled, group in (
        (groups.s3, _AWS_S3_PERMISSIONS),
        (groups.ec2, _AWS_EC2_PERMISSIONS),
        (groups.iam, _AWS_IAM_PERMISSIONS),
        (groups.data, _AWS_DATA_PERMISSIONS),
        (groups.data, _AWS_SECURITY_PERMISSIONS),
        (groups.compute, _AWS_COMPUTE_PERMISSIONS),
        (groups.network, _AWS_NETWORK_PERMISSIONS),
        (groups.network, _AWS_EDGE_PERMISSIONS),
    ):
        if enabled:
            permissions.extend(group)
    return tuple(sorted(set(permissions)))


def _ok_payload(
    *,
    account_id: str | None,
    region: str,
    scope_regions: list[str],
    permissions_used: tuple[str, ...],
    resources: dict[str, list[dict[str, Any]]],
    warnings: list[str],
    missing: list[dict[str, str]],
    regions: list[str] | None = None,
) -> dict[str, Any]:
    """Assemble the ``status: ok`` payload (same key order as :func:`_empty_payload`)."""
    discovery_scope = [f"aws:account/{account_id}"] if account_id else []
    discovery_scope.extend(f"aws:region/{r}" for r in scope_regions)
    envelope = DiscoveryEnvelope(
        scan_mode=ScanMode.CLOUD_READ_ONLY,
        discovery_scope=tuple(discovery_scope),
        permissions_used=permissions_used,
        redaction_status=RedactionStatus.CENTRAL_SANITIZER_APPLIED,
    )
    payload: dict[str, Any] = {"provider": "aws", "status": "ok", "account_id": account_id, "region": region}
    if regions is not None:
        payload["regions"] = regions
    for key in _empty_payload(region=region):
        if key not in _PAYLOAD_META_KEYS:
            payload[key] = resources.get(key, [])
    payload["warnings"] = warnings
    payload["missing_permissions"] = dedupe_missing_permissions(missing)
    payload["discovery_envelope"] = envelope.to_dict()
    return payload


def _scan_regions_concurrently(
    region_list: list[str], scan: Callable[[str], dict[str, Any]], warnings: list[str]
) -> dict[str, dict[str, Any]]:
    """Fan ``scan`` out over every region; a failing region becomes a warning."""
    region_payloads: dict[str, dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=min(8, max(1, len(region_list)))) as executor:
        future_to_region = {executor.submit(scan, region): region for region in region_list}
        for future in as_completed(future_to_region):
            region = future_to_region[future]
            try:
                region_payloads[region] = future.result()
            except Exception as exc:  # noqa: BLE001 — one bad region must not sink the scan
                warnings.append(f"Region {region} skipped: {sanitize_discovery_warning(exc)}")
    return region_payloads


def _dedupe_inventory_items(items: list[dict[str, Any]], field: str) -> list[dict[str, Any]]:
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for item in items:
        ident = str(item.get(field, "") or "") or str(item.get("name", "") or "")
        if ident and ident in seen:
            continue
        if ident:
            seen.add(ident)
        unique.append(item)
    return unique


def _merge_region_payloads(
    region_list: list[str],
    region_payloads: dict[str, dict[str, Any]],
    *,
    warnings: list[str],
    missing: list[dict[str, str]],
) -> dict[str, list[dict[str, Any]]]:
    """Concatenate region-scoped resources (in region order) and dedupe CloudFront."""
    merged: dict[str, list[dict[str, Any]]] = {key: [] for key in _REGION_SCOPED_KEYS}
    # CloudFront is global but is enumerated by each per-region scan (it rides on
    # include_network); collect across regions, then dedupe by name below.
    cloudfront_seen: list[dict[str, Any]] = []
    for region in region_list:
        payload = region_payloads.get(region)
        if payload is None:
            continue
        for warning in payload.get("warnings", []):
            warnings.append(f"[{region}] {warning}")
        missing.extend(payload.get("missing_permissions", []) or [])
        if payload.get("status") != "ok":
            # A degraded region surfaces its warnings (above) but contributes no
            # resources — it must never abort the merge.
            continue
        for key in _REGION_SCOPED_KEYS:
            merged[key].extend(payload.get(key, []) or [])
        cloudfront_seen.extend(payload.get("cloudfront_distributions", []) or [])
    merged["cloudfront_distributions"] = _dedupe_inventory_items(cloudfront_seen, "name")
    return merged


def _iso(value: Any) -> str:
    """Render a boto3 datetime (or string) as an ISO-8601 string, else ''."""
    if value in ("", None):
        return ""
    isoformat = getattr(value, "isoformat", None)
    if callable(isoformat):
        return str(isoformat())
    return str(value)
