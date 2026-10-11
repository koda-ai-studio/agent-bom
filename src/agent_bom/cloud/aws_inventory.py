"""AWS general cloud-asset inventory — estate-wide, read-only, agentless.

Unlike :mod:`agent_bom.cloud.aws` (which discovers *AI* runtimes: Bedrock
agents, Lambda action groups, SageMaker endpoints), this module enumerates the
general cloud estate so that a resource with **no** CIS finding, IaC target, or
discovered AI runtime still becomes a first-class graph node. That feeds the
CNAPP exposure overlay, the CIEM effective-permissions overlay, and the DSPM
tiers, which were previously starved of inventory input.

Three resource classes are enumerated estate-wide (NOT filtered to findings):

1. **S3 buckets**            → emitted as ``DATA_STORE`` so the DSPM /
   ``STORES`` / ``EXPOSED_TO`` overlays apply.
2. **EC2 instances + security groups** → emitted as ``CLOUD_RESOURCE``.
3. **IAM roles + users**    → emitted as identity principals with a
   ``HAS_PERMISSION``-ready policy structure.

This scanner is **opt-in** and **default OFF**. It runs only when
``AGENT_BOM_CLOUD_INVENTORY`` is truthy, mirroring the platform's other
optional-feature gates (e.g. ``AGENT_BOM_ENABLE_EXTENSION_ENTRYPOINTS``,
``AGENT_BOM_DISTRIBUTED_SCANS``).

Trust posture: read-only (``ScanMode.CLOUD_READ_ONLY``), reference-only, and
agentless. Resource discovery uses ``List*`` / ``Describe*`` / ``Get*Policy*``
APIs; IAM role usage adds the read-only Access Advisor report pair
``GenerateServiceLastAccessedDetails`` / ``GetServiceLastAccessedDetails`` plus
``GetRole`` for the role-last-used timestamp that ``ListRoles`` omits. Neither
path changes IAM or cloud-resource configuration, reads object content, or
exfiltrates credentials. Boto3 absence or missing credentials degrades to an
empty inventory plus a clear status, never a crash.

Requires ``boto3``. Install with::

    pip install 'agent-bom[aws]'
"""

from __future__ import annotations

import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from agent_bom.security import sanitize_text

from .aws import (
    _resolve_account_id,
)
from .aws_iam_collector import collect_iam_roles_usage_evidence
from .aws_inv._base import (  # noqa: F401 - facade re-export
    _ACCESS_DENIED_MARKERS,
    _AWS_BASELINE_PERMISSIONS,
    _AWS_COMPUTE_PERMISSIONS,
    _AWS_DATA_PERMISSIONS,
    _AWS_EC2_PERMISSIONS,
    _AWS_EDGE_PERMISSIONS,
    _AWS_IAM_PERMISSIONS,
    _AWS_NETWORK_PERMISSIONS,
    _AWS_S3_PERMISSIONS,
    _AWS_SECURITY_PERMISSIONS,
    _BILLING_DISABLED_MARKERS,
    _BOTO3_MISSING_WARNING,
    _INTERNET_CIDRS,
    _INTERNET_IPV6,
    _MAX_ACCESS_ADVISOR_PAGES,
    _MAX_ACCESS_ADVISOR_POLLS,
    _PAYLOAD_META_KEYS,
    _REGION_SCOPED_KEYS,
    _SERVICE_DISABLED_MARKERS,
    ALL_REGIONS_SENTINEL,
    _dedupe_inventory_items,
    _empty_payload,
    _enabled_regions,
    _error_code,
    _iso,
    _merge_region_payloads,
    _ok_payload,
    _open_session,
    _permissions_used,
    _scan_regions_concurrently,
    _ServiceGroups,
    _status_code,
    build_missing_permission,
    classify_project_disabled_error,
    dedupe_missing_permissions,
    is_access_denied_error,
    is_all_regions,
    record_discovery_failure,
)
from .aws_inv.edge import (  # noqa: F401 - facade re-export
    _discover_api_gateways,
    _discover_cloudfront,
    _discover_elb,
    _discover_messaging,
    _discover_waf,
)
from .aws_inv.network import (  # noqa: F401 - facade re-export
    _collect_edge_rows,
    _discover_ip_addresses,
    _discover_network_edge,
    _discover_vpcs,
    _ec2_items,
    _ec2_pages,
    _EdgeStage,
    _internet_gateway_row,
    _nat_gateway_row,
    _network_acl_exposure,
    _network_acl_row,
    _network_edge_stages,
    _network_interface_row,
    _route_table_row,
    _subnet_row,
    _vpc_endpoint_row,
)
from .aws_inv.services import (  # noqa: F401 - facade re-export
    _discover_dynamodb,
    _discover_ecr,
    _discover_eks,
    _discover_kms,
    _discover_lambda,
    _discover_rds,
    _discover_redshift,
    _discover_secrets,
    _latest_ecr_image_ref,
)
from .aws_inv.storage_compute import (  # noqa: F401 - facade re-export
    _AWS_MANAGED_PRIVILEGE,
    _PRIVILEGE_RANK,
    _PUBLIC_ACL_GRANTEE_URIS,
    _account_public_access_block,
    _attached_policies,
    _bucket_location,
    _bucket_public,
    _bucket_tags,
    _discover_ec2,
    _discover_s3_buckets,
    _group_members,
    _groups_for_user,
    _highest_privilege,
    _inline_policies,
    _normalize_group,
    _normalize_instance,
    _normalize_role,
    _normalize_security_group,
    _normalize_user,
    _policy_privilege_and_document,
    _security_group_internet_exposure,
)
from .normalization import sanitize_discovery_warning

logger = logging.getLogger(__name__)

# Opt-in env flag. Default OFF — estate-wide enumeration must be explicitly
# requested by an operator. Symmetric with the other providers'
# AGENT_BOM_<PROVIDER>_INVENTORY gates (AZURE / GCP / SNOWFLAKE).
INVENTORY_ENV_FLAG = "AGENT_BOM_AWS_INVENTORY"
# Deprecated original name. Still honoured (with a one-time warning) so existing
# automation keeps working; remove in a future release.
INVENTORY_ENV_FLAG_LEGACY = "AGENT_BOM_CLOUD_INVENTORY"

# Multi-region fan-out gate. Default OFF — single-region remains the default so
# existing single-region automation is unchanged. Symmetric with Azure's
# AGENT_BOM_AZURE_ALL_SUBSCRIPTIONS tenant-wide fan-out gate.
ALL_REGIONS_ENV_FLAG = "AGENT_BOM_AWS_ALL_REGIONS"
# Optional explicit region list (comma-separated). When set, it overrides
# describe_regions enumeration so an operator can scope a multi-region scan.
REGIONS_ENV_VAR = "AGENT_BOM_AWS_REGIONS"
# Defensive cap so an account with a large enabled-region set can't fan out
# unbounded without an operator opting into a larger budget.
_MAX_REGIONS = int(os.environ.get("AGENT_BOM_AWS_MAX_REGIONS", "32") or "32")
# Access Advisor starts one bounded analysis job per role. Inventory remains
# complete beyond this cap, but additional roles carry explicit unavailable
# usage evidence instead of launching an unbounded number of jobs.
_MAX_IAM_USAGE_ROLES = 100

_TRUTHY = {"1", "true", "yes", "on"}


# ---------------------------------------------------------------------------
# Cross-cloud degrade-don't-crash helpers
#
# These are the single source of truth for turning a failed discovery call into
# (a) a user-facing warning and (b) — when the failure is an access/permission
# error — a SPECIFIC, actionable warning plus a structured `missing_permissions`
# entry the product can render as "here is exactly what to grant".
#
# Azure and GCP inventory import these so all three providers degrade to the same
# bar: one failed discoverer -> one warning + (when access-denied) one
# missing_permissions entry -> `continue`, never an abort, never a silent empty
# result. Keep secrets out of every message by routing through
# sanitize_discovery_warning.
# ---------------------------------------------------------------------------


_legacy_flag_warned = False


def inventory_enabled() -> bool:
    """Return whether estate-wide AWS inventory enumeration is opted in.

    Default OFF. Operators enable it by setting ``AGENT_BOM_AWS_INVENTORY`` to a
    truthy value (``1`` / ``true`` / ``yes`` / ``on``). The original
    ``AGENT_BOM_CLOUD_INVENTORY`` name is still honoured for one release and
    emits a one-time deprecation warning.
    """
    global _legacy_flag_warned
    if os.environ.get(INVENTORY_ENV_FLAG, "").strip().lower() in _TRUTHY:
        return True
    if os.environ.get(INVENTORY_ENV_FLAG_LEGACY, "").strip().lower() in _TRUTHY:
        if not _legacy_flag_warned:
            logger.warning(
                "%s is deprecated; set %s instead.",
                INVENTORY_ENV_FLAG_LEGACY,
                INVENTORY_ENV_FLAG,
            )
            _legacy_flag_warned = True
        return True
    return False


def all_regions_enabled() -> bool:
    """Whether to fan a single scan across every enabled region in the account.

    Default OFF. Operators opt in by setting ``AGENT_BOM_AWS_ALL_REGIONS`` truthy
    (or by passing an explicit ``regions`` list to
    :func:`discover_inventory_all_regions`). Mirrors Azure's all-subscriptions
    gate so the single-region path stays the default.
    """
    return os.environ.get(ALL_REGIONS_ENV_FLAG, "").strip().lower() in _TRUTHY


def _resolve_region_list(
    session: Any,
    default_region: str,
    *,
    regions: list[str] | None,
    warnings: list[str],
) -> list[str]:
    """Return the (capped, deduped) ordered region list for a multi-region scan."""
    if regions:
        candidates = [str(r).strip() for r in regions if str(r).strip()]
    else:
        env_regions = os.environ.get(REGIONS_ENV_VAR, "").strip()
        if env_regions:
            candidates = [r.strip() for r in env_regions.split(",") if r.strip()]
        else:
            candidates = _enabled_regions(session, default_region, warnings)

    ordered: list[str] = []
    for region in candidates:
        if region not in ordered:
            ordered.append(region)
    if not ordered:
        ordered = [default_region]
    if len(ordered) > _MAX_REGIONS:
        warnings.append(f"Multi-region scan capped at {_MAX_REGIONS} of {len(ordered)} regions (set AGENT_BOM_AWS_MAX_REGIONS to raise).")
        ordered = ordered[:_MAX_REGIONS]
    return ordered


def _discover_inventory_for(groups: _ServiceGroups, *, region: str, profile: str | None, session: Any) -> dict[str, Any]:
    """Run :func:`discover_inventory` (resolved at call time) for one region and service-group set."""
    return discover_inventory(
        region=region,
        profile=profile,
        session=session,
        include_s3=groups.s3,
        include_ec2=groups.ec2,
        include_iam=groups.iam,
        include_data=groups.data,
        include_compute=groups.compute,
        include_network=groups.network,
        force=True,
    )


def discover_inventory_all_regions(
    profile: str | None = None,
    *,
    regions: list[str] | None = None,
    include_s3: bool = True,
    include_ec2: bool = True,
    include_iam: bool = True,
    include_data: bool = True,
    include_compute: bool = True,
    include_network: bool = True,
    force: bool = False,
    session: Any = None,
) -> dict[str, Any]:
    """Estate-wide multi-region AWS inventory: fan out per region, merge once.

    The AWS counterpart of Azure's all-subscriptions fan-out. Region-scoped
    resources (EC2, RDS, DynamoDB, Lambda, EKS, ELB, VPC, KMS, Secrets, ECR,
    Redshift, SNS/SQS) are discovered concurrently across the resolved region set
    and **concatenated** (each item already carries its own ``location``).

    Global resources (S3 buckets, IAM roles/users, CloudFront) are region-
    agnostic, so they are enumerated **once** (against the default region) and
    **deduped** by ARN/id — a multi-region scan never inflates the identity or
    DSPM graph.

    Returns the SAME payload shape as :func:`discover_inventory` so the graph
    builder consumes it unchanged, with ``region`` set to ``"multi:<r1,r2,...>"``.

    Crash-safe: a failing region degrades to a warning and contributes nothing,
    never sinking the whole scan. boto3 absence / missing credentials degrade
    exactly as the single-region path does.
    """
    if not force and not inventory_enabled():
        return {**_empty_payload(region=""), "status": "disabled"}

    try:
        import boto3  # noqa: F401
    except ImportError:
        return {**_empty_payload(region=""), "status": "boto3_missing", "warnings": [_BOTO3_MISSING_WARNING]}

    # A brokered assumed-role session (e.g. a stored cloud-connection scan) is used as-is.
    if session is None:
        session, session_error = _open_session(boto3, region=None, profile=profile)
        if session_error is not None:
            return {**_empty_payload(region=""), "status": "no_credentials", "warnings": [session_error]}

    default_region = session.region_name or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
    warnings: list[str] = []
    region_list = _resolve_region_list(session, default_region, regions=regions, warnings=warnings)

    # Global (region-agnostic) S3 + IAM are enumerated ONCE; suppressing ec2/data/compute/network
    # here keeps the identity/DSPM graph from inflating across regions. CloudFront rides on the
    # per-region network pass and is deduped on merge.
    groups = _ServiceGroups(include_s3, include_ec2, include_iam, include_data, include_compute, include_network)
    global_region = region_list[0] if default_region not in region_list else default_region
    global_groups = groups._replace(ec2=False, data=False, compute=False, network=False)
    global_payload = _discover_inventory_for(global_groups, region=global_region, profile=profile, session=session)
    if global_payload.get("status") in {"boto3_missing", "no_credentials"}:
        return {**global_payload, "region": global_region}
    warnings.extend(global_payload.get("warnings", []))
    missing: list[dict[str, str]] = list(global_payload.get("missing_permissions", []) or [])

    region_groups = groups._replace(s3=False, iam=False)
    region_payloads = _scan_regions_concurrently(
        region_list, lambda region: _discover_inventory_for(region_groups, region=region, profile=profile, session=session), warnings
    )
    resources = _merge_region_payloads(region_list, region_payloads, warnings=warnings, missing=missing)
    for key in ("buckets", "roles", "users", "groups"):
        resources[key] = _dedupe_inventory_items(global_payload.get(key, []) or [], "arn")

    return _ok_payload(
        account_id=global_payload.get("account_id"),
        region=f"multi:{','.join(region_list)}",
        scope_regions=region_list,
        permissions_used=_permissions_used(groups, extra=("ec2:DescribeRegions",)),
        resources=resources,
        warnings=warnings,
        missing=missing,
        regions=region_list,
    )


def discover_all_account_inventories(
    profile: str | None = None,
    *,
    region: str | None = None,
    force: bool = False,
    session: Any = None,
    external_id: str | None = None,
    role_name: str | None = None,
) -> list[dict[str, Any]]:
    """Inventory EVERY member account of the AWS Organization (multi-account fan-out).

    The AWS counterpart of Azure's all-subscriptions and GCP's all-projects
    fan-out: enumerate the org's member accounts, assume the read-only role in
    each (``sts:AssumeRole`` from the management / delegated-admin account, keyless
    and short-lived), and run the per-account inventory against the assumed
    session. Results are partitioned by ``account_id`` so the graph keeps every
    account distinct under the org → OU ``CONTAINS`` tree and cross-account attack
    paths correlate.

    When ``session`` is supplied (brokered management-account session), org
    enumeration and member AssumeRole use that session. ``external_id`` and
    ``role_name`` thread into each member AssumeRole (Connections scans pass the
    connection ExternalId and ``auth_params.member_role_name`` / default).
    ``region`` scopes every per-account inventory (``None`` keeps each
    session's default region).

    Returns a LIST of per-account inventory payloads (the exact shape the graph
    builder's ``_iter_cloud_inventories`` consumes). Partial-permission tolerant:
    an account whose role cannot be assumed (or whose reads are denied) yields a
    non-``ok`` payload carrying its ``account_id`` + a warning, so it is counted
    in the scan summary and skipped in the graph rather than sinking the run.
    Falls back to a single ambient-credential inventory when no org is visible (a
    standalone account). Read-only throughout; never raises.
    """
    if not force and not inventory_enabled():
        return []

    try:
        import boto3  # noqa: F401
    except ImportError:
        return [
            {
                **_empty_payload(region=""),
                "status": "boto3_missing",
                "warnings": ["boto3 is required for AWS inventory. Install with: pip install 'agent-bom[aws]'"],
            }
        ]

    from agent_bom.cloud import aws_organizations

    try:
        account_ids = aws_organizations.list_member_account_ids(profile, force=True, session=session)
    except Exception as exc:  # noqa: BLE001 — org enumeration failure must degrade, not crash
        logger.warning("AWS org account enumeration failed: %s", sanitize_text(sanitize_discovery_warning(exc)))
        account_ids = []

    if not account_ids:
        # Standalone account (not in an org) or no org visibility — fall back to
        # the single ambient-credential inventory so the scan still produces data.
        return [discover_inventory(region=region, profile=profile, force=True, session=session)]

    cap = aws_organizations.max_accounts()
    capped = account_ids[:cap]
    if len(account_ids) > cap:
        logger.warning(
            "AWS multi-account scan capped at %d of %d accounts (set AGENT_BOM_AWS_MAX_ACCOUNTS to raise).",
            cap,
            len(account_ids),
        )

    def _scan(account_id: str) -> dict[str, Any]:
        try:
            assumed = aws_organizations.assume_account_session(
                account_id,
                profile=profile,
                role_name=role_name,
                external_id=external_id,
                base_session=session,
            )
        except Exception as exc:  # noqa: BLE001 — a denied account is skipped, not fatal
            return {
                **_empty_payload(region=""),
                "status": "access_denied",
                "account_id": account_id,
                "warnings": [f"Account {account_id} skipped: {sanitize_discovery_warning(exc)}"],
            }
        return discover_inventory(region=region, session=assumed, force=True)

    payloads: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=min(8, len(capped))) as executor:
        futures = {executor.submit(_scan, aid): aid for aid in capped}
        for future in as_completed(futures):
            account_id = futures[future]
            try:
                payloads.append(future.result())
            except Exception as exc:  # noqa: BLE001 — one account's failure must not sink the rest
                logger.warning("AWS inventory failed for account %s: %s", account_id, sanitize_text(sanitize_discovery_warning(exc)))
                payloads.append(
                    {
                        **_empty_payload(region=""),
                        "status": "error",
                        "account_id": account_id,
                        "warnings": [f"Account {account_id} failed: {sanitize_discovery_warning(exc)}"],
                    }
                )
    return payloads


def _collect_network_inventory(session: Any, region: str, found: dict[str, list[dict[str, Any]]], ctx: dict[str, Any]) -> None:
    """Network + edge stage: ELB, VPC, CloudFront, messaging, WAF, API Gateway, VPC plumbing, IPs."""
    account_id = ctx["account_id"]
    found["elb_load_balancers"] = _discover_elb(session, region, **ctx)
    found["vpcs"] = _discover_vpcs(session, region, **ctx)
    found["cloudfront_distributions"] = _discover_cloudfront(session, **ctx)
    found["messaging"] = _discover_messaging(session, region, **ctx)
    found["web_acls"] = _discover_waf(session, region, **ctx)
    found["api_gateways"] = _discover_api_gateways(session, region, **ctx)
    edge = _discover_network_edge(session, region, **ctx)
    for key in ("network_interfaces", "subnets", "nat_gateways", "internet_gateways", "vpc_endpoints", "route_tables", "network_acls"):
        found[key] = edge[key]
    found["ip_addresses"] = _discover_ip_addresses(
        session,
        region,
        account_id=account_id,
        network_interfaces=found["network_interfaces"],
        warnings=ctx["warnings"],
        missing=ctx["missing"],
    )


def _collect_inventory(
    session: Any,
    region: str,
    groups: _ServiceGroups,
    *,
    account_id: str | None,
    warnings: list[str],
    missing: list[dict[str, str]],
) -> dict[str, list[dict[str, Any]]]:
    """Run each enabled per-service collector in a fixed order; returns resources by payload key."""
    ctx: dict[str, Any] = {"account_id": account_id, "warnings": warnings, "missing": missing}
    found: dict[str, list[dict[str, Any]]] = {}
    if groups.s3:
        found["buckets"] = _discover_s3_buckets(session, **ctx)
    if groups.ec2:
        found["instances"], found["security_groups"] = _discover_ec2(session, region, **ctx)
    if groups.iam:
        found["roles"], found["users"], found["groups"] = _discover_iam(session, **ctx)
    if groups.data:
        found["rds_instances"] = _discover_rds(session, region, **ctx)
        found["dynamodb_tables"] = _discover_dynamodb(session, region, **ctx)
        found["kms_keys"] = _discover_kms(session, region, **ctx)
        found["secrets"] = _discover_secrets(session, region, **ctx)
        found["redshift_clusters"] = _discover_redshift(session, region, **ctx)
    if groups.compute:
        found["lambda_functions"] = _discover_lambda(session, region, **ctx)
        found["eks_clusters"] = _discover_eks(session, region, **ctx)
        found["ecr_repositories"] = _discover_ecr(session, region, **ctx)
    if groups.network:
        _collect_network_inventory(session, region, found, ctx)
    return found


def discover_inventory(
    region: str | None = None,
    profile: str | None = None,
    *,
    include_s3: bool = True,
    include_ec2: bool = True,
    include_iam: bool = True,
    include_data: bool = True,
    include_compute: bool = True,
    include_network: bool = True,
    force: bool = False,
    session: Any = None,
) -> dict[str, Any]:
    """Enumerate the general AWS estate (S3, EC2 + security groups, IAM).

    Returns a JSON-serialisable inventory payload destined for
    ``report_json["cloud_inventory"]``; the graph builder turns it into nodes.

    The payload always carries a ``status`` string so callers can surface a
    clear reason when nothing was enumerated:

    - ``"disabled"``        — the feature flag is off and ``force`` was not set.
    - ``"boto3_missing"``   — boto3 is not installed.
    - ``"no_credentials"``  — no AWS credentials resolved.
    - ``"ok"``              — enumeration ran (possibly with per-service warnings).

    When ``session`` is supplied (e.g. the read-only session the credential
    broker assumes from a stored connection), it is used as-is instead of the
    local default chain. An explicit ``region`` still wins over the session's
    default region (the multi-region fan-out reuses one brokered session and
    scans each region's clients in turn); ``profile`` is ignored with a session.

    Never raises: boto3 absence, missing credentials, and per-service access
    denials all degrade to an empty (or partial) inventory plus warnings.
    """
    empty = _empty_payload(region=region or "")

    if not force and not inventory_enabled():
        return empty

    try:
        import boto3  # noqa: F401
        from botocore.exceptions import NoCredentialsError
    except ImportError:
        return {**empty, "status": "boto3_missing", "warnings": [_BOTO3_MISSING_WARNING]}

    if session is None:
        session, session_error = _open_session(boto3, region=region, profile=profile)
        if session_error is not None:
            return {**empty, "status": "no_credentials", "warnings": [session_error]}

    # An explicit region wins even when a session is injected — the multi-region
    # fan-out reuses one brokered session but scans each region's clients in turn.
    resolved_region = region or session.region_name or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
    account_id = _resolve_account_id(session)

    groups = _ServiceGroups(include_s3, include_ec2, include_iam, include_data, include_compute, include_network)
    warnings: list[str] = []
    missing: list[dict[str, str]] = []
    try:
        resources = _collect_inventory(session, resolved_region, groups, account_id=account_id, warnings=warnings, missing=missing)
    except NoCredentialsError:
        return {
            **empty,
            "status": "no_credentials",
            "warnings": ["AWS credentials not found. Configure via env vars, ~/.aws/credentials, IAM role, or SSO."],
        }

    return _ok_payload(
        account_id=account_id,
        region=resolved_region,
        scope_regions=[resolved_region] if resolved_region else [],
        permissions_used=_permissions_used(groups),
        resources=resources,
        warnings=warnings,
        missing=missing,
    )


# ---------------------------------------------------------------------------
# S3 buckets (estate-wide ListBuckets)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# EC2 instances + security groups (estate-wide Describe*)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# IAM roles + users (estate-wide ListRoles / ListUsers)
# ---------------------------------------------------------------------------


def _discover_iam(
    session: Any,
    *,
    account_id: str | None,
    warnings: list[str],
    missing: list[dict[str, str]] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Enumerate all IAM roles, users, and groups in the account (read-only).

    Each principal carries attached managed-policy metadata classified to a
    privilege level (admin/write/read) so the effective-permissions overlay can
    consume it without an additional fetch. Roles also carry their trust
    principals from the AssumeRole policy document. Groups carry their attached
    and inline policies plus their member users; each user carries the names of
    the groups it belongs to so the graph can attribute group-granted access to
    the member — group-based access is one of the most common privilege paths.
    """
    iam = session.client("iam")
    roles: list[dict[str, Any]] = []
    users: list[dict[str, Any]] = []
    groups: list[dict[str, Any]] = []

    raw_roles: list[dict[str, Any]] = []
    try:
        role_paginator = iam.get_paginator("list_roles")
        for page in role_paginator.paginate():
            for role in page.get("Roles", []):
                if isinstance(role, dict):
                    raw_roles.append(role)
    except Exception as exc:  # noqa: BLE001 — one failed IAM list must not sink the scan
        record_discovery_failure(
            exc=exc, resource_type="IAM roles", permission="iam:ListRoles", cloud="aws", warnings=warnings, missing=missing
        )

    # Normalize policy/trust evidence without serially polling asynchronous
    # Access Advisor jobs. The bounded usage subset is started together and then
    # polled in shared backoff rounds, so one estate waits once rather than once
    # per role.
    for role in raw_roles:
        roles.append(
            _normalize_role(
                iam,
                role,
                account_id=account_id,
                warnings=warnings,
                collect_usage=False,
            )
        )
    usage_inputs = [
        (
            str(role.get("Arn") or ""),
            str(role.get("RoleName") or ""),
            role,
        )
        for role in raw_roles[:_MAX_IAM_USAGE_ROLES]
        if str(role.get("Arn") or "") and str(role.get("RoleName") or "")
    ]
    usage_by_arn = collect_iam_roles_usage_evidence(
        iam,
        usage_inputs,
        max_access_advisor_polls=_MAX_ACCESS_ADVISOR_POLLS,
        max_access_advisor_pages=_MAX_ACCESS_ADVISOR_PAGES,
    )
    for role in roles[:_MAX_IAM_USAGE_ROLES]:
        principal_arn = str(role.get("arn") or "")
        evidence = usage_by_arn.get(principal_arn)
        if evidence is not None:
            role["usage_evidence"] = evidence.to_dict()

    try:
        group_paginator = iam.get_paginator("list_groups")
        for page in group_paginator.paginate():
            for group in page.get("Groups", []):
                groups.append(_normalize_group(iam, group, account_id=account_id, warnings=warnings))
    except Exception as exc:  # noqa: BLE001 — one failed IAM list must not sink the scan
        record_discovery_failure(
            exc=exc, resource_type="IAM groups", permission="iam:ListGroups", cloud="aws", warnings=warnings, missing=missing
        )

    try:
        user_paginator = iam.get_paginator("list_users")
        for page in user_paginator.paginate():
            for user in page.get("Users", []):
                users.append(_normalize_user(iam, user, account_id=account_id, warnings=warnings))
    except Exception as exc:  # noqa: BLE001 — one failed IAM list must not sink the scan
        record_discovery_failure(
            exc=exc, resource_type="IAM users", permission="iam:ListUsers", cloud="aws", warnings=warnings, missing=missing
        )

    return roles, users, groups


# ---------------------------------------------------------------------------
# Network edge: WAF, API Gateway, ENIs, NAT/IGW, subnets, route tables, IPs
# ---------------------------------------------------------------------------


__all__ = [
    "ALL_REGIONS_ENV_FLAG",
    "ALL_REGIONS_SENTINEL",
    "INVENTORY_ENV_FLAG",
    "REGIONS_ENV_VAR",
    "all_regions_enabled",
    "discover_all_account_inventories",
    "discover_inventory",
    "discover_inventory_all_regions",
    "inventory_enabled",
    "is_all_regions",
]
