"""AWS S3, EC2 and IAM principal normalization for the inventory facade."""

from __future__ import annotations

import importlib
from typing import Any

from ..aws import _account_id_from_arn, _classify_policy_actions, _extract_trust_principals, _policy_actions_from_document
from ..aws_iam_collector import collect_iam_role_usage_evidence
from ..aws_iam_evidence import IamRoleUsageEvidence, UsageEvidenceState
from ..normalization import sanitize_discovery_warning
from ._base import _INTERNET_CIDRS, _INTERNET_IPV6, _MAX_ACCESS_ADVISOR_PAGES, _MAX_ACCESS_ADVISOR_POLLS, _iso, record_discovery_failure

_FACADE = "agent_bom.cloud.aws_inventory"


def _seams() -> Any:
    """Resolve patchable collaborators through the public facade at call time."""
    return importlib.import_module(_FACADE)


def _discover_s3_buckets(
    session: Any, *, account_id: str | None, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate every S3 bucket in the account (read-only).

    Public-access posture is read from PolicyStatus, the bucket ACL, and the
    bucket- and account-level PublicAccessBlock — never from object contents. Buckets become ``DATA_STORE``
    nodes so DSPM and exposure overlays apply.
    """
    s3 = session.client("s3")
    buckets: list[dict[str, Any]] = []

    try:
        listed = s3.list_buckets().get("Buckets", [])
    except Exception as exc:  # noqa: BLE001 — one failed S3 list must not sink the scan
        record_discovery_failure(
            exc=exc, resource_type="S3 buckets", permission="s3:ListAllMyBuckets", cloud="aws", warnings=warnings, missing=missing
        )
        return buckets

    account_block = _account_public_access_block(session, account_id, warnings) if listed else {}
    for bucket in listed:
        name = str(bucket.get("Name", "") or "").strip()
        if not name:
            continue
        arn = f"arn:aws:s3:::{name}"
        location = _seams()._bucket_location(s3, name, warnings)
        publicly_accessible = _seams()._bucket_public(s3, name, warnings, account_block=account_block)
        tags = _seams()._bucket_tags(s3, name, warnings)
        bucket_record = {
            "name": name,
            "arn": arn,
            "location": location,
            "publicly_accessible": publicly_accessible,
            "tags": tags,
            "account_id": account_id or "",
            "created_at": _iso(bucket.get("CreationDate")),
        }
        try:
            from agent_bom.cloud.s3_data_classifier import classify_s3_bucket, s3_sampling_enabled

            if s3_sampling_enabled():
                bucket_record["content_classification"] = classify_s3_bucket(s3, name).to_dict()
        except Exception as exc:  # noqa: BLE001 — sampling is optional and must not sink inventory
            warnings.append(f"Could not classify S3 bucket {name}: {sanitize_discovery_warning(exc)}")
        buckets.append(bucket_record)
    return buckets


def _bucket_location(s3: Any, name: str, warnings: list[str]) -> str:
    try:
        constraint = s3.get_bucket_location(Bucket=name).get("LocationConstraint")
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not read location for S3 bucket {name}: {sanitize_discovery_warning(exc)}")
        return ""
    # us-east-1 reports a null LocationConstraint by AWS convention.
    return str(constraint or "us-east-1")


_PUBLIC_ACL_GRANTEE_URIS = frozenset(
    {
        "http://acs.amazonaws.com/groups/global/AllUsers",
        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
    }
)


def _account_public_access_block(session: Any, account_id: str | None, warnings: list[str]) -> dict[str, Any]:
    """Read the account-level S3 Block Public Access settings (read-only).

    Returns ``{}`` when the account has no configuration or it cannot be read,
    which leaves bucket-level evidence in charge.
    """
    if not account_id:
        return {}
    try:
        client = session.client("s3control")
        block = client.get_public_access_block(AccountId=account_id).get("PublicAccessBlockConfiguration", {})
    except Exception as exc:  # noqa: BLE001 — account block is optional evidence
        if "NoSuchPublicAccessBlock" not in str(exc):
            warnings.append(f"Could not read account-level S3 public-access block: {sanitize_discovery_warning(exc)}")
        return {}
    return block if isinstance(block, dict) else {}


def _bucket_public(s3: Any, name: str, warnings: list[str], *, account_block: dict[str, Any] | None = None) -> bool:
    """Whether the bucket is effectively public, from posture APIs only.

    Public requires an actual grant — a bucket policy S3 evaluates as public
    (``GetBucketPolicyStatus.IsPublic``) or an ACL grant to AllUsers /
    AuthenticatedUsers — that is not neutralized by an effective Block Public
    Access setting: ``RestrictPublicBuckets`` neutralizes a public policy and
    ``IgnorePublicAcls`` neutralizes public ACLs, at bucket OR account level.
    A missing or partial block with no grant is not public. Read errors degrade
    to "no grant observed" with a warning, never a guess that inflates risk.
    """
    policy_public = False
    try:
        status = s3.get_bucket_policy_status(Bucket=name).get("PolicyStatus", {})
        policy_public = bool(status.get("IsPublic"))
    except Exception as exc:  # noqa: BLE001
        # NoSuchBucketPolicy is normal (no policy attached) — only warn otherwise.
        if "NoSuchBucketPolicy" not in str(exc):
            warnings.append(f"Could not read policy status for S3 bucket {name}: {sanitize_discovery_warning(exc)}")

    acl_public = False
    try:
        grants = s3.get_bucket_acl(Bucket=name).get("Grants", [])
        acl_public = any(
            isinstance(grant, dict)
            and isinstance(grant.get("Grantee"), dict)
            and str(grant["Grantee"].get("URI") or "") in _PUBLIC_ACL_GRANTEE_URIS
            for grant in grants or []
        )
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not read ACL for S3 bucket {name}: {sanitize_discovery_warning(exc)}")

    if not policy_public and not acl_public:
        return False

    bucket_block: dict[str, Any] = {}
    try:
        bucket_block = s3.get_public_access_block(Bucket=name).get("PublicAccessBlockConfiguration", {}) or {}
    except Exception as exc:  # noqa: BLE001
        if "NoSuchPublicAccessBlock" not in str(exc):
            warnings.append(f"Could not read public-access block for S3 bucket {name}: {sanitize_discovery_warning(exc)}")
    account = account_block or {}

    def _effective(key: str) -> bool:
        return bool(bucket_block.get(key)) or bool(account.get(key))

    policy_exposes = policy_public and not _effective("RestrictPublicBuckets")
    acl_exposes = acl_public and not _effective("IgnorePublicAcls")
    return policy_exposes or acl_exposes


def _bucket_tags(s3: Any, name: str, warnings: list[str]) -> dict[str, str]:
    try:
        tag_set = s3.get_bucket_tagging(Bucket=name).get("TagSet", [])
    except Exception:  # noqa: BLE001
        # NoSuchTagSet is normal (no tags) — silently skip.
        return {}
    return {str(t.get("Key", "")): str(t.get("Value", "")) for t in tag_set if t.get("Key")}


def _discover_ec2(
    session: Any,
    region: str,
    *,
    account_id: str | None,
    warnings: list[str],
    missing: list[dict[str, str]] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Enumerate all EC2 instances and security groups in *region* (read-only).

    Unlike :func:`agent_bom.cloud.aws._discover_ec2_instances`, this is NOT
    tag-filtered — it captures the whole estate so resources with no CIS finding
    still enter the graph.
    """
    ec2 = session.client("ec2", region_name=region)
    instances: list[dict[str, Any]] = []
    security_groups: list[dict[str, Any]] = []

    try:
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    instances.append(_normalize_instance(instance, region=region, account_id=account_id))
    except Exception as exc:  # noqa: BLE001 — one failed EC2 describe must not sink the scan
        record_discovery_failure(
            exc=exc, resource_type="EC2 instances", permission="ec2:DescribeInstances", cloud="aws", warnings=warnings, missing=missing
        )

    try:
        sg_paginator = ec2.get_paginator("describe_security_groups")
        for page in sg_paginator.paginate():
            for group in page.get("SecurityGroups", []):
                security_groups.append(_normalize_security_group(group, region=region, account_id=account_id))
    except Exception as exc:  # noqa: BLE001 — one failed SG describe must not sink the scan
        record_discovery_failure(
            exc=exc,
            resource_type="EC2 security groups",
            permission="ec2:DescribeSecurityGroups",
            cloud="aws",
            warnings=warnings,
            missing=missing,
        )

    return instances, security_groups


def _normalize_instance(instance: dict[str, Any], *, region: str, account_id: str | None) -> dict[str, Any]:
    instance_id = str(instance.get("InstanceId", "") or "")
    tags = {str(t.get("Key", "")): str(t.get("Value", "")) for t in instance.get("Tags", []) if t.get("Key")}
    sg_ids: list[str] = []
    for group in instance.get("SecurityGroups", []) or []:
        gid = group.get("GroupId") if isinstance(group, dict) else None
        if gid and gid not in sg_ids:
            sg_ids.append(str(gid))
    state = instance.get("State", {})
    return {
        "instance_id": instance_id,
        "name": tags.get("Name", instance_id),
        "instance_type": str(instance.get("InstanceType", "") or ""),
        "image_id": str(instance.get("ImageId", "") or ""),
        "state": str(state.get("Name", "") or "") if isinstance(state, dict) else "",
        "region": region,
        "account_id": account_id or "",
        "vpc_id": str(instance.get("VpcId", "") or ""),
        "subnet_id": str(instance.get("SubnetId", "") or ""),
        "public_ip": str(instance.get("PublicIpAddress", "") or ""),
        "private_ip": str(instance.get("PrivateIpAddress", "") or ""),
        "iam_instance_profile": str((instance.get("IamInstanceProfile") or {}).get("Arn", "") or ""),
        "security_group_ids": sg_ids,
        "tags": tags,
        "launched_at": _iso(instance.get("LaunchTime")),
    }


def _normalize_security_group(group: dict[str, Any], *, region: str, account_id: str | None) -> dict[str, Any]:
    group_id = str(group.get("GroupId", "") or "")
    exposure = _security_group_internet_exposure(group)
    return {
        "group_id": group_id,
        "name": str(group.get("GroupName", "") or group_id),
        "description": str(group.get("Description", "") or ""),
        "vpc_id": str(group.get("VpcId", "") or ""),
        "region": region,
        "account_id": account_id or "",
        "internet_exposed": bool(exposure),
        "network_exposure": exposure,
    }


def _security_group_internet_exposure(group: dict[str, Any]) -> list[dict[str, Any]]:
    """Return internet-facing ingress rules in the CNAPP overlay's shape.

    Each entry is ``{"scope": "internet", "from_port", "to_port", "protocol"}``
    so :func:`agent_bom.graph.cnapp_overlay.apply_cnapp_overlay` can attach
    structured exposure without keyword-matching free text.
    """
    exposure: list[dict[str, Any]] = []
    for rule in group.get("IpPermissions", []) or []:
        if not isinstance(rule, dict):
            continue
        open_to_world = any(
            str(r.get("CidrIp", "")) in _INTERNET_CIDRS for r in rule.get("IpRanges", []) or [] if isinstance(r, dict)
        ) or any(str(r.get("CidrIpv6", "")) in _INTERNET_IPV6 for r in rule.get("Ipv6Ranges", []) or [] if isinstance(r, dict))
        if not open_to_world:
            continue
        exposure.append(
            {
                "scope": "internet",
                "from_port": rule.get("FromPort"),
                "to_port": rule.get("ToPort"),
                "protocol": str(rule.get("IpProtocol", "") or "tcp"),
            }
        )
    return exposure


def _normalize_role(
    iam: Any,
    role: dict[str, Any],
    *,
    account_id: str | None,
    warnings: list[str],
    collect_usage: bool = True,
) -> dict[str, Any]:
    role_name = str(role.get("RoleName", "") or "")
    role_arn = str(role.get("Arn", "") or "")
    policies = _attached_policies(iam, "role", role_name, warnings=warnings)
    policies += _inline_policies(iam, "role", role_name, warnings=warnings)
    trust_principals = _extract_trust_principals(
        role.get("AssumeRolePolicyDocument"),
        account_id=account_id or _account_id_from_arn(role_arn),
    )
    if collect_usage and role_name and role_arn:
        usage_evidence = collect_iam_role_usage_evidence(
            iam,
            principal_arn=role_arn,
            role_name=role_name,
            role_snapshot=role,
            max_access_advisor_polls=_MAX_ACCESS_ADVISOR_POLLS,
            max_access_advisor_pages=_MAX_ACCESS_ADVISOR_PAGES,
        )
    else:
        usage_evidence = IamRoleUsageEvidence(
            principal_arn=role_arn,
            usage_state=UsageEvidenceState.UNAVAILABLE,
            diagnostic=("role_collection_budget_exhausted" if not collect_usage else "role_identity_unavailable"),
        )
    return {
        "principal_type": "iam-role",
        "name": role_name,
        "arn": role_arn,
        "account_id": account_id or _account_id_from_arn(role_arn),
        "path": str(role.get("Path", "") or ""),
        "policies": policies,
        "trust_principals": trust_principals,
        "usage_evidence": usage_evidence.to_dict(),
        "privilege_level": _highest_privilege(policies),
        "created_at": _iso(role.get("CreateDate")),
    }


def _normalize_user(iam: Any, user: dict[str, Any], *, account_id: str | None, warnings: list[str]) -> dict[str, Any]:
    user_name = str(user.get("UserName", "") or "")
    user_arn = str(user.get("Arn", "") or "")
    policies = _attached_policies(iam, "user", user_name, warnings=warnings)
    policies += _inline_policies(iam, "user", user_name, warnings=warnings)
    return {
        "principal_type": "user",
        "name": user_name,
        "arn": user_arn,
        "account_id": account_id or _account_id_from_arn(user_arn),
        "path": str(user.get("Path", "") or ""),
        "policies": policies,
        "groups": _groups_for_user(iam, user_name, warnings=warnings),
        "privilege_level": _highest_privilege(policies),
        "created_at": _iso(user.get("CreateDate")),
    }


def _normalize_group(iam: Any, group: dict[str, Any], *, account_id: str | None, warnings: list[str]) -> dict[str, Any]:
    """Normalize one IAM group with its attached + inline policies and members.

    A group's attached/inline policies grant every member their access, so the
    group carries the same policy shape as a user/role (classified to a privilege
    level) plus the list of member users. The graph builder turns the group into
    a ``GROUP`` node, attaches its policies, and wires ``MEMBER_OF`` edges from
    each member so the effective-permissions overlay attributes group-granted
    access to the member.
    """
    group_name = str(group.get("GroupName", "") or "")
    group_arn = str(group.get("Arn", "") or "")
    policies = _attached_policies(iam, "group", group_name, warnings=warnings)
    policies += _inline_policies(iam, "group", group_name, warnings=warnings)
    return {
        "principal_type": "group",
        "name": group_name,
        "arn": group_arn,
        "account_id": account_id or _account_id_from_arn(group_arn),
        "path": str(group.get("Path", "") or ""),
        "policies": policies,
        "members": _group_members(iam, group_name, warnings=warnings),
        "privilege_level": _highest_privilege(policies),
        "created_at": _iso(group.get("CreateDate")),
    }


def _group_members(iam: Any, group_name: str, *, warnings: list[str]) -> list[dict[str, str]]:
    """Return the member users of an IAM group (read-only ``GetGroup``).

    Each member is recorded by ARN + name + ``user`` type so the builder can wire
    a ``MEMBER_OF`` edge to the existing user node. Degrades to an empty list plus
    a warning on error; never blocks enumeration.
    """
    if not group_name:
        return []
    members: list[dict[str, str]] = []
    try:
        paginator = iam.get_paginator("get_group")
        for page in paginator.paginate(GroupName=group_name):
            for user in page.get("Users", []) or []:
                arn = str(user.get("Arn", "") or "")
                name = str(user.get("UserName", "") or "")
                ident = arn or name
                if ident:
                    members.append({"id": ident, "name": name or ident, "type": "user"})
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"IAM group membership enumeration skipped for {group_name}: {sanitize_discovery_warning(exc)}")
    return members


def _groups_for_user(iam: Any, user_name: str, *, warnings: list[str]) -> list[str]:
    """Return the names of the IAM groups a user belongs to (read-only).

    Group membership is the link that carries a group's policies to the member,
    so capturing it lets the graph attribute group-granted access to each user.
    Degrades to an empty list plus a warning on error; never blocks enumeration.
    """
    if not user_name:
        return []
    names: list[str] = []
    try:
        paginator = iam.get_paginator("list_groups_for_user")
        for page in paginator.paginate(UserName=user_name):
            for group in page.get("Groups", []) or []:
                name = str(group.get("GroupName", "") or "")
                if name:
                    names.append(name)
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"IAM group-membership lookup skipped for user {user_name}: {sanitize_discovery_warning(exc)}")
    return names


def _attached_policies(iam: Any, principal_kind: str, principal_name: str, *, warnings: list[str]) -> list[dict[str, Any]]:
    """Return attached managed policies with a classified privilege level."""
    if not principal_name:
        return []
    paginator_name = f"list_attached_{principal_kind}_policies"
    kwarg = {"role": "RoleName", "user": "UserName", "group": "GroupName"}[principal_kind]
    policies: list[dict[str, Any]] = []
    try:
        paginator = iam.get_paginator(paginator_name)
        for page in paginator.paginate(**{kwarg: principal_name}):
            for policy in page.get("AttachedPolicies", []):
                policy_arn = str(policy.get("PolicyArn", "") or "")
                policy_name = str(policy.get("PolicyName", "") or policy_arn)
                if not (policy_arn or policy_name):
                    continue
                privilege_level, document = _policy_privilege_and_document(iam, policy_arn, policy_name, warnings=warnings)
                entry: dict[str, Any] = {
                    "policy_id": policy_arn,
                    "policy_name": policy_name,
                    "attachment_type": "managed",
                    "privilege_level": privilege_level,
                    "source_field": f"ListAttached{principal_kind.capitalize()}Policies.AttachedPolicies",
                }
                # Carry the raw document so the effective-permissions overlay can run
                # REAL policy evaluation (customer-managed only; AWS-managed policies
                # are name-classified without a fetch and have no document to attach).
                if isinstance(document, dict):
                    entry["policy_document"] = document
                policies.append(entry)
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"IAM policy enumeration skipped for {principal_kind} {principal_name}: {sanitize_discovery_warning(exc)}")
    return policies


def _inline_policies(iam: Any, principal_kind: str, principal_name: str, *, warnings: list[str]) -> list[dict[str, Any]]:
    """Return inline policies with a classified privilege level (read-only).

    Inline policies attach directly to a single principal and never appear in
    ``list_attached_*`` — yet they can silently grant admin, so a posture scan
    must read them. Lists the inline names, fetches each document, and classifies
    by Allow actions. Degrades to a warning on error; never blocks enumeration.
    """
    if not principal_name:
        return []
    list_op = f"list_{principal_kind}_policies"
    kwarg = {"role": "RoleName", "user": "UserName", "group": "GroupName"}[principal_kind]
    policies: list[dict[str, Any]] = []
    try:
        get_doc = getattr(iam, {"role": "get_role_policy", "user": "get_user_policy", "group": "get_group_policy"}[principal_kind])
        paginator = iam.get_paginator(list_op)
        for page in paginator.paginate(**{kwarg: principal_name}):
            for name in page.get("PolicyNames", []):
                if not name:
                    continue
                privilege = "unknown"
                document: Any = None
                try:
                    document = get_doc(**{kwarg: principal_name, "PolicyName": name}).get("PolicyDocument")
                    privilege = _classify_policy_actions(_policy_actions_from_document(document))
                except Exception as exc:  # noqa: BLE001
                    short = sanitize_discovery_warning(exc)
                    warnings.append(f"IAM inline policy doc skipped for {principal_kind} {principal_name}/{name}: {short}")
                entry: dict[str, Any] = {
                    "policy_id": f"{principal_name}/{name}",
                    "policy_name": str(name),
                    "attachment_type": "inline",
                    "privilege_level": privilege,
                    "source_field": f"List{principal_kind.capitalize()}Policies.PolicyNames",
                }
                # Inline documents are already read for classification; retain the raw
                # document so the overlay can evaluate it (an inline "*:*" is a common
                # benignly-named admin path the name heuristic cannot see).
                if isinstance(document, dict):
                    entry["policy_document"] = document
                policies.append(entry)
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"IAM inline policy enumeration skipped for {principal_kind} {principal_name}: {sanitize_discovery_warning(exc)}")
    return policies


# Canonical AWS-managed policy name → privilege level (no fetch needed). Mirrors
# the table in :mod:`agent_bom.cloud.aws`.
_AWS_MANAGED_PRIVILEGE: dict[str, str] = {
    "administratoraccess": "admin",
    "iamfullaccess": "admin",
    "poweruseraccess": "write",
    "readonlyaccess": "read",
    "viewonlyaccess": "read",
    "securityaudit": "read",
}


def _policy_privilege_and_document(
    iam: Any, policy_arn: str, policy_name: str, *, warnings: list[str]
) -> tuple[str, dict[str, Any] | None]:
    """Classify an attached policy and return its raw document when fetched.

    AWS-managed policies are classified by canonical name (no API call), so no
    document is returned for them (``None``). Customer-managed policies are
    fetched and classified by their Allow actions, and the raw document is
    returned so the effective-permissions overlay can evaluate it.
    Degrades to ``("unknown", None)`` on any error — never blocks enumeration.
    """
    name_key = (policy_name or policy_arn).rsplit("/", 1)[-1].lower()
    if ":aws:policy/" in policy_arn and name_key in _AWS_MANAGED_PRIVILEGE:
        return _AWS_MANAGED_PRIVILEGE[name_key], None
    if ":aws:policy/" in policy_arn:
        if "fullaccess" in name_key or "admin" in name_key:
            return "admin", None
        if "readonly" in name_key or "viewonly" in name_key:
            return "read", None
    try:
        version_id = iam.get_policy(PolicyArn=policy_arn)["Policy"]["DefaultVersionId"]
        document = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)["PolicyVersion"]["Document"]
        return _classify_policy_actions(_policy_actions_from_document(document)), document if isinstance(document, dict) else None
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"IAM policy action lookup skipped for {policy_name or policy_arn}: {sanitize_discovery_warning(exc)}")
        return "unknown", None


_PRIVILEGE_RANK = {"admin": 3, "write": 2, "read": 1, "unknown": 0}


def _highest_privilege(policies: list[dict[str, Any]]) -> str:
    """Return the most-privileged level across a principal's attached policies."""
    best = "unknown"
    for policy in policies:
        level = str(policy.get("privilege_level", "unknown"))
        if _PRIVILEGE_RANK.get(level, 0) > _PRIVILEGE_RANK.get(best, 0):
            best = level
    return best
