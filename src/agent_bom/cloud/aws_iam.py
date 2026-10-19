"""Cloud aws iam helpers."""

from __future__ import annotations

from typing import Any

from agent_bom.models import Agent

from .normalization import (
    sanitize_discovery_warning,
)


def _role_name_from_arn(role_arn: str) -> str:
    """Extract the IAM role name/path segment accepted by GetRole."""
    marker = ":role/"
    if marker not in role_arn:
        return role_arn.rsplit("/", 1)[-1].strip()
    return role_arn.split(marker, 1)[1].strip()


def _account_id_from_arn(arn: str) -> str:
    parts = arn.split(":")
    return parts[4] if len(parts) > 4 else ""


def _principal_type_from_aws_principal(principal_id: str) -> str:
    if principal_id.endswith(":root"):
        return "account"
    if ":role/" in principal_id:
        return "iam-role"
    if ":user/" in principal_id:
        return "user"
    return "account" if principal_id.isdigit() else "federated-identity"


def _principal_name_from_id(principal_id: str) -> str:
    if principal_id.endswith(":root"):
        account_id = _account_id_from_arn(principal_id)
        return account_id or principal_id
    return principal_id.rsplit("/", 1)[-1]


def _principal_values(value: Any) -> list[str]:
    if value in (None, ""):
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value if str(item or "").strip()]
    return [str(value)]


def _extract_trust_principals(policy_document: Any, *, account_id: str | None) -> list[dict[str, str]]:
    """Extract low-risk trust principals from an AssumeRole policy document."""
    if not isinstance(policy_document, dict):
        return []
    statements = policy_document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return []

    entries: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for statement in statements:
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        principal = statement.get("Principal")
        if not isinstance(principal, dict):
            continue
        for raw_value in _principal_values(principal.get("AWS")):
            if raw_value == "*":
                continue
            principal_type = _principal_type_from_aws_principal(raw_value)
            principal_account = raw_value if raw_value.isdigit() else _account_id_from_arn(raw_value)
            relationship = "cross_account_trust" if account_id and principal_account and principal_account != account_id else "trusts"
            key = (principal_type, raw_value)
            if key in seen:
                continue
            seen.add(key)
            entries.append(
                {
                    "principal_type": principal_type,
                    "principal_id": principal_account if principal_type == "account" and principal_account else raw_value,
                    "principal_name": _principal_name_from_id(raw_value),
                    "relationship": relationship,
                    "source_field": "AssumeRolePolicyDocument.Principal.AWS",
                }
            )
        for raw_value in _principal_values(principal.get("Service")):
            key = ("service-principal", raw_value)
            if key in seen:
                continue
            seen.add(key)
            entries.append(
                {
                    "principal_type": "service-principal",
                    "principal_id": raw_value,
                    "principal_name": raw_value,
                    "relationship": "trusts",
                    "source_field": "AssumeRolePolicyDocument.Principal.Service",
                }
            )
        for raw_value in _principal_values(principal.get("Federated")):
            key = ("federated-identity", raw_value)
            if key in seen:
                continue
            seen.add(key)
            entries.append(
                {
                    "principal_type": "federated-identity",
                    "principal_id": raw_value,
                    "principal_name": _principal_name_from_id(raw_value),
                    "relationship": "trusts",
                    "source_field": "AssumeRolePolicyDocument.Principal.Federated",
                }
            )
    return entries


# Canonical AWS-managed policy → privilege level (name is authoritative, no fetch needed).
_AWS_MANAGED_PRIVILEGE: dict[str, str] = {
    "administratoraccess": "admin",
    "iamfullaccess": "admin",
    "poweruseraccess": "write",
    "readonlyaccess": "read",
    "viewonlyaccess": "read",
    "securityaudit": "read",
}

# Action verbs that imply write/mutate (vs read).
_WRITE_VERBS = ("create", "delete", "put", "update", "modify", "write", "attach", "detach", "remove", "set", "tag", "untag", "run")


def _classify_policy_actions(actions: list[str]) -> str:
    """Classify an action list as admin / write / read."""
    admin = {"*", "*:*", "iam:*"}
    has_write = False
    for raw in actions:
        action = str(raw).lower()
        if action in admin or action.endswith(":*") and action.startswith("iam"):
            return "admin"
        if action == "*":
            return "admin"
        verb = action.split(":", 1)[-1]
        if any(verb.startswith(w) for w in _WRITE_VERBS) or action.endswith(":*"):
            has_write = True
    return "write" if has_write else "read"


def _policy_actions_from_document(document: Any) -> list[str]:
    """Extract the Action strings from an IAM policy document (Allow statements)."""
    actions: list[str] = []
    statements = document.get("Statement", []) if isinstance(document, dict) else []
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
            continue
        raw = stmt.get("Action", [])
        actions.extend([raw] if isinstance(raw, str) else [a for a in raw if isinstance(a, str)])
    return actions


def _policy_privilege(iam: Any, policy_arn: str, policy_name: str, *, warnings: list[str]) -> tuple[str, list[str], dict[str, Any] | None]:
    """Return (privilege_level, sampled_actions, raw_document) for an attached policy.

    AWS-managed policies are classified by their canonical name (no API call) and
    carry no document. Customer-managed policies are fetched and classified by
    their actions, and the raw document is returned so the effective-permissions
    overlay can run real policy evaluation.
    Degrades to ('unknown', [], None) on any error — never blocks discovery.
    """
    name_key = (policy_name or policy_arn).rsplit("/", 1)[-1].lower()
    if ":aws:policy/" in policy_arn and name_key in _AWS_MANAGED_PRIVILEGE:
        return _AWS_MANAGED_PRIVILEGE[name_key], [], None
    if ":aws:policy/" in policy_arn:
        # Unknown AWS-managed policy — name still hints at privilege.
        if "fullaccess" in name_key or "admin" in name_key:
            return "admin", [], None
        if "readonly" in name_key or "viewonly" in name_key:
            return "read", [], None
    try:
        version_id = iam.get_policy(PolicyArn=policy_arn)["Policy"]["DefaultVersionId"]
        document = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)["PolicyVersion"]["Document"]
        actions = _policy_actions_from_document(document)
        return _classify_policy_actions(actions), sorted(set(actions))[:25], document if isinstance(document, dict) else None
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"IAM policy action lookup skipped for {policy_name or policy_arn}: {sanitize_discovery_warning(exc)}")
        return "unknown", [], None


def _enrich_agents_with_iam(session: Any, agents: list[Agent], *, account_id: str | None, warnings: list[str]) -> None:
    """Attach live IAM role policy/trust metadata to discovered principals."""

    def _cloud_principal_metadata(agent: Agent) -> dict[str, object] | None:
        value = agent.metadata.get("cloud_principal")
        return value if isinstance(value, dict) else None

    role_arns = sorted(
        {
            str(principal.get("principal_id") or "").strip()
            for agent in agents
            if (principal := _cloud_principal_metadata(agent))
            and str(principal.get("principal_type") or "").lower() in {"iam-role", "role"}
            and str(principal.get("principal_id") or "").strip()
        }
    )
    if not role_arns:
        return
    iam = session.client("iam")
    enriched: dict[str, dict[str, Any]] = {}
    for role_arn in role_arns:
        role_name = _role_name_from_arn(role_arn)
        try:
            role_detail = iam.get_role(RoleName=role_name).get("Role", {})
            paginator = iam.get_paginator("list_attached_role_policies")
            policies = []
            for page in paginator.paginate(RoleName=role_name):
                for policy in page.get("AttachedPolicies", []):
                    policy_arn = str(policy.get("PolicyArn") or "")
                    policy_name = str(policy.get("PolicyName") or policy_arn or "")
                    if not (policy_arn or policy_name):
                        continue
                    privilege_level, actions, document = _policy_privilege(iam, policy_arn, policy_name, warnings=warnings)
                    policy_entry: dict[str, Any] = {
                        "policy_id": policy_arn,
                        "policy_name": policy_name,
                        "attachment_type": "managed",
                        "privilege_level": privilege_level,
                        "actions": actions,
                        "source_field": "ListAttachedRolePolicies.AttachedPolicies",
                    }
                    # Retain the raw document (customer-managed only) so the graph
                    # can run real effective-permission evaluation.
                    if isinstance(document, dict):
                        policy_entry["policy_document"] = document
                    policies.append(policy_entry)
        except Exception as exc:
            warnings.append(f"IAM role enrichment skipped for {role_name}: {sanitize_discovery_warning(exc)}")
            continue
        enriched[role_arn] = {
            "policies": policies,
            "trust_principals": _extract_trust_principals(
                role_detail.get("AssumeRolePolicyDocument"),
                account_id=account_id,
            ),
        }
    for agent in agents:
        principal_value = agent.metadata.get("cloud_principal")
        if not isinstance(principal_value, dict):
            continue
        principal = principal_value
        role_arn = str(principal.get("principal_id") or "").strip()
        payload = enriched.get(role_arn)
        if not payload:
            continue
        existing_policies = principal.get("policies")
        if not isinstance(existing_policies, list):
            existing_policies = []
        by_id = {
            str(policy.get("policy_id") or policy.get("arn") or policy.get("name") or ""): policy
            for policy in existing_policies
            if isinstance(policy, dict)
        }
        for policy in payload["policies"]:
            if policy["policy_id"]:
                by_id[policy["policy_id"]] = policy
        principal["policies"] = list(by_id.values())
        principal["trust_principals"] = payload["trust_principals"]
        principal["iam_enriched"] = True
        principal["iam_enrichment_source"] = "aws-iam"
