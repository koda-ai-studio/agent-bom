"""Evidence-aware IAM policy evaluation for permission overlays."""

from __future__ import annotations

import re
from dataclasses import replace
from typing import Any, Mapping, Sequence

from agent_bom.cloud.aws_iam_evaluator import IamDecision, evaluate_identity_policies
from agent_bom.cloud.aws_iam_evidence import (
    EvidenceCompleteness,
    NormalizedIamPolicy,
    normalize_iam_policy_document,
)
from agent_bom.graph.node import UnifiedNode

# Admin-equivalence probes for real IAM evaluation. A policy that ALLOWs any of
# these unrestricted (Resource "*") actions grants effective admin: either full
# access (``*``) or an IAM self-escalation primitive that lets the identity mint
# arbitrary permissions for itself. Evaluation respects explicit Deny, resource
# scope, and conditions — so a scoped or denied variant is NOT flagged, which a
# name/keyword match cannot distinguish.
_ADMIN_EQUIVALENCE_PROBES: tuple[tuple[str, str], ...] = (
    ("*", "*"),
    ("iam:PutUserPolicy", "*"),
    ("iam:PutRolePolicy", "*"),
    ("iam:PutGroupPolicy", "*"),
    ("iam:AttachUserPolicy", "*"),
    ("iam:AttachRolePolicy", "*"),
    ("iam:AttachGroupPolicy", "*"),
    ("iam:CreatePolicyVersion", "*"),
    ("iam:UpdateAssumeRolePolicy", "*"),
    ("iam:CreateAccessKey", "*"),
)


# Node-attribute keys under which a raw IAM policy document (or list of them) may
# be carried, so the overlay can run real evaluation when the evidence is present.
_POLICY_DOC_KEYS = ("policy_document", "policy_documents", "policy_documents_json")


def _iter_policy_documents(attrs: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """Extract raw IAM policy documents from a node's attributes (best-effort)."""
    docs: list[Mapping[str, Any]] = []
    for key in _POLICY_DOC_KEYS:
        value = attrs.get(key)
        if isinstance(value, Mapping):
            docs.append(value)
        elif isinstance(value, (list, tuple)):
            docs.extend(item for item in value if isinstance(item, Mapping))
    return docs


# Every IAM resource in one account (``arn:aws:iam::123456789012:*``) or in any
# account (``arn:aws:iam::*:*``). ``iam:*`` over either lets an identity attach
# AdministratorAccess to itself. Path-scoped forms (``:role/app/*``) are not
# account-wide and stay excluded.
_ACCOUNT_WIDE_IAM_ARN = re.compile(r"arn:(?:aws(?:-[a-z]+)*|\*):iam:\*?:(?:[0-9]{12}|\*):\*")


def _admin_resource_scopes(policies: Sequence[NormalizedIamPolicy]) -> list[str]:
    """Only account-wide IAM ARNs extend the unrestricted probes.

    A specific user/role ARN or a path-scoped wildcard is not account-wide.
    Keep the original scope in evidence rather than substituting Resource '*'.
    Each scope is probed as-is, so a Deny whose resource pattern covers it
    (``*``, the same ARN, or a broader glob) still takes precedence.
    """
    return sorted(
        {
            resource
            for policy in policies
            for statement in policy.statements
            if statement.effect == "Allow"
            for resource in statement.resources
            if _ACCOUNT_WIDE_IAM_ARN.fullmatch(resource)
        }
    )


def _admin_equivalence_decisions(policies: Sequence[NormalizedIamPolicy]) -> set[IamDecision]:
    """Retain deny precedence and uncertainty for global and account-wide probes."""
    probes = [*_ADMIN_EQUIVALENCE_PROBES]
    for resource in _admin_resource_scopes(policies):
        probes.extend((action, resource) for action, _ in _ADMIN_EQUIVALENCE_PROBES if action.startswith("iam:"))
    return {evaluate_identity_policies(policies, action=action, resource=resource).decision for action, resource in probes}


def _potential_conditional_admin(policies: Sequence[NormalizedIamPolicy]) -> bool:
    """Identify broad conditional grants, without claiming their conditions hold.

    Remove Allow conditions only for classification. Deny conditions and
    incomplete-policy markers remain intact, so unresolved restrictions cannot
    produce a confirmed grant or override an explicit deny.
    """
    supported = {
        "Bool",
        "Null",
        "StringEquals",
        "StringNotEquals",
        "StringLike",
        "StringNotLike",
        "ArnEquals",
        "ArnNotEquals",
        "ArnLike",
        "ArnNotLike",
        "IpAddress",
        "NotIpAddress",
        "DateEquals",
        "DateNotEquals",
        "DateLessThan",
        "DateLessThanEquals",
        "DateGreaterThan",
        "DateGreaterThanEquals",
        "NumericEquals",
        "NumericNotEquals",
        "NumericLessThan",
        "NumericLessThanEquals",
        "NumericGreaterThan",
        "NumericGreaterThanEquals",
    }
    for policy in policies:
        for statement in policy.statements:
            for operator, _, _ in statement.conditions:
                parts = operator.split(":")
                if len(parts) > 2 or (len(parts) == 2 and parts[0] not in {"ForAllValues", "ForAnyValue"}):
                    return False
                if parts[-1].removesuffix("IfExists") not in supported:
                    return False
    relaxed = [
        replace(
            policy,
            statements=tuple(
                replace(statement, conditions=()) if statement.effect == "Allow" else statement for statement in policy.statements
            ),
        )
        for policy in policies
    ]
    return IamDecision.ALLOW in _admin_equivalence_decisions(relaxed)


def _normalized_policies_for(principal: UnifiedNode, attached_policies: Sequence[UnifiedNode]) -> list[NormalizedIamPolicy]:
    """Collect normalized IAM policies from a principal's inline + attached documents.

    Documents may be carried on the principal node itself (inline policies) or on
    each attached ``POLICY`` node. Documents that normalize to no statements
    (``UNAVAILABLE``) are dropped so ``[]`` cleanly means "no evidence to evaluate"
    and the caller degrades to the scanner/name signal.
    """
    raw_docs: list[Mapping[str, Any]] = list(_iter_policy_documents(principal.attributes))
    for policy in attached_policies:
        raw_docs.extend(_iter_policy_documents(policy.attributes))
    normalized: list[NormalizedIamPolicy] = []
    for doc in raw_docs:
        parsed = normalize_iam_policy_document(doc)
        if parsed.completeness is not EvidenceCompleteness.UNAVAILABLE:
            normalized.append(parsed)
    return normalized
