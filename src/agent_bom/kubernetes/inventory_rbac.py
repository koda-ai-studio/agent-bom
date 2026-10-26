"""Service-account RBAC grants resolved from Roles, ClusterRoles and their bindings.

Only ServiceAccount subjects become grants: the workload graph follows a
compromised workload to the identity it runs as. User and Group subjects are
counted, not modelled. A binding whose role was not collected stays an
unresolved grant; only the four user-facing default ClusterRoles are filled in
from their documented upstream definitions.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

_READ_VERBS = frozenset({"get", "list", "watch", "*"})
_MAX_RULES = 32

# Upstream default user-facing ClusterRoles (kubernetes.io RBAC "User-facing roles").
# ``view`` deliberately excludes Secrets; ``edit`` and ``admin`` can read them.
_EDIT_VERBS = ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
_BUILTIN_ROLE_RULES: dict[str, list[dict[str, list[str]]]] = {
    "cluster-admin": [{"api_groups": ["*"], "resources": ["*"], "verbs": ["*"], "resource_names": []}],
    "admin": [
        {"api_groups": [""], "resources": ["secrets", "pods"], "verbs": _EDIT_VERBS, "resource_names": []},
        {"api_groups": [""], "resources": ["pods/exec"], "verbs": ["create", "get"], "resource_names": []},
    ],
    "edit": [
        {"api_groups": [""], "resources": ["secrets", "pods"], "verbs": _EDIT_VERBS, "resource_names": []},
        {"api_groups": [""], "resources": ["pods/exec"], "verbs": ["create", "get"], "resource_names": []},
    ],
    "view": [
        {"api_groups": [""], "resources": ["pods", "configmaps", "services"], "verbs": ["get", "list", "watch"], "resource_names": []}
    ],
}


def _strings(value: Any) -> list[str]:
    return [str(item) for item in value if isinstance(item, (str, int))] if isinstance(value, list) else []


def normalize_rule(rule: Mapping[str, Any]) -> dict[str, list[str]]:
    return {
        "api_groups": _strings(rule.get("apiGroups")),
        "resources": _strings(rule.get("resources")),
        "verbs": [verb.lower() for verb in _strings(rule.get("verbs"))],
        "resource_names": _strings(rule.get("resourceNames")),
    }


def role_record(obj: Mapping[str, Any]) -> dict[str, Any]:
    metadata = obj.get("metadata") or {}
    rules = [normalize_rule(rule) for rule in obj.get("rules") or [] if isinstance(rule, Mapping)]
    return {
        "kind": str(obj.get("kind") or ""),
        "name": str(metadata.get("name") or ""),
        "namespace": str(metadata.get("namespace") or "") if obj.get("kind") == "Role" else "",
        "rules": rules[:_MAX_RULES],
        "rules_truncated": len(rules) > _MAX_RULES,
    }


def binding_record(obj: Mapping[str, Any]) -> dict[str, Any]:
    metadata = obj.get("metadata") or {}
    role_ref = obj.get("roleRef") or {}
    namespace = str(metadata.get("namespace") or "") if obj.get("kind") == "RoleBinding" else ""
    subjects = []
    for subject in obj.get("subjects") or []:
        if not isinstance(subject, Mapping):
            continue
        kind = str(subject.get("kind") or "")
        subject_ns = str(subject.get("namespace") or "") or (namespace if kind == "ServiceAccount" else "")
        subjects.append({"kind": kind, "name": str(subject.get("name") or ""), "namespace": subject_ns})
    return {
        "kind": str(obj.get("kind") or ""),
        "name": str(metadata.get("name") or ""),
        "namespace": namespace,
        "role_ref": {"kind": str(role_ref.get("kind") or ""), "name": str(role_ref.get("name") or "")},
        "subjects": subjects,
    }


def _matches(values: list[str], wanted: str) -> bool:
    return "*" in values or wanted in values


def _secret_access(rules: list[dict[str, list[str]]] | None) -> dict[str, Any]:
    if rules is None:
        return {"access": "unknown", "names": []}
    names: set[str] = set()
    for rule in rules:
        if not (_matches(rule["api_groups"], "") and _matches(rule["resources"], "secrets")):
            continue
        if not _READ_VERBS.intersection(rule["verbs"]):
            continue
        if not rule["resource_names"]:
            return {"access": "all", "names": []}
        names.update(rule["resource_names"])
    return {"access": "named", "names": sorted(names)} if names else {"access": "none", "names": []}


def _wildcard(rules: list[dict[str, list[str]]] | None) -> bool:
    return any("*" in rule["verbs"] or "*" in rule["resources"] for rule in rules or [])


def _resolve_role(binding: dict[str, Any], roles: dict[tuple[str, str, str], dict[str, Any]]) -> tuple[list | None, str]:
    ref = binding["role_ref"]
    namespace = binding["namespace"] if ref["kind"] == "Role" else ""
    role = roles.get((ref["kind"], namespace, ref["name"]))
    if role is not None:
        return role["rules"], "collected"
    if ref["kind"] == "ClusterRole" and ref["name"] in _BUILTIN_ROLE_RULES:
        return _BUILTIN_ROLE_RULES[ref["name"]], "builtin_default"
    return None, "unresolved"


def resolve_grants(roles: Iterable[dict[str, Any]], bindings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """One grant per (binding, ServiceAccount subject), with the binding's effective scope."""
    by_key = {(role["kind"], role["namespace"], role["name"]): role for role in roles}
    grants: list[dict[str, Any]] = []
    for binding in bindings:
        rules, role_source = _resolve_role(binding, by_key)
        for subject in binding["subjects"]:
            if subject["kind"] != "ServiceAccount" or not subject["name"] or not subject["namespace"]:
                continue
            grants.append(
                {
                    "service_account": {"namespace": subject["namespace"], "name": subject["name"]},
                    "binding": {"kind": binding["kind"], "name": binding["name"], "namespace": binding["namespace"]},
                    "role": dict(binding["role_ref"]),
                    "role_resolved": rules is not None,
                    "role_source": role_source,
                    "scope": binding["namespace"] or "cluster",
                    "rules": list(rules or []),
                    "wildcard": _wildcard(rules),
                    "secrets": _secret_access(rules),
                }
            )
    return sorted(grants, key=lambda g: (g["service_account"]["namespace"], g["service_account"]["name"], g["binding"]["name"]))
