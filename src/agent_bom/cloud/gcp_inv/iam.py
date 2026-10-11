"""GCP project IAM bindings, role resolution and service-account discovery for the inventory facade."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ..aws_inventory import record_discovery_failure
from ..normalization import sanitize_discovery_warning
from ._base import _classify_role_privilege, _highest_privilege


def _policy_bindings(policy: Any) -> list[dict[str, Any]]:
    raw = getattr(policy, "bindings", None)
    if raw is None and isinstance(policy, dict):
        raw = policy.get("bindings")
    bindings: list[dict[str, Any]] = []
    for binding in raw or []:
        if isinstance(binding, dict):
            bindings.append(binding)
        else:
            bindings.append(
                {
                    "role": str(getattr(binding, "role", "") or ""),
                    "members": list(getattr(binding, "members", []) or []),
                }
            )
    return bindings


def _discover_project_iam_bindings(
    project_id: str, *, credentials: Any, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> tuple[dict[str, list[str]], dict[str, str]]:
    """Read the project IAM policy (read-only) → ``({member: [roles…]}, {member: kind})``.

    Calls ``cloudresourcemanager`` ``projects.getIamPolicy`` and inverts the
    role→members bindings into a member→roles map so each principal carries the
    roles bound to it. The member key is the bare identity (e.g.
    ``svc@p.iam.gserviceaccount.com``) with the ``serviceAccount:`` / ``user:`` /
    ``group:`` prefix stripped, matching the SA email used elsewhere. The second
    map records each member's kind (``serviceaccount`` / ``user`` / ``group`` /
    ``domain`` …) so ``group:`` bindings can be represented as group principals
    rather than silently collapsed into the SA-only view. Degrades to empty maps
    plus a warning on any error — never raises.
    """
    bindings_by_member: dict[str, list[str]] = {}
    member_kinds: dict[str, str] = {}
    try:
        from google.cloud import resourcemanager_v3
    except ImportError:
        warnings.append("google-cloud-resource-manager not installed. Skipping project IAM-binding discovery.")
        return bindings_by_member, member_kinds
    try:
        from google.iam.v1 import iam_policy_pb2

        client = resourcemanager_v3.ProjectsClient(credentials=credentials)
        request = iam_policy_pb2.GetIamPolicyRequest(resource=f"projects/{project_id}")
        policy = client.get_iam_policy(request=request)
        for binding in _policy_bindings(policy):
            role = str(binding.get("role", "") or "")
            if not role:
                continue
            for member in binding.get("members", []) or []:
                raw = str(member)
                if ":" in raw:
                    prefix, _, ident = raw.partition(":")
                    key = ident.strip().lower()
                    kind = prefix.strip().lower()
                else:
                    key = raw.strip().lower()
                    kind = ""
                if not key:
                    continue
                member_kinds.setdefault(key, kind)
                roles = bindings_by_member.setdefault(key, [])
                if role not in roles:
                    roles.append(role)
    except Exception as exc:  # noqa: BLE001 — one failed project IAM policy list must not sink the scan
        record_discovery_failure(
            exc=exc,
            resource_type="project IAM policy",
            permission="resourcemanager.projects.getIamPolicy",
            cloud="gcp",
            warnings=warnings,
            missing=missing,
        )
    return bindings_by_member, member_kinds


def _make_role_resolver(*, credentials: Any, warnings: list[str]) -> Any:
    """Return a cached ``role_id -> [permission…]`` resolver (read-only ``roles.get``).

    Resolves both predefined (``roles/...``) and custom
    (``projects|organizations/.../roles/...``) role definitions to their concrete
    ``includedPermissions`` so a binding's *actual* capabilities are known rather
    than only its name-classified privilege level — closing the gap with the
    Azure path, which already resolves role definitions to actions. Each role is
    resolved at most once (cached), and every returned permission is retained.
    The call is covered by the connector's read-only IAM review roles. It
    degrades to an empty list plus a warning on any error — never raises.
    """
    cache: dict[str, list[str]] = {}
    client_holder: dict[str, Any] = {}

    def resolve(role: str) -> list[str]:
        name = str(role or "").strip()
        if not name:
            return []
        if name in cache:
            return cache[name]
        permissions: list[str] = []
        try:
            from google.cloud import iam_admin_v1

            client = client_holder.get("client")
            if client is None:
                client = iam_admin_v1.IAMClient(credentials=credentials)
                client_holder["client"] = client
            role_def = client.get_role(request=iam_admin_v1.GetRoleRequest(name=name))
            permissions = [str(p) for p in (getattr(role_def, "included_permissions", None) or [])]
        except Exception as exc:  # noqa: BLE001 — one failed role lookup must not sink the scan
            warnings.append(f"GCP role-definition resolution skipped for {name}: {sanitize_discovery_warning(exc)}")
        cache[name] = permissions
        return permissions

    return resolve


def _role_policy_entry(role: str, *, role_resolver: Any) -> dict[str, Any]:
    """Build one classified IAM-binding policy entry, resolved to its permissions."""
    return {
        "policy_id": role,
        "policy_name": role,
        "attachment_type": "iam-binding",
        "privilege_level": _classify_role_privilege(role),
        "permissions": role_resolver(role) if role_resolver is not None else [],
        "source_field": "projects.getIamPolicy.bindings",
    }


def _build_iam_group_principals(
    bindings_by_member: dict[str, list[str]],
    member_kinds: dict[str, str],
    *,
    project_id: str,
    role_resolver: Any,
) -> list[dict[str, Any]]:
    """Represent ``group:`` IAM-policy bindings as group principals (read-only).

    A role granted to a Google group reaches every member of that group, so the
    group must be a first-class principal carrying its bound roles (resolved to
    permissions) — otherwise group-granted access is invisible to the
    effective-permissions graph. Member expansion (who is in the group) needs the
    Workspace Directory API (admin-scoped) and is left as an explicit, optional
    seam: ``members`` stays empty here unless a gated directory connector fills it.
    """
    groups: list[dict[str, Any]] = []
    for member, roles in bindings_by_member.items():
        if member_kinds.get(member) != "group":
            continue
        policies = [_role_policy_entry(role, role_resolver=role_resolver) for role in roles]
        groups.append(
            {
                "principal_type": "group",
                "name": member,
                "arn": member,
                "principal_id": member,
                "email": member,
                "account_id": project_id,
                "roles": roles,
                "policies": policies,
                # Seam: Workspace Directory API (admin-scoped) member expansion is
                # optional + gated; leave empty rather than guess membership.
                "members": [],
                "members_expansion": "unresolved",
                "privilege_level": _highest_privilege(roles),
            }
        )
    return groups


# Fail-closed default when no read-only GCP usage source is wired: usage is
# UNEVALUABLE, never fabricated as "used" or "unused". Shaped like the AWS
# Access-Advisor payload (``state`` + ``records``) the graph builder consumes, so
# a "state != available" bundle makes the builder attach NO ``last_used_at`` and
# NO access-advisor edges → ``nhi_governance`` stays fail-closed (no phantom
# dormant / over-grant finding). A live GCP usage source (Policy Analyzer activity
# / audit-log last-authentication) can be injected via ``usage_resolver`` to
# populate real telemetry — DEFERRED: no such read-only API is wired in this repo
# yet, so production inventory honestly reports "usage source not configured".
_GCP_SA_USAGE_DEFERRED: dict[str, Any] = {
    "state": "unavailable",
    "diagnostic": "gcp_service_account_usage_source_not_configured",
    "records": [],
}


def _service_account_usage_evidence(email: str, roles: list[str], resolver: Any) -> dict[str, Any]:
    """Resolve read-only usage evidence for one service account (never fabricated).

    ``resolver`` is an optional callable ``(email, roles) -> Mapping`` supplying
    real last-authentication telemetry (mirrors the AWS Access-Advisor collector
    injection point). When absent or failing, usage is reported as unevaluable so
    downstream CIEM stays fail-closed.
    """
    if resolver is None:
        return dict(_GCP_SA_USAGE_DEFERRED)
    try:
        evidence = resolver(email, list(roles))
    except Exception:  # noqa: BLE001 — a usage lookup failure must never sink inventory
        return {"state": "unavailable", "diagnostic": "gcp_usage_resolver_error", "records": []}
    if not isinstance(evidence, Mapping):
        return dict(_GCP_SA_USAGE_DEFERRED)
    records = evidence.get("records")
    return {
        "state": str(evidence.get("state") or "unavailable"),
        "diagnostic": str(evidence.get("diagnostic") or "gcp_usage_resolver"),
        "records": list(records) if isinstance(records, list) else [],
    }


def _discover_service_accounts(
    project_id: str,
    *,
    credentials: Any,
    warnings: list[str],
    iam_bindings: dict[str, list[str]] | None = None,
    role_resolver: Any = None,
    missing: list[dict[str, str]] | None = None,
    usage_resolver: Any = None,
) -> list[dict[str, Any]]:
    """Enumerate all service accounts in the project (read-only).

    Each service account becomes a ``service_account`` graph node carrying its
    unique id and the project IAM roles bound to it, classified into a
    ``privilege_level`` (admin / write / read / unknown) so the
    effective-permissions overlay and ``OVERPERMISSIONED_TO_SENSITIVE`` /
    CIEM reasoning fire on GCP — mirroring the AWS IAM path. Privilege defaults to
    ``unknown`` when no binding is found — inventory never guesses an inflated level.

    Each record also carries ``usage_evidence`` (AWS Access-Advisor shape) so the
    graph builder can attach ``last_used_at`` + access-advisor grant edges and
    ``nhi_governance`` can evaluate GCP identities for over-grant / dormancy. With
    no wired read-only GCP usage source, usage is reported UNEVALUABLE (fail-closed,
    never fabricated); a ``usage_resolver`` injects real last-auth telemetry.
    """
    try:
        from google.cloud import iam_admin_v1
    except ImportError:
        warnings.append("google-cloud-iam not installed. Skipping service-account inventory.")
        return []

    bindings = iam_bindings or {}
    accounts: list[dict[str, Any]] = []
    try:
        client = iam_admin_v1.IAMClient(credentials=credentials)
        request = iam_admin_v1.ListServiceAccountsRequest(name=f"projects/{project_id}")
        for account in client.list_service_accounts(request=request):
            email = str(getattr(account, "email", "") or "").strip()
            if not email:
                continue
            roles = list(bindings.get(email.lower(), []))
            policies = [_role_policy_entry(role, role_resolver=role_resolver) for role in roles]
            accounts.append(
                {
                    "principal_type": "service-account",
                    "name": str(getattr(account, "display_name", "") or "") or email,
                    "arn": email,
                    "principal_id": str(getattr(account, "unique_id", "") or "") or email,
                    "email": email,
                    "disabled": bool(getattr(account, "disabled", False)),
                    "account_id": project_id,
                    "roles": roles,
                    "policies": policies,
                    "trust_principals": [],
                    "privilege_level": _highest_privilege(roles),
                    "usage_evidence": _service_account_usage_evidence(email, roles, usage_resolver),
                }
            )
    except Exception as exc:  # noqa: BLE001 — one failed service accounts list must not sink the scan
        record_discovery_failure(
            exc=exc,
            resource_type="service accounts",
            permission="iam.serviceAccounts.list",
            cloud="gcp",
            warnings=warnings,
            missing=missing,
        )
    return accounts
