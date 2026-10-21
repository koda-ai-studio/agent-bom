"""Recorded owner scope shared by inventory IDs and graph identity consumers.

Only an asset's own identifiers are examined. Backend, policy and principal
references may legitimately point to another account and are not owner fields.
Collector identity is deliberately not an asset owner.
"""

from collections.abc import Mapping
from typing import Any

_NATIVE_FIELDS = (
    "arn",
    "resource_arn",
    "instance_arn",
    "id",
    "resource_id",
    "identifier",
    "native_id",
    "provider_id",
    "id_native",
    "self_link",
    "selfLink",
)
_ACCOUNT_FIELDS = {
    "aws": ("account_id", "cloud_account_id", "aws_account_id"),
    "azure": ("account_id", "cloud_account_id", "subscription_id"),
    "gcp": ("account_id", "cloud_account_id", "project_id"),
}
_GCP_PREFIXES = (
    "https://www.googleapis.com/compute/v1/",
    "https://compute.googleapis.com/compute/v1/",
    "//compute.googleapis.com/",
    "https://sqladmin.googleapis.com/sql/v1beta4/",
)


def native_owner_scope(provider: str, native: str) -> tuple[str, str]:
    """Return a qualified native owner's kind and value, or empty for local IDs."""
    if provider == "aws":
        parts = native.split(":", 5)
        if len(parts) == 6 and parts[0] == "arn" and parts[1] and parts[2] and parts[5]:
            if len(parts[4]) == 12 and parts[4].isascii() and parts[4].isdigit():
                return "account", parts[4]
            if parts[2] == "s3" and not parts[3] and not parts[4]:
                return "global", "s3"
    elif provider == "azure":
        parts = native.casefold().strip("/").split("/")
        if len(parts) >= 4 and parts[1]:
            if parts[0] == "subscriptions":
                return "account", parts[1]
            if parts[0] == "tenants":
                return "tenant", parts[1]
    elif provider == "gcp":
        for prefix in _GCP_PREFIXES:
            native = native.removeprefix(prefix)
        parts = native.strip("/").split("/")
        if len(parts) >= 4 and parts[1] and parts[1] != "-":
            if parts[0] == "projects":
                return "account", parts[1]
            if parts[0] in {"folders", "organizations"}:
                return parts[0], parts[1]
    return "", ""


def assess_cloud_scope(provider: str, record: Mapping[str, Any], account: str = "") -> dict[str, Any]:
    """Resolve only mutually consistent owner evidence; never invent missing scope.

    Project-number/name aliases require a verified mapping before joining. An
    unverified disagreement is kept as a scope conflict, not silently resolved.
    Tenant and organization resources retain their native scope instead of
    acquiring a subscription/project from the collection session.
    """
    provider = provider.strip().casefold()
    fields = _ACCOUNT_FIELDS.get(provider)
    if fields is None:
        return {"status": "not_applicable", "reason_codes": []}
    normalize = str.casefold if provider == "azure" else str.strip
    recorded = {normalize(str(record[key]).strip()) for key in fields if record.get(key)}
    if account:
        recorded.add(normalize(account.strip()))
    native = {scope for key in _NATIVE_FIELDS if record.get(key) if (scope := native_owner_scope(provider, str(record[key]).strip()))[0]}
    native_accounts = {value for kind, value in native if kind == "account"}
    reasons = []
    if any(
        native_owner_scope(other, str(record[key]).strip())[0]
        for key in _NATIVE_FIELDS
        if record.get(key)
        for other in _ACCOUNT_FIELDS
        if other != provider
    ):
        reasons.append("native_provider_disagrees")
    if len(recorded) > 1:
        reasons.append("conflicting_recorded_accounts")
    if len(native_accounts | recorded) > 1:
        reasons.append("native_owner_scope_disagrees")
    if len(native) > 1:
        reasons.append("conflicting_native_scopes")
    if reasons:
        return {"status": "conflict", "reason_codes": reasons}
    if native:
        kind, value = next(iter(native))
        return {"status": "scoped", "scope_kind": kind, "scope_id": value, "reason_codes": []}
    if recorded:
        return {"status": "scoped", "scope_kind": "account", "scope_id": next(iter(recorded)), "reason_codes": []}
    return {"status": "unknown", "reason_codes": ["missing_owner_scope"]}


def cloud_scope_attributes(provider: str, record: Mapping[str, Any], account: str = "") -> dict[str, Any]:
    """Carry unresolved inventory scope through projections that rename native fields."""
    scope = assess_cloud_scope(provider, record, account)
    return {"identity_scope": scope} if scope["status"] in {"conflict", "unknown"} else {}
