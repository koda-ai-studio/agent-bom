"""Per-node risk context derived only from recorded facts.

Four attributes describe what an attack path passes through: whether a node is
reachable from the internet, how privileged it is, how sensitive its data is,
and whether it is a crown jewel. Each is computed from attributes a collector or
an earlier overlay recorded, never from a name, and every known value carries
the reasons that establish it. The rules are documented in
``docs/graph/NODE_RISK_CONTEXT.md``.

The functions here are pure; :mod:`agent_bom.graph.risk_context_overlay`
applies them to a graph.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Mapping
from typing import Any

from agent_bom.cloud.normalization import coerce_bool_or_none

RISK_CONTEXT_KEY = "risk_context"
RISK_CONTEXT_VERSION = 1

# Recorded boolean flags that state public reachability. ``internet_exposed`` is
# checked first and reported under its own rule because overlays attach the
# network-rule receipt that set it.
_PUBLIC_FLAGS = ("publicly_accessible", "is_public", "public_access", "public", "internet_facing", "endpoint_public")
_PUBLIC_IP_KEYS = ("public_ip", "public_ip_address")

_ADMIN_STATUSES = {"admin": ("admin", True), "conditional_admin": ("conditional_admin", None), "not_admin": (None, False)}
_UNKNOWN_TEXT = frozenset({"", "unknown", "none", "null"})

_NON_SENSITIVE = frozenset({"", "0", "false", "no", "null", "unevaluable", "unknown"})

_CROWN_JEWEL_DATA_TYPES = frozenset({"data_store"})
_DECLARED_CRITICAL = frozenset({"critical", "crown_jewel", "tier0", "tier-0"})
_SECRET_STORE_TYPES = frozenset({"key_vault", "secrets_manager", "secretsmanager", "secret_manager"})
_PRODUCTION = frozenset({"production", "prod", "prd"})


# Every rule a reason can name: (field, rule, the recorded fact it requires).
RISK_CONTEXT_RULES: tuple[tuple[str, str, str], ...] = (
    (
        "internet_exposed",
        "recorded_internet_exposed",
        "`internet_exposed` true, set by a collector or a structured internet-scoped network rule",
    ),
    ("internet_exposed", "recorded_public_flag", "a provider flag true: " + ", ".join(f"`{flag}`" for flag in _PUBLIC_FLAGS)),
    ("internet_exposed", "recorded_public_ip", "a globally routable address in `public_ip` / `public_ip_address`"),
    ("internet_exposed", "recorded_not_public", "the same flags recorded false and none true (verdict false)"),
    ("privilege_level", "admin_equivalence", "the effective-permissions verdict `admin_equivalence_status` / `admin_equivalent`"),
    ("privilege_level", "recorded_admin_flag", "`is_admin` true"),
    ("privilege_level", "recorded_privilege_level", "the collector's highest policy level `privilege_level` (admin / write / read)"),
    ("privilege_level", "kubernetes_cluster_admin_binding", "an `inherits` edge to the built-in `ClusterRole/cluster-admin`"),
    ("privilege_level", "escalates_to_admin", "an assume chain to an admin role (`escalates_to_admin`); not standing admin"),
    ("privilege_level", "escalates_to_conditional_admin", "an assume chain to a conditional admin role"),
    (
        "data_sensitivity",
        "recorded_data_sensitivity",
        "`data_sensitivity` from a classifier; `data_sensitivity_basis` says name or metadata",
    ),
    ("data_sensitivity", "recorded_classification_tier", "`data_classification_tier`"),
    ("data_sensitivity", "recorded_regulatory_framework", "`data_regulatory_frameworks` (PCI-DSS, HIPAA, GDPR, SOC2)"),
    ("data_sensitivity", "content_sampling", "`content_data_sensitivity` from sampled contents"),
    ("crown_jewel", "sensitive_data_store", "a `data_store` node whose data sensitivity is established"),
    ("crown_jewel", "declared_critical_asset", "`asset_criticality` / `criticality` of critical, crown_jewel, tier0"),
    ("crown_jewel", "production_secret_store", "a secrets store `resource_type` with a production `environment`"),
)


def _reason(field: str, rule: str, attribute: str, value: Any, evidence: Mapping[str, Any] | None = None) -> dict[str, Any]:
    reason: dict[str, Any] = {"field": field, "rule": rule, "attribute": attribute, "value": value}
    if evidence:
        reason["evidence"] = dict(evidence)
    return reason


def _network_rule_evidence(attributes: Mapping[str, Any]) -> dict[str, Any]:
    receipt = attributes.get("internet_exposure_evidence")
    if not isinstance(receipt, Mapping):
        return {}
    finding_ids = sorted(
        {str(rule["finding_id"]) for rule in receipt.get("network_rules") or [] if isinstance(rule, Mapping) and rule.get("finding_id")}
    )
    evidence: dict[str, Any] = {}
    if finding_ids:
        evidence["finding_ids"] = finding_ids
    for key in ("source", "basis"):
        if receipt.get(key):
            evidence[key] = str(receipt[key])
    inputs = receipt.get("inputs")
    if isinstance(inputs, Mapping) and inputs:
        evidence["inputs"] = dict(inputs)
    return evidence


def _is_public_ip(value: Any) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    try:
        return ipaddress.ip_address(value.strip()).is_global
    except ValueError:
        return False


def derive_internet_exposure(attributes: Mapping[str, Any]) -> tuple[bool | None, list[dict[str, Any]]]:
    """True on any recorded public fact, False when facts only show private, else unknown."""
    field = "internet_exposed"
    public: list[dict[str, Any]] = []
    private: list[dict[str, Any]] = []
    recorded = coerce_bool_or_none(attributes.get("internet_exposed"))
    if recorded is True:
        public.append(_reason(field, "recorded_internet_exposed", "internet_exposed", True, _network_rule_evidence(attributes)))
    elif recorded is False:
        private.append(_reason(field, "recorded_not_public", "internet_exposed", False))
    for key in _PUBLIC_FLAGS:
        flag = coerce_bool_or_none(attributes.get(key))
        if flag is True:
            public.append(_reason(field, "recorded_public_flag", key, True))
        elif flag is False:
            private.append(_reason(field, "recorded_not_public", key, False))
    for key in _PUBLIC_IP_KEYS:
        if _is_public_ip(attributes.get(key)):
            public.append(_reason(field, "recorded_public_ip", key, str(attributes[key]).strip()))
    if public:
        return True, public
    if private:
        return False, private
    return None, []


def derive_privilege(
    attributes: Mapping[str, Any], *, admin_grants: Iterable[Mapping[str, Any]] = ()
) -> tuple[str | None, bool | None, list[dict[str, Any]]]:
    """Privilege level and admin verdict from recorded policy analysis and grants."""
    field = "privilege_level"
    reasons: list[dict[str, Any]] = []
    level: str | None = None
    is_admin: bool | None = None

    status = str(attributes.get("admin_equivalence_status") or "").strip().lower()
    if status in _ADMIN_STATUSES:
        level, is_admin = _ADMIN_STATUSES[status]
        reasons.append(_reason(field, "admin_equivalence", "admin_equivalence_status", status))
    if coerce_bool_or_none(attributes.get("admin_equivalent")) is True and is_admin is not True:
        level, is_admin = "admin", True
        reasons.append(_reason(field, "admin_equivalence", "admin_equivalent", True))
    if coerce_bool_or_none(attributes.get("is_admin")) is True:
        level, is_admin = "admin", True
        reasons.append(_reason(field, "recorded_admin_flag", "is_admin", True))
    for grant in admin_grants:
        level, is_admin = "admin", True
        reasons.append(_reason(field, "kubernetes_cluster_admin_binding", "role", grant.get("role"), grant))

    recorded_level = str(attributes.get("privilege_level") or "").strip().lower()
    if recorded_level not in _UNKNOWN_TEXT:
        if recorded_level == "admin":
            level, is_admin = "admin", True
        elif level is None:
            level = recorded_level
        reasons.append(_reason(field, "recorded_privilege_level", "privilege_level", recorded_level))

    # Reaching admin through an assume chain outranks a direct read/write or
    # conditional grant, but it is not standing admin, so ``is_admin`` keeps
    # whatever the direct assessment established.
    if is_admin is not True:
        if coerce_bool_or_none(attributes.get("escalates_to_admin")) is True:
            level = "escalates_to_admin"
            reasons.append(_reason(field, "escalates_to_admin", "escalates_to_admin", True))
        elif coerce_bool_or_none(attributes.get("escalates_to_conditional_admin")) is True:
            if level != "conditional_admin":
                level = "escalates_to_conditional_admin"
            reasons.append(_reason(field, "escalates_to_conditional_admin", "escalates_to_conditional_admin", True))
    if level is None and is_admin is None:
        return None, None, []
    return level, is_admin, reasons


def derive_data_sensitivity(attributes: Mapping[str, Any]) -> tuple[str | None, list[dict[str, Any]]]:
    """The recorded sensitivity label; ``"none"`` when a classifier recorded none."""
    field = "data_sensitivity"
    reasons: list[dict[str, Any]] = []
    label: str | None = None

    recorded = attributes.get("data_sensitivity")
    text = str(recorded).strip().lower() if isinstance(recorded, str) else ("sensitive" if recorded is True else "")
    if text and text not in _NON_SENSITIVE:
        label = text
        basis = attributes.get("data_sensitivity_basis")
        evidence = {"basis": [str(item) for item in basis]} if isinstance(basis, list) and basis else None
        reasons.append(_reason(field, "recorded_data_sensitivity", "data_sensitivity", text, evidence))
    tier = str(attributes.get("data_classification_tier") or "").strip().lower()
    if tier and tier not in _NON_SENSITIVE and tier != "none":
        label = label if label not in (None, "none") else tier
        reasons.append(_reason(field, "recorded_classification_tier", "data_classification_tier", tier))
    frameworks = attributes.get("data_regulatory_frameworks")
    if isinstance(frameworks, list) and frameworks:
        label = label if label not in (None, "none") else "regulated"
        reasons.append(_reason(field, "recorded_regulatory_framework", "data_regulatory_frameworks", [str(item) for item in frameworks]))
    sampled = str(attributes.get("content_data_sensitivity") or "").strip().lower()
    if sampled and sampled not in _NON_SENSITIVE:
        label = label if label not in (None, "none") else sampled
        reasons.append(_reason(field, "content_sampling", "content_data_sensitivity", sampled))
    return label, reasons


def is_sensitive_label(label: str | None) -> bool:
    return label is not None and label != "none"


def derive_crown_jewel(entity_type: str, attributes: Mapping[str, Any], sensitivity: str | None) -> tuple[bool, list[dict[str, Any]]]:
    """Crown jewel when one documented rule matches; reasons name every rule that did."""
    field = "crown_jewel"
    reasons: list[dict[str, Any]] = []
    if entity_type in _CROWN_JEWEL_DATA_TYPES and is_sensitive_label(sensitivity):
        reasons.append(_reason(field, "sensitive_data_store", "data_sensitivity", sensitivity))
    criticality = str(attributes.get("asset_criticality") or attributes.get("criticality") or "").strip().lower()
    if criticality in _DECLARED_CRITICAL:
        key = "asset_criticality" if attributes.get("asset_criticality") else "criticality"
        reasons.append(_reason(field, "declared_critical_asset", key, criticality))
    resource_type = str(attributes.get("resource_type") or "").strip().lower()
    environment = str(attributes.get("environment") or "").strip().lower()
    if resource_type in _SECRET_STORE_TYPES and environment in _PRODUCTION:
        reasons.append(_reason(field, "production_secret_store", "resource_type", resource_type, {"environment": environment}))
    return bool(reasons), reasons


def derive_node_risk_context(
    entity_type: str,
    attributes: Mapping[str, Any],
    *,
    scan_id: str,
    data_sources: Iterable[str],
    admin_grants: Iterable[Mapping[str, Any]] = (),
) -> dict[str, Any] | None:
    """The stored context for one node, or ``None`` when no field is established."""
    exposed, exposure_reasons = derive_internet_exposure(attributes)
    level, is_admin, privilege_reasons = derive_privilege(attributes, admin_grants=admin_grants)
    sensitivity, sensitivity_reasons = derive_data_sensitivity(attributes)
    crown, crown_reasons = derive_crown_jewel(entity_type, attributes, sensitivity)
    reasons = exposure_reasons + privilege_reasons + sensitivity_reasons + crown_reasons
    if not reasons:
        return None
    return {
        "version": RISK_CONTEXT_VERSION,
        "scan_id": scan_id,
        "sources": sorted({str(source) for source in data_sources}),
        "internet_exposed": exposed,
        "privilege_level": level,
        "is_admin": is_admin,
        "data_sensitivity": sensitivity,
        "crown_jewel": crown,
        "reasons": reasons,
    }


def stored_risk_context(attributes: Mapping[str, Any]) -> Mapping[str, Any] | None:
    context = attributes.get(RISK_CONTEXT_KEY)
    return context if isinstance(context, Mapping) else None


def node_internet_exposed(attributes: Mapping[str, Any]) -> bool | None:
    """The node's exposure verdict: the stored context, else derived from its facts."""
    context = stored_risk_context(attributes)
    if context is not None:
        value = context.get("internet_exposed")
        return value if isinstance(value, bool) else None
    return derive_internet_exposure(attributes)[0]


__all__ = [
    "RISK_CONTEXT_KEY",
    "RISK_CONTEXT_RULES",
    "RISK_CONTEXT_VERSION",
    "derive_crown_jewel",
    "derive_data_sensitivity",
    "derive_internet_exposure",
    "derive_node_risk_context",
    "derive_privilege",
    "is_sensitive_label",
    "node_internet_exposed",
    "stored_risk_context",
]
