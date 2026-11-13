"""Node risk context is derived only from recorded facts, each with a reason."""

from __future__ import annotations

import pytest

from agent_bom.graph.risk_context import (
    derive_crown_jewel,
    derive_data_sensitivity,
    derive_internet_exposure,
    derive_node_risk_context,
    derive_privilege,
    node_internet_exposed,
)


def _rules(reasons: list[dict]) -> list[str]:
    return [reason["rule"] for reason in reasons]


# ── internet exposure ────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("attributes", "rule"),
    [
        ({"internet_exposed": True}, "recorded_internet_exposed"),
        ({"internet_exposed": "true"}, "recorded_internet_exposed"),
        ({"publicly_accessible": True}, "recorded_public_flag"),
        ({"is_public": "yes"}, "recorded_public_flag"),
        ({"internet_facing": True}, "recorded_public_flag"),
        ({"endpoint_public": True}, "recorded_public_flag"),
        ({"public_ip": "34.120.0.10"}, "recorded_public_ip"),
    ],
)
def test_exposure_true_only_from_a_recorded_public_fact(attributes: dict, rule: str) -> None:
    exposed, reasons = derive_internet_exposure(attributes)
    assert exposed is True
    assert rule in _rules(reasons)
    assert all(reason["field"] == "internet_exposed" for reason in reasons)


def test_exposure_carries_the_network_rule_receipt() -> None:
    receipt = {"source": "cnapp-overlay", "network_rules": [{"finding_id": "mc:sg-open", "sources": ["aws"], "rules": []}]}
    exposed, reasons = derive_internet_exposure({"internet_exposed": True, "internet_exposure_evidence": receipt})
    assert exposed is True
    assert reasons[0]["evidence"] == {"finding_ids": ["mc:sg-open"], "source": "cnapp-overlay"}


@pytest.mark.parametrize(
    "attributes",
    [{"internet_exposed": False}, {"publicly_accessible": "false"}, {"is_public": False, "internet_exposed": "no"}],
)
def test_exposure_false_when_a_fact_shows_private(attributes: dict) -> None:
    exposed, reasons = derive_internet_exposure(attributes)
    assert exposed is False
    assert reasons and all(reason["rule"] == "recorded_not_public" for reason in reasons)


@pytest.mark.parametrize(
    "attributes",
    [
        {},
        {"internet_exposed": None},
        {"internet_exposed": "unknown"},
        {"public_ip": ""},
        {"public_ip": "10.0.0.4"},
        {"name": "public-web-frontend"},
        {"description": "internet facing load balancer"},
    ],
)
def test_exposure_unknown_without_a_recorded_fact(attributes: dict) -> None:
    assert derive_internet_exposure(attributes) == (None, [])


def test_a_positive_exposure_fact_wins_over_a_private_one() -> None:
    exposed, reasons = derive_internet_exposure({"internet_exposed": False, "publicly_accessible": True})
    assert exposed is True
    assert _rules(reasons) == ["recorded_public_flag"]


# ── privilege ────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("attributes", "rule"),
    [
        ({"admin_equivalence_status": "admin"}, "admin_equivalence"),
        ({"admin_equivalent": True}, "admin_equivalence"),
        ({"is_admin": True}, "recorded_admin_flag"),
        ({"privilege_level": "admin"}, "recorded_privilege_level"),
    ],
)
def test_admin_from_recorded_admin_evidence(attributes: dict, rule: str) -> None:
    level, is_admin, reasons = derive_privilege(attributes)
    assert (level, is_admin) == ("admin", True)
    assert rule in _rules(reasons)


def test_admin_from_a_bound_cluster_admin_role() -> None:
    level, is_admin, reasons = derive_privilege(
        {}, admin_grants=[{"role": "ClusterRole/cluster-admin", "binding": "ClusterRoleBinding/ops"}]
    )
    assert (level, is_admin) == ("admin", True)
    assert reasons[0]["rule"] == "kubernetes_cluster_admin_binding"
    assert reasons[0]["evidence"]["binding"] == "ClusterRoleBinding/ops"


def test_escalation_is_privileged_but_not_admin() -> None:
    level, is_admin, reasons = derive_privilege({"escalates_to_admin": True})
    assert level == "escalates_to_admin"
    assert is_admin is None
    assert _rules(reasons) == ["escalates_to_admin"]


def test_conditional_admin_is_not_admin() -> None:
    level, is_admin, _ = derive_privilege({"admin_equivalence_status": "conditional_admin"})
    assert (level, is_admin) == ("conditional_admin", None)


def test_not_admin_assessment_is_a_negative_fact() -> None:
    level, is_admin, reasons = derive_privilege({"admin_equivalence_status": "not_admin", "privilege_level": "read"})
    assert (level, is_admin) == ("read", False)
    assert "admin_equivalence" in _rules(reasons)


@pytest.mark.parametrize(
    "attributes", [{}, {"privilege_level": "unknown"}, {"admin_equivalence_status": "unknown"}, {"name": "admin-role"}]
)
def test_privilege_unknown_without_evidence(attributes: dict) -> None:
    assert derive_privilege(attributes) == (None, None, [])


# ── data sensitivity ─────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("attributes", "label", "rule"),
    [
        ({"data_sensitivity": "sensitive", "data_sensitivity_basis": ["tags"]}, "sensitive", "recorded_data_sensitivity"),
        ({"data_classification_tier": "restricted"}, "restricted", "recorded_classification_tier"),
        ({"data_regulatory_frameworks": ["GDPR"]}, "regulated", "recorded_regulatory_framework"),
        ({"content_data_sensitivity": "pii"}, "pii", "content_sampling"),
    ],
)
def test_sensitivity_from_recorded_classification(attributes: dict, label: str, rule: str) -> None:
    value, reasons = derive_data_sensitivity(attributes)
    assert value == label
    assert rule in _rules(reasons)


def test_sensitivity_reason_names_the_classifier_basis() -> None:
    _, reasons = derive_data_sensitivity({"data_sensitivity": "sensitive", "data_sensitivity_basis": ["label"]})
    assert reasons[0]["evidence"] == {"basis": ["label"]}


def test_sensitivity_none_is_a_recorded_negative() -> None:
    value, reasons = derive_data_sensitivity({"data_sensitivity": "none"})
    assert value == "none"
    assert reasons[0]["rule"] == "recorded_data_sensitivity"


@pytest.mark.parametrize("attributes", [{}, {"data_sensitivity": "unknown"}, {"data_sensitivity": "unevaluable"}, {"name": "customer-pii"}])
def test_sensitivity_unknown_without_classification(attributes: dict) -> None:
    assert derive_data_sensitivity(attributes) == (None, [])


# ── crown jewel ──────────────────────────────────────────────────────────────


def test_sensitive_data_store_is_a_crown_jewel() -> None:
    crown, reasons = derive_crown_jewel("data_store", {"environment": "production"}, "sensitive")
    assert crown is True
    assert _rules(reasons) == ["sensitive_data_store"]


def test_operator_declared_criticality_is_a_crown_jewel() -> None:
    crown, reasons = derive_crown_jewel("cloud_resource", {"asset_criticality": "Tier0"}, None)
    assert crown is True
    assert reasons[0]["rule"] == "declared_critical_asset"
    assert reasons[0]["value"] == "tier0"


def test_production_secret_store_is_a_crown_jewel() -> None:
    crown, reasons = derive_crown_jewel("cloud_resource", {"resource_type": "key_vault", "environment": "prod"}, None)
    assert crown is True
    assert reasons[0]["rule"] == "production_secret_store"


@pytest.mark.parametrize(
    ("entity_type", "attributes", "sensitivity"),
    [
        ("data_store", {}, None),
        ("data_store", {}, "none"),
        ("cloud_resource", {}, "sensitive"),
        ("cloud_resource", {"resource_type": "key_vault", "environment": "dev"}, None),
        ("cloud_resource", {"resource_type": "key_vault"}, None),
        ("cloud_resource", {"asset_criticality": "high"}, None),
        ("data_store", {"name": "crown-jewels-db"}, None),
    ],
)
def test_no_crown_jewel_without_a_rule_match(entity_type: str, attributes: dict, sensitivity: str | None) -> None:
    assert derive_crown_jewel(entity_type, attributes, sensitivity) == (False, [])


# ── assembled context ────────────────────────────────────────────────────────


def test_context_records_scan_and_sources_for_every_known_field() -> None:
    context = derive_node_risk_context(
        "data_store",
        {"publicly_accessible": True, "data_sensitivity": "sensitive", "data_regulatory_frameworks": ["PCI-DSS"]},
        scan_id="scan-1",
        data_sources=["aws"],
    )
    assert context is not None
    assert context["internet_exposed"] is True
    assert context["data_sensitivity"] == "sensitive"
    assert context["crown_jewel"] is True
    assert context["scan_id"] == "scan-1"
    assert context["sources"] == ["aws"]
    fields = {reason["field"] for reason in context["reasons"]}
    assert fields == {"internet_exposed", "data_sensitivity", "crown_jewel"}


def test_no_context_when_nothing_is_recorded() -> None:
    assert derive_node_risk_context("cloud_resource", {"name": "public-admin-pii"}, scan_id="s", data_sources=[]) is None


def test_node_internet_exposed_prefers_the_stored_context() -> None:
    stored = {"risk_context": {"internet_exposed": False}, "internet_exposed": True}
    assert node_internet_exposed(stored) is False
    assert node_internet_exposed({"publicly_accessible": True}) is True
    assert node_internet_exposed({}) is None


def test_every_emitted_rule_is_documented() -> None:
    import inspect
    import re

    from agent_bom.graph import risk_context

    source = inspect.getsource(risk_context)
    emitted = set(re.findall(r'_reason\(field, "([a-z_]+)"', source)) | {"escalates_to_admin", "escalates_to_conditional_admin"}
    documented = {rule for _, rule, _ in risk_context.RISK_CONTEXT_RULES}
    assert emitted <= documented
    assert len(documented) == len(risk_context.RISK_CONTEXT_RULES)
