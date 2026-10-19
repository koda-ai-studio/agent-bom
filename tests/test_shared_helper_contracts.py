"""Frozen legacy settings and identity contracts for helper consolidation."""

import importlib

import pytest

ENV_CASES = [
    ("agent_bom.backpressure", "_env_bool", None, {"default": True}, True),
    ("agent_bom.backpressure", "_env_bool", "", {"default": True}, False),
    ("agent_bom.backpressure", "_env_bool", " ", {"default": True}, False),
    ("agent_bom.backpressure", "_env_bool", "true", {"default": True}, True),
    ("agent_bom.backpressure", "_env_bool", " TRUE ", {"default": True}, True),
    ("agent_bom.backpressure", "_env_bool", "false", {"default": True}, False),
    ("agent_bom.backpressure", "_env_bool", "on", {"default": True}, True),
    ("agent_bom.backpressure", "_env_bool", "enabled", {"default": True}, False),
    ("agent_bom.backpressure", "_env_bool", "bad", {"default": True}, False),
    ("agent_bom.backpressure", "_env_bool", "-1", {"default": True}, False),
    ("agent_bom.backpressure", "_env_bool", "0", {"default": True}, False),
    ("agent_bom.backpressure", "_env_bool", "1", {"default": True}, True),
    ("agent_bom.backpressure", "_env_bool", "12", {"default": True}, False),
    ("agent_bom.backpressure", "_env_bool", "1.5", {"default": True}, False),
    ("agent_bom.backpressure", "_env_int", None, {"default": 7, "minimum": 1, "maximum": 10}, 7),
    ("agent_bom.backpressure", "_env_int", "", {"default": 7, "minimum": 1, "maximum": 10}, 7),
    ("agent_bom.backpressure", "_env_int", " ", {"default": 7, "minimum": 1, "maximum": 10}, 7),
    ("agent_bom.backpressure", "_env_int", "true", {"default": 7, "minimum": 1, "maximum": 10}, 7),
    ("agent_bom.backpressure", "_env_int", " TRUE ", {"default": 7, "minimum": 1, "maximum": 10}, 7),
    ("agent_bom.backpressure", "_env_int", "false", {"default": 7, "minimum": 1, "maximum": 10}, 7),
    ("agent_bom.backpressure", "_env_int", "on", {"default": 7, "minimum": 1, "maximum": 10}, 7),
    ("agent_bom.backpressure", "_env_int", "enabled", {"default": 7, "minimum": 1, "maximum": 10}, 7),
    ("agent_bom.backpressure", "_env_int", "bad", {"default": 7, "minimum": 1, "maximum": 10}, 7),
    ("agent_bom.backpressure", "_env_int", "-1", {"default": 7, "minimum": 1, "maximum": 10}, 1),
    ("agent_bom.backpressure", "_env_int", "0", {"default": 7, "minimum": 1, "maximum": 10}, 1),
    ("agent_bom.backpressure", "_env_int", "1", {"default": 7, "minimum": 1, "maximum": 10}, 1),
    ("agent_bom.backpressure", "_env_int", "12", {"default": 7, "minimum": 1, "maximum": 10}, 10),
    ("agent_bom.backpressure", "_env_int", "1.5", {"default": 7, "minimum": 1, "maximum": 10}, 7),
    ("agent_bom.analytics_retention", "_env_cap", None, {"default": 7}, 7),
    ("agent_bom.analytics_retention", "_env_cap", "", {"default": 7}, 7),
    ("agent_bom.analytics_retention", "_env_cap", " ", {"default": 7}, 7),
    ("agent_bom.analytics_retention", "_env_cap", "true", {"default": 7}, 7),
    ("agent_bom.analytics_retention", "_env_cap", " TRUE ", {"default": 7}, 7),
    ("agent_bom.analytics_retention", "_env_cap", "false", {"default": 7}, 7),
    ("agent_bom.analytics_retention", "_env_cap", "on", {"default": 7}, 7),
    ("agent_bom.analytics_retention", "_env_cap", "enabled", {"default": 7}, 7),
    ("agent_bom.analytics_retention", "_env_cap", "bad", {"default": 7}, 7),
    ("agent_bom.analytics_retention", "_env_cap", "-1", {"default": 7}, -1),
    ("agent_bom.analytics_retention", "_env_cap", "0", {"default": 7}, 0),
    ("agent_bom.analytics_retention", "_env_cap", "1", {"default": 7}, 1),
    ("agent_bom.analytics_retention", "_env_cap", "12", {"default": 7}, 12),
    ("agent_bom.analytics_retention", "_env_cap", "1.5", {"default": 7}, 7),
    ("agent_bom.audit_integrity", "_env_truthy", None, {}, False),
    ("agent_bom.audit_integrity", "_env_truthy", "", {}, False),
    ("agent_bom.audit_integrity", "_env_truthy", " ", {}, False),
    ("agent_bom.audit_integrity", "_env_truthy", "true", {}, True),
    ("agent_bom.audit_integrity", "_env_truthy", " TRUE ", {}, True),
    ("agent_bom.audit_integrity", "_env_truthy", "false", {}, False),
    ("agent_bom.audit_integrity", "_env_truthy", "on", {}, True),
    ("agent_bom.audit_integrity", "_env_truthy", "enabled", {}, False),
    ("agent_bom.audit_integrity", "_env_truthy", "bad", {}, False),
    ("agent_bom.audit_integrity", "_env_truthy", "-1", {}, False),
    ("agent_bom.audit_integrity", "_env_truthy", "0", {}, False),
    ("agent_bom.audit_integrity", "_env_truthy", "1", {}, True),
    ("agent_bom.audit_integrity", "_env_truthy", "12", {}, False),
    ("agent_bom.audit_integrity", "_env_truthy", "1.5", {}, False),
    ("agent_bom.proxy_audit", "_env_flag_enabled", None, {}, False),
    ("agent_bom.proxy_audit", "_env_flag_enabled", "", {}, False),
    ("agent_bom.proxy_audit", "_env_flag_enabled", " ", {}, False),
    ("agent_bom.proxy_audit", "_env_flag_enabled", "true", {}, True),
    ("agent_bom.proxy_audit", "_env_flag_enabled", " TRUE ", {}, True),
    ("agent_bom.proxy_audit", "_env_flag_enabled", "false", {}, False),
    ("agent_bom.proxy_audit", "_env_flag_enabled", "on", {}, True),
    ("agent_bom.proxy_audit", "_env_flag_enabled", "enabled", {}, True),
    ("agent_bom.proxy_audit", "_env_flag_enabled", "bad", {}, False),
    ("agent_bom.proxy_audit", "_env_flag_enabled", "-1", {}, False),
    ("agent_bom.proxy_audit", "_env_flag_enabled", "0", {}, False),
    ("agent_bom.proxy_audit", "_env_flag_enabled", "1", {}, True),
    ("agent_bom.proxy_audit", "_env_flag_enabled", "12", {}, False),
    ("agent_bom.proxy_audit", "_env_flag_enabled", "1.5", {}, False),
    ("agent_bom.proxy_audit", "_env_positive_int", None, {"default": 7}, 7),
    ("agent_bom.proxy_audit", "_env_positive_int", "", {"default": 7}, 7),
    ("agent_bom.proxy_audit", "_env_positive_int", " ", {"default": 7}, 7),
    ("agent_bom.proxy_audit", "_env_positive_int", "true", {"default": 7}, 7),
    ("agent_bom.proxy_audit", "_env_positive_int", " TRUE ", {"default": 7}, 7),
    ("agent_bom.proxy_audit", "_env_positive_int", "false", {"default": 7}, 7),
    ("agent_bom.proxy_audit", "_env_positive_int", "on", {"default": 7}, 7),
    ("agent_bom.proxy_audit", "_env_positive_int", "enabled", {"default": 7}, 7),
    ("agent_bom.proxy_audit", "_env_positive_int", "bad", {"default": 7}, 7),
    ("agent_bom.proxy_audit", "_env_positive_int", "-1", {"default": 7}, 1),
    ("agent_bom.proxy_audit", "_env_positive_int", "0", {"default": 7}, 1),
    ("agent_bom.proxy_audit", "_env_positive_int", "1", {"default": 7}, 1),
    ("agent_bom.proxy_audit", "_env_positive_int", "12", {"default": 7}, 12),
    ("agent_bom.proxy_audit", "_env_positive_int", "1.5", {"default": 7}, 7),
    ("agent_bom.identity.credential_policy", "_env_int", None, {"default": 7}, 7),
    ("agent_bom.identity.credential_policy", "_env_int", "", {"default": 7}, 7),
    ("agent_bom.identity.credential_policy", "_env_int", " ", {"default": 7}, 7),
    ("agent_bom.identity.credential_policy", "_env_int", "true", {"default": 7}, 7),
    ("agent_bom.identity.credential_policy", "_env_int", " TRUE ", {"default": 7}, 7),
    ("agent_bom.identity.credential_policy", "_env_int", "false", {"default": 7}, 7),
    ("agent_bom.identity.credential_policy", "_env_int", "on", {"default": 7}, 7),
    ("agent_bom.identity.credential_policy", "_env_int", "enabled", {"default": 7}, 7),
    ("agent_bom.identity.credential_policy", "_env_int", "bad", {"default": 7}, 7),
    ("agent_bom.identity.credential_policy", "_env_int", "-1", {"default": 7}, 7),
    ("agent_bom.identity.credential_policy", "_env_int", "0", {"default": 7}, 0),
    ("agent_bom.identity.credential_policy", "_env_int", "1", {"default": 7}, 1),
    ("agent_bom.identity.credential_policy", "_env_int", "12", {"default": 7}, 12),
    ("agent_bom.identity.credential_policy", "_env_int", "1.5", {"default": 7}, 7),
    ("agent_bom.cli._skills_group", "_env_flag", None, {}, False),
    ("agent_bom.cli._skills_group", "_env_flag", "", {}, False),
    ("agent_bom.cli._skills_group", "_env_flag", " ", {}, False),
    ("agent_bom.cli._skills_group", "_env_flag", "true", {}, True),
    ("agent_bom.cli._skills_group", "_env_flag", " TRUE ", {}, True),
    ("agent_bom.cli._skills_group", "_env_flag", "false", {}, False),
    ("agent_bom.cli._skills_group", "_env_flag", "on", {}, True),
    ("agent_bom.cli._skills_group", "_env_flag", "enabled", {}, False),
    ("agent_bom.cli._skills_group", "_env_flag", "bad", {}, False),
    ("agent_bom.cli._skills_group", "_env_flag", "-1", {}, False),
    ("agent_bom.cli._skills_group", "_env_flag", "0", {}, False),
    ("agent_bom.cli._skills_group", "_env_flag", "1", {}, True),
    ("agent_bom.cli._skills_group", "_env_flag", "12", {}, False),
    ("agent_bom.cli._skills_group", "_env_flag", "1.5", {}, False),
    ("agent_bom.api.agent_identity_store", "_env_int", None, {"default": 7}, 7),
    ("agent_bom.api.agent_identity_store", "_env_int", "", {"default": 7}, 7),
    ("agent_bom.api.agent_identity_store", "_env_int", " ", {"default": 7}, 7),
    ("agent_bom.api.agent_identity_store", "_env_int", "true", {"default": 7}, 7),
    ("agent_bom.api.agent_identity_store", "_env_int", " TRUE ", {"default": 7}, 7),
    ("agent_bom.api.agent_identity_store", "_env_int", "false", {"default": 7}, 7),
    ("agent_bom.api.agent_identity_store", "_env_int", "on", {"default": 7}, 7),
    ("agent_bom.api.agent_identity_store", "_env_int", "enabled", {"default": 7}, 7),
    ("agent_bom.api.agent_identity_store", "_env_int", "bad", {"default": 7}, 7),
    ("agent_bom.api.agent_identity_store", "_env_int", "-1", {"default": 7}, 7),
    ("agent_bom.api.agent_identity_store", "_env_int", "0", {"default": 7}, 0),
    ("agent_bom.api.agent_identity_store", "_env_int", "1", {"default": 7}, 1),
    ("agent_bom.api.agent_identity_store", "_env_int", "12", {"default": 7}, 12),
    ("agent_bom.api.agent_identity_store", "_env_int", "1.5", {"default": 7}, 7),
    ("agent_bom.api.report_artifact_store", "_env_int", None, {"default": 7}, 7),
    ("agent_bom.api.report_artifact_store", "_env_int", "", {"default": 7}, 7),
    ("agent_bom.api.report_artifact_store", "_env_int", " ", {"default": 7}, 7),
    ("agent_bom.api.report_artifact_store", "_env_int", "true", {"default": 7}, "raises"),
    ("agent_bom.api.report_artifact_store", "_env_int", " TRUE ", {"default": 7}, "raises"),
    ("agent_bom.api.report_artifact_store", "_env_int", "false", {"default": 7}, "raises"),
    ("agent_bom.api.report_artifact_store", "_env_int", "on", {"default": 7}, "raises"),
    ("agent_bom.api.report_artifact_store", "_env_int", "enabled", {"default": 7}, "raises"),
    ("agent_bom.api.report_artifact_store", "_env_int", "bad", {"default": 7}, "raises"),
    ("agent_bom.api.report_artifact_store", "_env_int", "-1", {"default": 7}, -1),
    ("agent_bom.api.report_artifact_store", "_env_int", "0", {"default": 7}, 0),
    ("agent_bom.api.report_artifact_store", "_env_int", "1", {"default": 7}, 1),
    ("agent_bom.api.report_artifact_store", "_env_int", "12", {"default": 7}, 12),
    ("agent_bom.api.report_artifact_store", "_env_int", "1.5", {"default": 7}, "raises"),
    ("agent_bom.api.saml", "_env_flag", None, {}, False),
    ("agent_bom.api.saml", "_env_flag", "", {}, False),
    ("agent_bom.api.saml", "_env_flag", " ", {}, False),
    ("agent_bom.api.saml", "_env_flag", "true", {}, True),
    ("agent_bom.api.saml", "_env_flag", " TRUE ", {}, True),
    ("agent_bom.api.saml", "_env_flag", "false", {}, False),
    ("agent_bom.api.saml", "_env_flag", "on", {}, False),
    ("agent_bom.api.saml", "_env_flag", "enabled", {}, False),
    ("agent_bom.api.saml", "_env_flag", "bad", {}, False),
    ("agent_bom.api.saml", "_env_flag", "-1", {}, False),
    ("agent_bom.api.saml", "_env_flag", "0", {}, False),
    ("agent_bom.api.saml", "_env_flag", "1", {}, True),
    ("agent_bom.api.saml", "_env_flag", "12", {}, False),
    ("agent_bom.api.saml", "_env_flag", "1.5", {}, False),
    ("agent_bom.api.browser_session", "_env_flag", None, {}, False),
    ("agent_bom.api.browser_session", "_env_flag", "", {}, False),
    ("agent_bom.api.browser_session", "_env_flag", " ", {}, False),
    ("agent_bom.api.browser_session", "_env_flag", "true", {}, True),
    ("agent_bom.api.browser_session", "_env_flag", " TRUE ", {}, True),
    ("agent_bom.api.browser_session", "_env_flag", "false", {}, False),
    ("agent_bom.api.browser_session", "_env_flag", "on", {}, True),
    ("agent_bom.api.browser_session", "_env_flag", "enabled", {}, False),
    ("agent_bom.api.browser_session", "_env_flag", "bad", {}, False),
    ("agent_bom.api.browser_session", "_env_flag", "-1", {}, False),
    ("agent_bom.api.browser_session", "_env_flag", "0", {}, False),
    ("agent_bom.api.browser_session", "_env_flag", "1", {}, True),
    ("agent_bom.api.browser_session", "_env_flag", "12", {}, False),
    ("agent_bom.api.browser_session", "_env_flag", "1.5", {}, False),
    ("agent_bom.api.scim", "_env_flag", None, {}, False),
    ("agent_bom.api.scim", "_env_flag", "", {}, False),
    ("agent_bom.api.scim", "_env_flag", " ", {}, False),
    ("agent_bom.api.scim", "_env_flag", "true", {}, True),
    ("agent_bom.api.scim", "_env_flag", " TRUE ", {}, True),
    ("agent_bom.api.scim", "_env_flag", "false", {}, False),
    ("agent_bom.api.scim", "_env_flag", "on", {}, True),
    ("agent_bom.api.scim", "_env_flag", "enabled", {}, False),
    ("agent_bom.api.scim", "_env_flag", "bad", {}, False),
    ("agent_bom.api.scim", "_env_flag", "-1", {}, False),
    ("agent_bom.api.scim", "_env_flag", "0", {}, False),
    ("agent_bom.api.scim", "_env_flag", "1", {}, True),
    ("agent_bom.api.scim", "_env_flag", "12", {}, False),
    ("agent_bom.api.scim", "_env_flag", "1.5", {}, False),
    ("agent_bom.api.compliance_signing", "_env_int", None, {}, None),
    ("agent_bom.api.compliance_signing", "_env_int", "", {}, None),
    ("agent_bom.api.compliance_signing", "_env_int", " ", {}, None),
    ("agent_bom.api.compliance_signing", "_env_int", "true", {}, None),
    ("agent_bom.api.compliance_signing", "_env_int", " TRUE ", {}, None),
    ("agent_bom.api.compliance_signing", "_env_int", "false", {}, None),
    ("agent_bom.api.compliance_signing", "_env_int", "on", {}, None),
    ("agent_bom.api.compliance_signing", "_env_int", "enabled", {}, None),
    ("agent_bom.api.compliance_signing", "_env_int", "bad", {}, None),
    ("agent_bom.api.compliance_signing", "_env_int", "-1", {}, None),
    ("agent_bom.api.compliance_signing", "_env_int", "0", {}, 0),
    ("agent_bom.api.compliance_signing", "_env_int", "1", {}, 1),
    ("agent_bom.api.compliance_signing", "_env_int", "12", {}, 12),
    ("agent_bom.api.compliance_signing", "_env_int", "1.5", {}, None),
    ("agent_bom.api.secret_lifecycle", "_env_enabled", None, {}, False),
    ("agent_bom.api.secret_lifecycle", "_env_enabled", "", {}, False),
    ("agent_bom.api.secret_lifecycle", "_env_enabled", " ", {}, False),
    ("agent_bom.api.secret_lifecycle", "_env_enabled", "true", {}, True),
    ("agent_bom.api.secret_lifecycle", "_env_enabled", " TRUE ", {}, True),
    ("agent_bom.api.secret_lifecycle", "_env_enabled", "false", {}, False),
    ("agent_bom.api.secret_lifecycle", "_env_enabled", "on", {}, True),
    ("agent_bom.api.secret_lifecycle", "_env_enabled", "enabled", {}, False),
    ("agent_bom.api.secret_lifecycle", "_env_enabled", "bad", {}, False),
    ("agent_bom.api.secret_lifecycle", "_env_enabled", "-1", {}, False),
    ("agent_bom.api.secret_lifecycle", "_env_enabled", "0", {}, False),
    ("agent_bom.api.secret_lifecycle", "_env_enabled", "1", {}, True),
    ("agent_bom.api.secret_lifecycle", "_env_enabled", "12", {}, False),
    ("agent_bom.api.secret_lifecycle", "_env_enabled", "1.5", {}, False),
    ("agent_bom.api.secret_lifecycle", "_env_int", None, {}, None),
    ("agent_bom.api.secret_lifecycle", "_env_int", "", {}, None),
    ("agent_bom.api.secret_lifecycle", "_env_int", " ", {}, None),
    ("agent_bom.api.secret_lifecycle", "_env_int", "true", {}, None),
    ("agent_bom.api.secret_lifecycle", "_env_int", " TRUE ", {}, None),
    ("agent_bom.api.secret_lifecycle", "_env_int", "false", {}, None),
    ("agent_bom.api.secret_lifecycle", "_env_int", "on", {}, None),
    ("agent_bom.api.secret_lifecycle", "_env_int", "enabled", {}, None),
    ("agent_bom.api.secret_lifecycle", "_env_int", "bad", {}, None),
    ("agent_bom.api.secret_lifecycle", "_env_int", "-1", {}, None),
    ("agent_bom.api.secret_lifecycle", "_env_int", "0", {}, 0),
    ("agent_bom.api.secret_lifecycle", "_env_int", "1", {}, 1),
    ("agent_bom.api.secret_lifecycle", "_env_int", "12", {}, 12),
    ("agent_bom.api.secret_lifecycle", "_env_int", "1.5", {}, None),
    ("agent_bom.api.audit_log", "_env_enabled", None, {}, False),
    ("agent_bom.api.audit_log", "_env_enabled", "", {}, False),
    ("agent_bom.api.audit_log", "_env_enabled", " ", {}, False),
    ("agent_bom.api.audit_log", "_env_enabled", "true", {}, True),
    ("agent_bom.api.audit_log", "_env_enabled", " TRUE ", {}, True),
    ("agent_bom.api.audit_log", "_env_enabled", "false", {}, False),
    ("agent_bom.api.audit_log", "_env_enabled", "on", {}, True),
    ("agent_bom.api.audit_log", "_env_enabled", "enabled", {}, False),
    ("agent_bom.api.audit_log", "_env_enabled", "bad", {}, False),
    ("agent_bom.api.audit_log", "_env_enabled", "-1", {}, False),
    ("agent_bom.api.audit_log", "_env_enabled", "0", {}, False),
    ("agent_bom.api.audit_log", "_env_enabled", "1", {}, True),
    ("agent_bom.api.audit_log", "_env_enabled", "12", {}, False),
    ("agent_bom.api.audit_log", "_env_enabled", "1.5", {}, False),
    ("agent_bom.api.audit_log", "_env_int", None, {}, None),
    ("agent_bom.api.audit_log", "_env_int", "", {}, None),
    ("agent_bom.api.audit_log", "_env_int", " ", {}, None),
    ("agent_bom.api.audit_log", "_env_int", "true", {}, None),
    ("agent_bom.api.audit_log", "_env_int", " TRUE ", {}, None),
    ("agent_bom.api.audit_log", "_env_int", "false", {}, None),
    ("agent_bom.api.audit_log", "_env_int", "on", {}, None),
    ("agent_bom.api.audit_log", "_env_int", "enabled", {}, None),
    ("agent_bom.api.audit_log", "_env_int", "bad", {}, None),
    ("agent_bom.api.audit_log", "_env_int", "-1", {}, None),
    ("agent_bom.api.audit_log", "_env_int", "0", {}, 0),
    ("agent_bom.api.audit_log", "_env_int", "1", {}, 1),
    ("agent_bom.api.audit_log", "_env_int", "12", {}, 12),
    ("agent_bom.api.audit_log", "_env_int", "1.5", {}, None),
    ("agent_bom.api.gateway_auth", "_env_flag_enabled", None, {}, False),
    ("agent_bom.api.gateway_auth", "_env_flag_enabled", "", {}, False),
    ("agent_bom.api.gateway_auth", "_env_flag_enabled", " ", {}, False),
    ("agent_bom.api.gateway_auth", "_env_flag_enabled", "true", {}, True),
    ("agent_bom.api.gateway_auth", "_env_flag_enabled", " TRUE ", {}, True),
    ("agent_bom.api.gateway_auth", "_env_flag_enabled", "false", {}, False),
    ("agent_bom.api.gateway_auth", "_env_flag_enabled", "on", {}, True),
    ("agent_bom.api.gateway_auth", "_env_flag_enabled", "enabled", {}, True),
    ("agent_bom.api.gateway_auth", "_env_flag_enabled", "bad", {}, False),
    ("agent_bom.api.gateway_auth", "_env_flag_enabled", "-1", {}, False),
    ("agent_bom.api.gateway_auth", "_env_flag_enabled", "0", {}, False),
    ("agent_bom.api.gateway_auth", "_env_flag_enabled", "1", {}, True),
    ("agent_bom.api.gateway_auth", "_env_flag_enabled", "12", {}, False),
    ("agent_bom.api.gateway_auth", "_env_flag_enabled", "1.5", {}, False),
    ("agent_bom.api.auth_posture", "_env_flag", None, {}, False),
    ("agent_bom.api.auth_posture", "_env_flag", "", {}, False),
    ("agent_bom.api.auth_posture", "_env_flag", " ", {}, False),
    ("agent_bom.api.auth_posture", "_env_flag", "true", {}, True),
    ("agent_bom.api.auth_posture", "_env_flag", " TRUE ", {}, True),
    ("agent_bom.api.auth_posture", "_env_flag", "false", {}, False),
    ("agent_bom.api.auth_posture", "_env_flag", "on", {}, True),
    ("agent_bom.api.auth_posture", "_env_flag", "enabled", {}, False),
    ("agent_bom.api.auth_posture", "_env_flag", "bad", {}, False),
    ("agent_bom.api.auth_posture", "_env_flag", "-1", {}, False),
    ("agent_bom.api.auth_posture", "_env_flag", "0", {}, False),
    ("agent_bom.api.auth_posture", "_env_flag", "1", {}, True),
    ("agent_bom.api.auth_posture", "_env_flag", "12", {}, False),
    ("agent_bom.api.auth_posture", "_env_flag", "1.5", {}, False),
]


@pytest.mark.parametrize("module,name,raw,kwargs,expected", ENV_CASES)
def test_environment_compatibility(monkeypatch, module, name, raw, kwargs, expected):
    key = "AGENT_BOM_TEST_HELPER"
    if raw is None:
        monkeypatch.delenv(key, raising=False)
    else:
        monkeypatch.setenv(key, raw)
    helper = getattr(importlib.import_module(module), name)
    if expected == "raises":
        with pytest.raises(ValueError):
            helper(key, **kwargs)
    else:
        assert helper(key, **kwargs) == expected


@pytest.mark.parametrize(
    "module,name",
    [
        ("agent_bom.core.sla", "_parse_iso"),
        ("agent_bom.vuln_freshness", "_parse_ts"),
        ("agent_bom.api.cost_forecast", "_parse_ts"),
        ("agent_bom.api.access_review", "_parse_iso"),
        ("agent_bom.api.connection_scheduler", "_parse_iso"),
        ("agent_bom.api.gateway_feed_health", "_parse_iso_timestamp"),
        ("agent_bom.cloud.runtime_workload_evidence", "_parse_ts"),
    ],
)
def test_timestamp_contract(module, name):
    from datetime import datetime, timezone

    parse = getattr(importlib.import_module(module), name)
    expected = datetime(2026, 10, 18, 12, tzinfo=timezone.utc)
    for text in ("2026-10-18T12:00:00", "2026-10-18T12:00:00Z", "2026-10-18T14:00:00+02:00"):
        actual = parse(text)
        assert actual == expected
        assert actual.tzinfo is timezone.utc
    assert parse("bad") is None
    assert parse(None) is None


@pytest.mark.parametrize(
    "parts,expected",
    [
        ((), "azure:legacy-role-assignment:e3b0c44298fc1c149afbf4c8"),
        (("tenant", "role", "member"), "azure:legacy-role-assignment:5a7ac7dfe73605941e9b1af4"),
        ((" Tenant ", "Role", ""), "azure:legacy-role-assignment:52b15059002f2f734ba37362"),
        (("é", "🛡"), "azure:legacy-role-assignment:b94d5678fe810de22c38e7ab"),
        (("a\x1fb", "c"), "azure:legacy-role-assignment:e0dee694aed26d323b0d8b86"),
    ],
)
def test_azure_rbac_evidence_ids(parts, expected):
    from agent_bom.cloud.azure_rbac_evidence import _stable_id

    assert _stable_id(*parts) == expected


@pytest.mark.parametrize(
    "parts,expected",
    [
        ((), "gcp:legacy-iam-binding:e3b0c44298fc1c149afbf4c8"),
        (("tenant", "role", "member"), "gcp:legacy-iam-binding:5a7ac7dfe73605941e9b1af4"),
        ((" Tenant ", "Role", ""), "gcp:legacy-iam-binding:52b15059002f2f734ba37362"),
        (("é", "🛡"), "gcp:legacy-iam-binding:b94d5678fe810de22c38e7ab"),
        (("a\x1fb", "c"), "gcp:legacy-iam-binding:e0dee694aed26d323b0d8b86"),
    ],
)
def test_gcp_iam_evidence_ids(parts, expected):
    from agent_bom.cloud.gcp_iam_evidence import _stable_id

    assert _stable_id(*parts) == expected


def test_gcp_native_binding_id_bytes():
    from agent_bom.cloud.gcp_authorization_records import _bindings

    bindings, dropped = _bindings(
        {"bindings": [{"role": "roles/viewer", "members": ["user:é@example.com", "user:a@example.com"]}]},
        "//cloudresourcemanager.googleapis.com/projects/123",
    )
    assert dropped == 0
    assert bindings[0]["id"] == "gcp:iam-binding:27d760896f351ddc09d7c83a"


def test_timestamp_strict_identity_contract():
    from datetime import timezone

    from agent_bom.core.timestamps import parse_identity_timestamp, parse_timestamp

    assert parse_identity_timestamp is parse_timestamp
    assert parse_timestamp("2026-10-18T12:00:00", require_timezone=True) is None
    assert parse_timestamp("2026-10-18T12:00:00Z", require_timezone=True).tzinfo is timezone.utc
    assert parse_timestamp("2026-10-18T12:00:00z").tzinfo is timezone.utc
    assert parse_timestamp(123) is None


def test_evidence_bundle_timestamp_keeps_strict_invalid_policy():
    from datetime import datetime, timezone

    from fastapi import HTTPException

    from agent_bom.api.routes.compliance_routes.bundle import _parse_iso_or_default

    default = datetime(2026, 10, 18, tzinfo=timezone.utc)
    assert _parse_iso_or_default(None, default) is default
    assert _parse_iso_or_default("", default) is default
    with pytest.raises(HTTPException) as exc:
        _parse_iso_or_default("invalid", default)
    assert exc.value.status_code == 400
    parsed = _parse_iso_or_default("2026-10-18T14:00:00+02:00", default)
    assert parsed == datetime(2026, 10, 18, 12, tzinfo=timezone.utc)
    assert parsed.tzinfo is timezone.utc
