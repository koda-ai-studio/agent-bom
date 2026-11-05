"""A control with nothing to evaluate is not_applicable, never a vacuous PASS."""

from __future__ import annotations

import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from agent_bom.cloud import aws_cis_benchmark as aws
from agent_bom.cloud import azure_cis_benchmark as azure
from agent_bom.cloud import databricks_security as dbx
from agent_bom.cloud import gcp_cis_benchmark as gcp
from agent_bom.cloud import snowflake_cis_benchmark as sf
from agent_bom.cloud.aws_cis import iam_access, iam_account, networking, runner, storage
from agent_bom.cloud.aws_cis_benchmark import CheckStatus, CISCheckResult, not_applicable_if_empty
from agent_bom.cloud.azure_cis import iam as azure_iam
from agent_bom.cloud.azure_cis import keyvault
from agent_bom.cloud.azure_cis import networking as azure_net
from agent_bom.cloud.databricks_iam import _check_1_4 as dbx_1_4
from agent_bom.cloud.gcp_cis import bigquery, cloudsql, compute, iam_keys
from agent_bom.cloud.gcp_cis import iam as gcp_iam
from agent_bom.cloud.gcp_cis import networking as gcp_net
from agent_bom.cloud.gcp_cis import storage as gcp_storage

NA = CheckStatus.NOT_APPLICABLE
PASS = CheckStatus.PASS


def _result(status=PASS):
    return CISCheckResult(check_id="x", title="x", status=status, severity="low")


def test_helper_only_converts_an_empty_pass():
    converted = not_applicable_if_empty(_result(), 0, "bucket")
    assert converted.status is NA
    assert converted.evidence == "No bucket(s) found; this control has nothing to evaluate."
    assert converted.vacuous is True
    assert not_applicable_if_empty(_result(), 3, "bucket").status is PASS
    assert not_applicable_if_empty(_result(CheckStatus.FAIL), 0, "bucket").status is CheckStatus.FAIL
    assert not_applicable_if_empty(_result(CheckStatus.ERROR), 0, "bucket").status is CheckStatus.ERROR


def test_finalize_read_coverage_empty_is_not_applicable_and_denied_stays_error():
    empty = aws.finalize_read_coverage(_result(), inspected=0, denied=[], permission="p", resource_kind="key", pass_evidence="ok")
    assert empty.status is NA and empty.vacuous is True
    denied = aws.finalize_read_coverage(_result(), inspected=0, denied=["a"], permission="p", resource_kind="key", pass_evidence="ok")
    assert denied.status is CheckStatus.ERROR
    read = aws.finalize_read_coverage(_result(), inspected=2, denied=[], permission="p", resource_kind="key", pass_evidence="ok")
    assert read.status is PASS


def test_vacuous_flag_is_not_serialized():
    report = aws.CISBenchmarkReport(checks=[not_applicable_if_empty(_result(), 0, "key")])
    assert "vacuous" not in report.to_dict()["checks"][0]


# --- AWS ------------------------------------------------------------------------------------------


def _paged(*pages):
    client = MagicMock()
    client.get_paginator.return_value.paginate.return_value = list(pages)
    return client


def _credential_client(content):
    client = MagicMock()
    client.generate_credential_report.return_value = {"State": "COMPLETE"}
    client.get_credential_report.return_value = {"Content": content}
    return client


HEADER = (
    "user,password_last_used,access_key_1_active,access_key_1_last_rotated,"
    "access_key_2_active,access_key_2_last_rotated,user_creation_time\n"
)
ROOT_ROW = "<root_account>,N/A,false,N/A,false,N/A,N/A\n"


@pytest.mark.parametrize(
    "check,client",
    [
        (storage._check_2_3_1, _paged({"DBInstances": []})),
        (storage._check_2_3_2, _paged({"DBInstances": []})),
        (storage._check_2_4_1, _paged({"Keys": []})),
        (iam_access._check_1_10, _paged({"Users": []})),
        (iam_access._check_1_13, _paged({"Users": []})),
        (iam_access._check_1_14, _paged({"Users": []})),
        (iam_access._check_1_15, _paged({"Users": []})),
        (iam_access._check_1_19, _paged({"Reservations": []})),
        (iam_access._check_1_11, _credential_client(HEADER + ROOT_ROW)),
        (iam_access._check_1_12, _credential_client(HEADER + ROOT_ROW)),
        (networking._check_5_1, _paged({"NetworkAcls": []})),
        (networking._check_5_2, _paged({"SecurityGroups": []})),
        (networking._check_5_3, _paged({"SecurityGroups": []})),
        (networking._check_5_5, _paged({"SecurityGroups": []})),
        (networking._check_5_4, _paged({"RouteTables": []})),
    ],
)
def test_aws_empty_enumeration_is_not_applicable(check, client):
    result = check(client)
    assert result.status is NA, check.__name__
    assert result.vacuous is True


def test_aws_rds_evidence_no_longer_hedges_on_empty_and_real_pass_stays():
    clean = _paged({"DBInstances": [{"DBInstanceIdentifier": "db", "StorageEncrypted": True, "AutoMinorVersionUpgrade": True}]})
    for check in (storage._check_2_3_1, storage._check_2_3_2):
        result = check(clean)
        assert result.status is PASS
        assert "no instances found" not in result.evidence


def test_aws_security_groups_present_stay_pass():
    groups = _paged({"SecurityGroups": [{"GroupId": "sg-1", "IpPermissions": [], "IpPermissionsEgress": []}]})
    for check in (networking._check_5_2, networking._check_5_3, networking._check_5_5):
        assert check(groups).status is PASS


def test_aws_route_tables_without_peering_have_nothing_to_evaluate():
    tables = _paged({"RouteTables": [{"RouteTableId": "rtb", "Routes": [{"GatewayId": "local", "DestinationCidrBlock": "10.0.0.0/8"}]}]})
    assert networking._check_5_4(tables).status is NA
    peered = _paged(
        {"RouteTables": [{"RouteTableId": "rtb", "Routes": [{"VpcPeeringConnectionId": "pcx", "DestinationCidrBlock": "10.0.0.0/8"}]}]}
    )
    assert networking._check_5_4(peered).status is PASS


def test_aws_users_without_console_access_make_1_10_not_applicable():
    client = _paged({"Users": [{"UserName": "svc"}]})
    client.get_login_profile.side_effect = _aws_error("NoSuchEntity")
    assert iam_access._check_1_10(client).status is NA


def _aws_error(code):
    exc = Exception(code)
    exc.response = {"Error": {"Code": code}}
    return exc


def test_aws_1_14_without_active_keys_is_not_applicable():
    client = _paged({"Users": [{"UserName": "u"}]})
    client.list_access_keys.return_value = {"AccessKeyMetadata": [{"Status": "Inactive"}]}
    assert iam_access._check_1_14(client).status is NA


def test_aws_2_4_1_counts_customer_keys_not_aws_managed():
    client = _paged({"Keys": [{"KeyId": "aws-managed"}]})
    client.describe_key.return_value = {"KeyMetadata": {"KeyManager": "AWS", "KeyState": "Enabled"}}
    assert storage._check_2_4_1(client).status is NA
    client = _paged({"Keys": [{"KeyId": "cmk"}]})
    client.describe_key.return_value = {"KeyMetadata": {"KeyManager": "CUSTOMER", "KeyState": "Enabled"}}
    client.get_key_rotation_status.return_value = {"KeyRotationEnabled": True}
    result = storage._check_2_4_1(client)
    assert result.status is PASS
    assert "no keys found" not in result.evidence


def test_aws_2_4_1_unreadable_rotation_is_not_an_empty_estate():
    client = _paged({"Keys": [{"KeyId": "cmk"}]})
    client.describe_key.return_value = {"KeyMetadata": {"KeyManager": "CUSTOMER", "KeyState": "Enabled"}}
    client.get_key_rotation_status.side_effect = _aws_error("InternalFailure")
    assert storage._check_2_4_1(client).status is CheckStatus.ERROR


def test_aws_1_7_without_a_root_row_is_no_data_not_pass():
    result = iam_account._check_1_7(_credential_client(HEADER))
    assert result.status is CheckStatus.NO_DATA


def test_regional_merge_real_pass_beats_empty_region():
    real = _result(PASS)
    empty = not_applicable_if_empty(_result(), 0, "RDS instance")
    assert runner._merge_regional_cis_check(empty, real, "r2").status is PASS
    assert runner._merge_regional_cis_check(real, empty, "r2").status is PASS
    both = runner._merge_regional_cis_check(empty, not_applicable_if_empty(_result(), 0, "RDS instance"), "r2")
    assert both.status is NA and both.vacuous is True


def test_incomplete_region_scope_demotes_vacuous_but_not_manual_not_applicable():
    vacuous = not_applicable_if_empty(_result(), 0, "RDS instance")
    manual = _result(NA)
    report = aws.CISBenchmarkReport(checks=[vacuous, manual])
    runner._demote_passes_to_unknown(report, check_ids=None, reason="regions missing")
    assert vacuous.status is CheckStatus.ERROR
    assert manual.status is NA


# --- Azure ----------------------------------------------------------------------------------------


@pytest.mark.parametrize("check", [azure_iam._check_1_1, azure_iam._check_1_2])
def test_azure_no_role_assignments_is_not_applicable_but_other_assignments_pass(check):
    client = MagicMock()
    client.role_assignments.list_for_scope.return_value = []
    assert check(client, "sub").status is NA
    client.role_assignments.list_for_scope.return_value = [SimpleNamespace(role_definition_id="/x/other", principal_id="p")]
    assert check(client, "sub").status is PASS


@pytest.mark.parametrize("check", [azure_net._check_6_1, azure_net._check_6_2, azure_net._check_6_3, azure_net._check_6_4])
def test_azure_nsg_checks(check):
    client = MagicMock()
    client.network_security_groups.list_all.return_value = []
    assert check(client).status is NA
    nsg = SimpleNamespace(name="nsg", security_rules=[])
    client.network_security_groups.list_all.return_value = [nsg]
    assert check(client).status is PASS


def test_azure_pass_or_no_data_zero_is_not_applicable():
    from agent_bom.cloud.azure_cis._base import _pass_or_no_data

    result = _pass_or_no_data(_result(), 0, "SQL server", "ok")
    assert result.status is NA and result.vacuous is True
    assert _pass_or_no_data(_result(), 1, "SQL server", "ok").status is PASS


KEYVAULT_CHECKS = [
    (keyvault._check_8_1, "keys"),
    (keyvault._check_8_2, "secrets"),
    (keyvault._check_8_4, "keys"),
    (keyvault._check_8_5, "secrets"),
    (keyvault._check_8_6, "secrets"),
]


def _vault_client(*, rbac=True):
    vault = SimpleNamespace(name="v", id="/subscriptions/s/resourceGroups/rg/providers/x/vaults/v")
    client = MagicMock()
    client.vaults.list.return_value = [vault]
    client.vaults.get.return_value = SimpleNamespace(properties=SimpleNamespace(enable_rbac_authorization=rbac))
    return client


def _azure_sdk(monkeypatch, *, items=(), raises=None):
    data_client = MagicMock()
    for method in (data_client.list_properties_of_keys, data_client.list_properties_of_secrets):
        method.return_value = list(items)
        method.side_effect = raises
    monkeypatch.setitem(sys.modules, "azure.identity", SimpleNamespace(DefaultAzureCredential=MagicMock()))
    monkeypatch.setitem(sys.modules, "azure.keyvault.keys", SimpleNamespace(KeyClient=MagicMock(return_value=data_client)))
    monkeypatch.setitem(sys.modules, "azure.keyvault.secrets", SimpleNamespace(SecretClient=MagicMock(return_value=data_client)))


@pytest.mark.parametrize("check,_kind", KEYVAULT_CHECKS)
def test_azure_keyvault_empty_cases(check, _kind, monkeypatch):
    client = MagicMock()
    client.vaults.list.return_value = []
    assert check(client, "sub").status is NA
    _azure_sdk(monkeypatch)
    assert check(_vault_client(), "sub").status is NA


@pytest.mark.parametrize("check,_kind", KEYVAULT_CHECKS)
def test_azure_keyvault_real_compliant_items_stay_pass(check, _kind, monkeypatch):
    item = SimpleNamespace(name="i", expires_on="2030-01-01", content_type="text/plain")
    _azure_sdk(monkeypatch, items=[item])
    assert check(_vault_client(), "sub").status is PASS


def test_azure_keyvault_zero_items_with_a_denied_vault_is_unknown_not_empty(monkeypatch):
    readable = MagicMock()
    readable.list_properties_of_secrets.return_value = []
    denied = MagicMock()
    denied.list_properties_of_secrets.side_effect = PermissionError("denied")
    client = MagicMock()
    client.vaults.list.return_value = [SimpleNamespace(name="a"), SimpleNamespace(name="b")]
    monkeypatch.setitem(sys.modules, "azure.identity", SimpleNamespace(DefaultAzureCredential=MagicMock()))
    monkeypatch.setitem(sys.modules, "azure.keyvault.secrets", SimpleNamespace(SecretClient=MagicMock(side_effect=[readable, denied])))
    assert keyvault._check_8_2(client, "sub").status is CheckStatus.ERROR


# --- GCP ------------------------------------------------------------------------------------------


@pytest.fixture
def gcp_empty(monkeypatch):
    monkeypatch.setitem(sys.modules, "google.oauth2", SimpleNamespace(service_account=MagicMock()))
    discovery = MagicMock()
    discovery.projects.return_value.serviceAccounts.return_value.list.return_value.execute.return_value = {"accounts": []}
    discovery.projects.return_value.keys.return_value.list.return_value.execute.return_value = {"keys": []}
    discovery.projects.return_value.locations.return_value.keys.return_value.list.return_value.execute.return_value = {"keys": []}
    compute_module = MagicMock()
    for client in ("InstancesClient", "DisksClient", "SubnetworksClient"):
        getattr(compute_module, client).return_value.aggregated_list.return_value = []
    compute_module.FirewallsClient.return_value.list.return_value = []
    compute_module.NetworksClient.return_value.list.return_value = []
    storage_module = MagicMock()
    storage_module.Client.return_value.list_buckets.return_value = []
    with (
        patch.object(gcp, "_discovery_client", return_value=discovery),
        patch.object(gcp, "_import_google_cloud_module", side_effect=lambda name: {"compute_v1": compute_module}.get(name, storage_module)),
        patch.object(gcp_net, "_gcp_managed_zones", return_value=[]),
        patch.object(cloudsql, "_gcp_cloud_sql_instances", return_value=[]),
        patch.object(bigquery, "_gcp_bigquery_datasets", return_value=[]),
        patch.object(iam_keys, "_gcp_kms_crypto_keys", return_value=[]),
    ):
        yield discovery


@pytest.mark.parametrize(
    "check",
    [
        compute._check_4_1,
        compute._check_4_2,
        compute._check_4_3,
        compute._check_4_5,
        compute._check_4_6,
        compute._check_4_7,
        compute._check_4_8,
        compute._check_4_9,
        compute._check_4_11,
        gcp_net._check_3_3,
        gcp_net._check_3_4,
        gcp_net._check_3_5,
        gcp_net._check_3_6,
        gcp_net._check_3_7,
        gcp_net._check_3_8,
        gcp_net._check_3_9,
        gcp_net._check_3_10,
        bigquery._check_7_1,
        bigquery._check_7_2,
        bigquery._check_7_3,
        cloudsql._check_6_1,
        cloudsql._check_6_2,
        cloudsql._check_6_3,
        cloudsql._check_6_4,
        cloudsql._check_6_5,
        cloudsql._check_6_6,
        cloudsql._check_6_7,
        iam_keys._check_1_9,
        iam_keys._check_1_10,
        iam_keys._check_1_12,
        iam_keys._check_1_13,
        iam_keys._check_1_14,
        gcp_iam._check_1_4,
        gcp_iam._check_1_8,
    ],
)
def test_gcp_empty_enumeration_is_not_applicable(gcp_empty, check):
    result = check("project")
    assert result.status is NA, f"{check.__module__}.{check.__name__}: {result.status} {result.evidence}"


def test_gcp_storage_5_2_empty(gcp_empty):
    assert gcp_storage._check_5_2("project").status is NA


@pytest.mark.parametrize("check", [gcp_iam._check_1_1, gcp_iam._check_1_5, gcp_iam._check_1_6, gcp_iam._check_1_7, iam_keys._check_1_11])
def test_gcp_empty_iam_policy_is_not_applicable(gcp_empty, check):
    gcp_empty.projects.return_value.getIamPolicy.return_value.execute.return_value = {"bindings": []}
    assert check("project").status is NA


def test_gcp_logging_2_12_only_private_zones_are_in_scope():
    from agent_bom.cloud.gcp_cis import logging_checks

    public = {"name": "pub", "visibility": "public"}
    with patch.object(logging_checks, "_gcp_managed_zones", return_value=[public]):
        assert logging_checks._check_2_12("project").status is NA
    private = {"name": "pri", "visibility": "private", "cloudLoggingConfig": {"enableLogging": True}}
    with patch.object(logging_checks, "_gcp_managed_zones", return_value=[private]):
        assert logging_checks._check_2_12("project").status is PASS


def test_gcp_dnssec_algorithm_checks_need_dnssec_on_zones():
    off = {"name": "z", "dnssecConfig": {"state": "off"}}
    on = {"name": "z", "dnssecConfig": {"state": "on", "defaultKeySpecs": []}}
    for check in (gcp_net._check_3_4, gcp_net._check_3_5):
        with patch.object(gcp_net, "_gcp_managed_zones", return_value=[off]):
            assert check("project").status is NA
        with patch.object(gcp_net, "_gcp_managed_zones", return_value=[on]):
            assert check("project").status is PASS


@pytest.mark.parametrize("check", [cloudsql._check_6_4, cloudsql._check_6_5, cloudsql._check_6_6, cloudsql._check_6_7])
def test_gcp_postgres_flags_are_not_applicable_to_other_engines(check):
    with patch.object(cloudsql, "_gcp_cloud_sql_instances", return_value=[{"name": "m", "databaseVersion": "MYSQL_8_0"}]):
        assert check("project").status is NA


def test_gcp_postgres_instance_with_compliant_flag_still_passes():
    flags = [{"name": "log_error_verbosity", "value": "default"}]
    instance = {"name": "p", "databaseVersion": "POSTGRES_15", "settings": {"databaseFlags": flags}}
    with patch.object(cloudsql, "_gcp_cloud_sql_instances", return_value=[instance]):
        assert cloudsql._check_6_4("project").status is PASS


def test_gcp_service_accounts_without_user_keys_1_8_is_empty_but_1_4_passes(gcp_empty):
    accounts = gcp_empty.projects.return_value.serviceAccounts.return_value
    accounts.list.return_value.execute.return_value = {"accounts": [{"name": "sa", "email": "e"}]}
    accounts.keys.return_value.list.return_value.execute.return_value = {"keys": []}
    assert gcp_iam._check_1_8("project").status is NA
    assert gcp_iam._check_1_4("project").status is PASS


# --- Snowflake ------------------------------------------------------------------------------------


@pytest.mark.parametrize("check", [sf._check_1_1, sf._check_3_2])
def test_snowflake_empty_is_not_applicable(check):
    with patch.object(sf, "_run_query", return_value=[]):
        assert check(MagicMock()).status is NA


def test_snowflake_password_users_with_mfa_stay_pass():
    rows = [{"name": "u", "disabled": "false", "has_password": "true", "ext_authn_duo": "true"}]
    with patch.object(sf, "_run_query", return_value=rows):
        assert sf._check_1_1(MagicMock()).status is PASS


def test_snowflake_report_counts_no_data():
    report = sf.SnowflakeCISReport(checks=[_result(CheckStatus.NO_DATA), _result(NA)])
    payload = report.to_dict()
    assert (payload["no_data"], payload["not_applicable"]) == (1, 1)


# --- Databricks -----------------------------------------------------------------------------------


@pytest.mark.parametrize("check", [dbx._check_2_1, dbx._check_2_2, dbx._check_2_4, dbx._check_5_2])
def test_databricks_no_clusters_is_not_applicable(check):
    ws = MagicMock()
    ws.clusters.list.return_value = []
    assert check(ws).status is NA


@pytest.mark.parametrize("check", [dbx._check_2_2, dbx._check_2_4])
def test_databricks_stopped_clusters_only_is_not_applicable(check):
    ws = MagicMock()
    ws.clusters.list.return_value = [SimpleNamespace(state="TERMINATED", cluster_id="c")]
    assert check(ws).status is NA


def test_databricks_job_clusters_only_makes_auto_termination_not_applicable():
    ws = MagicMock()
    ws.clusters.list.return_value = [SimpleNamespace(cluster_source="JOB")]
    assert dbx._check_2_1(ws).status is NA


def test_databricks_admin_count_needs_enumerated_users():
    ws = MagicMock()
    ws.users.list.return_value = []
    assert dbx._check_1_1(ws).status is NA
    ws.users.list.return_value = [SimpleNamespace(roles=[], groups=[], user_name="u", id="1")]
    assert dbx._check_1_1(ws).status is PASS


def test_databricks_service_principals_and_tokens():
    ws = MagicMock()
    ws.service_principals.list.return_value = []
    assert dbx_1_4(ws).status is NA
    ws.service_principals.list.return_value = [SimpleNamespace(id=1)]
    ws.token_management.list.return_value = []
    assert dbx_1_4(ws).status is NA


def test_databricks_report_counts_unevaluated_states():
    report = dbx.DatabricksSecurityReport(checks=[_result(CheckStatus.NO_DATA), _result(NA), _result(CheckStatus.ERROR), _result(PASS)])
    payload = report.to_dict()
    assert (payload["no_data"], payload["not_applicable"], payload["errored"]) == (1, 1, 1)
    assert payload["passed"] == 1 and payload["total"] == 4


def test_azure_module_still_reexports_helper_name():
    assert hasattr(azure, "_pass_or_no_data")
