"""Saved Databricks connections must use only their scoped credential and real dispatch."""

import sys
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock

import pytest

from agent_bom.cloud.connection_request import ephemeral_connection_record


def test_broker_uses_explicit_host_and_encrypted_token(monkeypatch):
    from agent_bom.cloud.connection_broker import broker_session

    sdk = ModuleType("databricks.sdk")
    sdk.WorkspaceClient = Mock(return_value=object())
    core = ModuleType("databricks.sdk.core")
    core.Config = Mock(return_value=object())
    monkeypatch.setitem(sys.modules, "databricks.sdk.core", core)
    monkeypatch.setitem(sys.modules, "databricks.sdk", sdk)
    with ephemeral_connection_record(
        provider="databricks", display_name="workspace", role_ref="https://demo.cloud.databricks.com", external_id="private-token"
    ) as record:
        result = broker_session(record)
    assert result is sdk.WorkspaceClient.return_value
    sdk.WorkspaceClient.assert_called_once_with(config=core.Config.return_value)
    core.Config.assert_called_once_with(
        host="https://demo.cloud.databricks.com", token="private-token", auth_type="pat", http_timeout_seconds=10, retry_timeout_seconds=10
    )


def test_databricks_probe_is_a_bounded_read():
    from agent_bom.cloud.capability_probe import probe_read_capability

    client = SimpleNamespace(clusters=SimpleNamespace(list=Mock(return_value=iter([object()]))))
    assert probe_read_capability("databricks", client, regions=[], auth_params={}).capabilities == ("databricks:clusters-list",)
    client.clusters.list.assert_called_once_with()


def test_databricks_dispatch_is_supported_everywhere():
    from agent_bom.api.connection_scheduler import _SCHEDULABLE_PROVIDERS
    from agent_bom.api.connection_store import SUPPORTED_PROVIDERS
    from agent_bom.api.routes.cloud import _CIS_PROVIDERS
    from agent_bom.api.routes.cloud_connections import _SCAN_RUNNERS

    for values in (SUPPORTED_PROVIDERS, _SCHEDULABLE_PROVIDERS, _CIS_PROVIDERS, _SCAN_RUNNERS):
        assert "databricks" in values


def test_permission_denial_cannot_become_a_clean_security_check():
    from agent_bom.cloud.aws_cis_benchmark import CheckStatus
    from agent_bom.cloud.databricks_security import _check_1_4

    denied = Mock(side_effect=RuntimeError("token=private-token customer-path"))
    ws = SimpleNamespace(service_principals=SimpleNamespace(list=denied))
    result = _check_1_4(ws)
    assert result.status == CheckStatus.ERROR
    assert "private-token" not in result.evidence


@pytest.mark.parametrize(
    "host",
    [
        "http://demo.cloud.databricks.com",
        "https://127.0.0.1",
        "https://demo.cloud.databricks.com.evil.test",
        "https://token@demo.cloud.databricks.com",
        "https://demo.cloud.databricks.com/?token=secret",
        "https://demo.cloud.databricks.com/api",
    ],
)
def test_workspace_origin_rejected_before_decrypt(monkeypatch, host):
    from agent_bom.cloud import connection_broker as broker

    decrypt = Mock(side_effect=AssertionError("must reject before decrypt"))
    monkeypatch.setattr(broker, "_decrypt_or_fail", decrypt)
    with pytest.raises(broker.ConnectionBrokerError):
        broker.broker_session(SimpleNamespace(provider="databricks", role_ref=host, auth_params={}))
    decrypt.assert_not_called()


@pytest.mark.parametrize("extra", [{"scan_mode": "continuous"}, {"inventory_scope": "organization"}, {"regions": ["us-east-1"]}])
def test_unsupported_databricks_modes_rejected(extra):
    from pydantic import ValidationError

    from agent_bom.api.routes.cloud_connections import CloudConnectionCreate

    with pytest.raises(ValidationError):
        CloudConnectionCreate(provider="databricks", display_name="workspace", role_ref="https://demo.cloud.databricks.com", **extra)


def test_connection_scan_uses_scoped_client_and_marks_partial(monkeypatch):
    from agent_bom.api import databricks_connection_scan as runner
    from agent_bom.cloud import databricks, databricks_security

    client = object()
    monkeypatch.setattr(runner, "broker_session", lambda record: client)
    discover = Mock(return_value=([], ["permission denied"]))
    checks = Mock(return_value=SimpleNamespace(to_dict=lambda: {"checks": [{"status": "error"}], "total": 1}))
    monkeypatch.setattr(databricks, "discover", discover)
    monkeypatch.setattr(databricks_security, "run_security_checks", checks)
    saved = []

    def persist(record, tenant, report, **kwargs):
        saved.append(report)
        return "scan-1"

    with ephemeral_connection_record(
        provider="databricks", display_name="workspace", role_ref="https://demo.cloud.databricks.com", external_id="private-token"
    ) as record:
        result = runner.run_databricks_connection_scan(record, record.tenant_id, persist=persist)
        with pytest.raises(ValueError, match="tenant"):
            runner.run_databricks_connection_scan(record, "other", persist=persist)
    discover.assert_called_once_with(host=record.role_ref, workspace_client=client)
    checks.assert_called_once_with(host=record.role_ref, workspace_client=client)
    assert len(saved) == 1 and saved[0].scan_run.outcome.value == "partial"
    assert result["scan_id"] == "scan-1" and result["audit_metadata"]["writes_performed"] is False


def test_permission_probe_returns_only_stable_code():
    from agent_bom.cloud.capability_probe import CapabilityProbeError, probe_read_capability

    class PermissionDenied(Exception):  # noqa: N818 - matches provider SDK exception name
        pass

    client = SimpleNamespace(clusters=SimpleNamespace(list=Mock(side_effect=PermissionDenied("private-token"))))
    with pytest.raises(CapabilityProbeError, match="^permission_denied$"):
        probe_read_capability("databricks", client, regions=[], auth_params={})


def test_benchmark_route_dispatch_keeps_vendor_provenance(monkeypatch):
    from agent_bom.api.routes.cloud import _run_cis_benchmark
    from agent_bom.cloud import databricks_security

    run = Mock(return_value=SimpleNamespace(to_dict=lambda: {"benchmark": "Databricks Security Best Practices", "checks": []}))
    monkeypatch.setattr(databricks_security, "run_security_checks", run)
    result = _run_cis_benchmark("tenant-a", "databricks", ["1.4"], None, None, "", "")
    run.assert_called_once_with(checks=["1.4"])
    assert result["benchmark"] == "Databricks Security Best Practices"
    assert result["tenant_id"] == "tenant-a"
    assert result["audit_metadata"]["writes_performed"] is False


def test_cli_databricks_guidance_has_real_verification_and_no_fake_generator():
    from click.testing import CliRunner

    from agent_bom.cli._entry_points import connect_group

    result = CliRunner().invoke(connect_group, ["databricks", "--help"])
    assert result.exit_code == 0
    assert "--host" in result.output and "--token-file" in result.output
    assert "--emit" not in result.output


def test_cli_workspace_command_reaches_bounded_local_verification(monkeypatch, tmp_path):
    from click.testing import CliRunner

    from agent_bom.cli import _entry_points as cli

    token = tmp_path / "token"
    token.write_text("private-token")
    verify = Mock()
    monkeypatch.setattr(cli, "_local_verify", verify)
    result = CliRunner().invoke(
        cli.connect_group, ["databricks", "--host", "https://demo.cloud.databricks.com", "--token-file", str(token)]
    )
    assert result.exit_code == 0, result.output
    assert verify.call_args.kwargs["external_id"] == "private-token"
    assert verify.call_args.kwargs["role_ref"] == "https://demo.cloud.databricks.com"
    assert "private-token" not in result.output


def test_installed_sdk_constructs_scoped_client_with_mocked_transport(monkeypatch):
    pytest.importorskip("databricks.sdk")
    from agent_bom.cloud.databricks_connection import workspace_client

    monkeypatch.setenv("DATABRICKS_HOST", "https://ambient.cloud.databricks.com")
    monkeypatch.setenv("DATABRICKS_TOKEN", "ambient-token")
    import requests

    response = requests.Response()
    response.status_code = 200
    response._content = b"{}"
    request = Mock(return_value=response)
    monkeypatch.setattr("requests.sessions.Session.request", request)
    client = workspace_client("https://scoped.cloud.databricks.com", "scoped-token")
    assert client.config.host == "https://scoped.cloud.databricks.com"
    assert client.config.auth_type == "pat"
    assert client.config.http_timeout_seconds == 10
    assert client.config.authenticate()["Authorization"] == "Bearer scoped-token"
    assert client.config.retry_timeout_seconds == 10
    request.assert_called_once()
    assert request.call_args.args[:2] == ("GET", "https://scoped.cloud.databricks.com/.well-known/databricks-config")
    assert request.call_args.kwargs["auth"] is None
