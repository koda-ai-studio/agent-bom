"""CLI cloud targets follow explicit overrides before the signed-in context."""

import subprocess
from unittest.mock import Mock

import pytest
from click.testing import CliRunner

from agent_bom.cli import main


@pytest.mark.parametrize(
    "provider,field,target,envvar,flag",
    [
        ("azure", "azure_subscription", "00000000-0000-4000-8000-000000000001", "AZURE_SUBSCRIPTION_ID", "--subscription"),
        ("gcp", "gcp_project", "fixture-project", "GOOGLE_CLOUD_PROJECT", "--project"),
    ],
)
@pytest.mark.parametrize("source", ["active", "environment", "explicit"])
def test_cloud_command_resolves_selected_target_before_all_collectors(monkeypatch, provider, field, target, envvar, flag, source):
    seen = []
    monkeypatch.setattr("agent_bom.cli.agents.scan.callback", lambda **kwargs: seen.append(kwargs))
    monkeypatch.setattr("agent_bom.cli._cloud_sdk.providers_missing_sdk", lambda providers: [])
    monkeypatch.setattr("agent_bom.cloud.gcp_inv._base._derive_default_project", lambda: ("", ""))
    monkeypatch.setattr("shutil.which", lambda name: "/fixture/bin/" + name)
    run = Mock(return_value=subprocess.CompletedProcess([], 0, stdout=target + "\n", stderr=""))
    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.delenv(envvar, raising=False)
    args = ["cloud", provider, "--quiet"]
    if source == "environment":
        monkeypatch.setenv(envvar, target)
    elif source == "explicit":
        monkeypatch.setenv(envvar, "unselected-environment")
        args.extend([flag, target])
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 0, result.output
    assert seen[0][field] == target
    if source == "active":
        assert run.call_count == 1
        assert run.call_args.kwargs["timeout"] <= 5
        assert run.call_args.kwargs.get("shell", False) is False
    else:
        run.assert_not_called()


@pytest.mark.parametrize("output", ["", "(unset)", "null", "one\ntwo", "\x1bfixture", "x" * 256])
def test_invalid_cli_project_output_does_not_select_a_target(monkeypatch, output):
    from agent_bom.cli._cloud_group import _active_cloud_target

    monkeypatch.setattr("agent_bom.cloud.gcp_inv._base._derive_default_project", lambda: ("", ""))
    monkeypatch.setattr("shutil.which", lambda name: "/fixture/bin/" + name)
    monkeypatch.setattr(subprocess, "run", Mock(return_value=subprocess.CompletedProcess([], 0, stdout=output, stderr="")))
    assert _active_cloud_target("gcp") is None


def test_adc_project_takes_precedence_over_unrelated_cli_configuration(monkeypatch):
    from agent_bom.cli._cloud_group import _active_cloud_target

    monkeypatch.setattr("agent_bom.cloud.gcp_inv._base._derive_default_project", lambda: ("credential-project", ""))
    run = Mock(side_effect=AssertionError("must not read a different CLI context"))
    monkeypatch.setattr(subprocess, "run", run)
    assert _active_cloud_target("gcp") == "credential-project"
    run.assert_not_called()


def test_cli_timeout_does_not_abort_other_providers(monkeypatch):
    from agent_bom.cli._cloud_group import _active_cloud_target

    monkeypatch.setattr("shutil.which", lambda name: "/fixture/bin/" + name)
    monkeypatch.setattr(subprocess, "run", Mock(side_effect=subprocess.TimeoutExpired("az", 5)))
    assert _active_cloud_target("azure") is None


@pytest.mark.parametrize("provider,flag", [("azure", "--subscription"), ("gcp", "--project")])
def test_missing_scope_guidance_names_the_provider_command_flag(provider, flag):
    from agent_bom.cloud.base import missing_scope_hint

    assert f"Pass {flag} to `agent-bom cloud {provider}`" in missing_scope_hint(provider)
