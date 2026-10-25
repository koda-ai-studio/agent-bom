"""A cloud command without its provider SDK stops before any scanning, with one install line."""

from __future__ import annotations

import sys

import pytest
from click.testing import CliRunner

from agent_bom.cli import main

_HIDDEN = {
    "aws": ("boto3",),
    "azure": ("azure", "azure.identity"),
    "gcp": ("google.cloud.aiplatform", "google.cloud.functions_v2", "google.cloud.container_v1", "google.cloud.run_v2"),
}


@pytest.mark.parametrize("provider", ["aws", "azure", "gcp"])
def test_cloud_provider_without_its_sdk_fails_fast_with_the_install_hint(provider, monkeypatch):
    for module in _HIDDEN[provider]:
        monkeypatch.setitem(sys.modules, module, None)

    def no_discovery(*_args, **_kwargs):
        raise AssertionError("a missing SDK must stop the run before any discovery")

    monkeypatch.setattr("agent_bom.cli.agents._discovery.run_local_discovery", no_discovery)
    result = CliRunner().invoke(main, ["cloud", provider])

    assert result.exit_code == 1
    assert f"pip install 'agent-bom[{provider}]'" in result.output
    assert result.output.count("pip install") == 1
    assert "scan verdict" not in result.output
    assert "installed but not configured" not in result.output
