"""The marketplace oracle must come from the published package, not its host."""

from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def load_script():
    spec = importlib.util.spec_from_file_location("release_contract", ROOT / "scripts/export_release_mcp_contract.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_release_install_is_exact_isolated_and_has_no_publishing_credentials(monkeypatch):
    script = load_script()
    calls = []
    expected = [{"name": "exposure_paths", "inputSchema": {"type": "object", "properties": {}}}]

    def run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps(expected), stderr="")

    monkeypatch.setenv("GLAMA_API_KEY", "must-not-reach-release-process")
    monkeypatch.setenv("PYTHONPATH", "/mutable-checkout/src")
    monkeypatch.setenv("PIP_INDEX_URL", "https://untrusted.invalid/simple")
    monkeypatch.setattr(script.subprocess, "run", run)
    assert script.export_contract("0.105.0", ["exposure_paths"]) == expected
    install = calls[1][0]
    assert install[-1] == "agent-bom==0.105.0"
    assert "--isolated" in install and "--only-binary=:all:" in install
    assert install[install.index("--index-url") + 1] == "https://pypi.org/simple"
    for command, kwargs in calls:
        assert "-I" in command
        assert not {"GLAMA_API_KEY", "PYTHONPATH", "PIP_INDEX_URL"}.intersection(kwargs["env"])
        assert kwargs["timeout"] <= 300


@pytest.mark.parametrize("version", ["main", "0.106.0 --extra-index-url evil", "0.105.0rc1", "../0.105.0"])
def test_release_install_rejects_non_release_version_before_subprocess(version, monkeypatch):
    script = load_script()
    monkeypatch.setattr(script.subprocess, "run", lambda *_a, **_kw: pytest.fail("must not execute"))
    with pytest.raises(ValueError, match="stable version"):
        script.export_contract(version, ["scan"])


_FULL_CONTRACT = [{"name": name, "inputSchema": {"type": "object"}} for name in ("check", "remediate", "scan")]
_READ_ONLY_CONTRACT = [tool for tool in _FULL_CONTRACT if tool["name"] != "scan"]


def _fake_extract(read_only_reply):
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        if "-c" not in command:
            return subprocess.CompletedProcess(command, 0, "", "")
        reply = read_only_reply if command[-1] == "oauth" else _FULL_CONTRACT
        return subprocess.CompletedProcess(command, 0, json.dumps(reply), "")

    return calls, run


def test_release_export_also_derives_the_oauth_read_only_contract(monkeypatch):
    """One isolated install yields the default contract and the OAuth-registered subset."""
    script = load_script()
    calls, run = _fake_extract(_READ_ONLY_CONTRACT)
    monkeypatch.setattr(script.subprocess, "run", run)
    default, read_only = script.export_contracts("0.114.0", ["check", "remediate", "scan"])
    assert default == _FULL_CONTRACT
    assert read_only == _READ_ONLY_CONTRACT
    extracts = [command for command in calls if "-c" in command]
    assert [command[-1] for command in extracts] == ["default", "oauth"]
    assert sum("pip" in command for command in calls) == 1


@pytest.mark.parametrize(
    "reply",
    [[], [{"name": "endpoint_sync", "inputSchema": {}}], _FULL_CONTRACT + [{"name": "graph_correlate", "inputSchema": {}}]],
)
def test_release_oauth_contract_must_be_a_non_empty_subset_of_immutable_names(monkeypatch, reply):
    script = load_script()
    _calls, run = _fake_extract(reply)
    monkeypatch.setattr(script.subprocess, "run", run)
    with pytest.raises(ValueError):
        script.export_contracts("0.114.0", ["check", "remediate", "scan"])


def test_extract_oauth_mode_runs_the_release_registration_filter(monkeypatch, capsys):
    """Execute the extraction code against this checkout: the OAuth subset is what the server registers."""
    import importlib.metadata
    import sys

    from agent_bom import __version__
    from agent_bom.mcp_tools import profiles

    script = load_script()
    monkeypatch.setattr(importlib.metadata, "version", lambda _name: __version__)
    monkeypatch.setattr(profiles, "configure_registration", profiles.configure_registration)
    monkeypatch.setattr(sys, "argv", ["extract", __version__, "oauth"])
    exec(script.EXTRACT, {})
    names = [tool["name"] for tool in json.loads(capsys.readouterr().out)]
    assert names == sorted(profiles.registered_tool_names("scan", read_only=True) or ())
    assert "scan" not in names


def test_extract_oauth_mode_rejects_a_write_tool(monkeypatch):
    import importlib.metadata
    import sys
    import types

    from pydantic import BaseModel, Field

    class Tool(BaseModel):
        name: str
        input_schema: dict = Field(alias="inputSchema")
        annotations: dict

    seen = []
    profiles = types.ModuleType("agent_bom.mcp_tools.profiles")

    def configure_registration(mcp, name, *, read_only=False):
        seen.append(read_only)

    profiles.configure_registration = configure_registration

    class Server:
        async def list_tools(self):
            return [Tool(name="scan", inputSchema={}, annotations={"readOnlyHint": False})]

    def create_mcp_server(**_kwargs):
        sys.modules["agent_bom.mcp_tools.profiles"].configure_registration(None, "scan", read_only=False)
        return Server()

    package = types.ModuleType("agent_bom")
    package.__version__ = "0.114.0"
    tools_package = types.ModuleType("agent_bom.mcp_tools")
    tools_package.profiles = profiles
    server = types.ModuleType("agent_bom.mcp_server")
    server.create_mcp_server = create_mcp_server
    for name, module in (
        ("agent_bom", package),
        ("agent_bom.mcp_tools", tools_package),
        ("agent_bom.mcp_tools.profiles", profiles),
        ("agent_bom.mcp_server", server),
    ):
        monkeypatch.setitem(sys.modules, name, module)
    monkeypatch.setattr(importlib.metadata, "version", lambda _name: "0.114.0")
    monkeypatch.setattr(sys, "argv", ["extract", "0.114.0", "oauth"])
    with pytest.raises(SystemExit, match="non-read-only"):
        exec(load_script().EXTRACT, {})
    assert seen == [True]


@pytest.mark.parametrize("contract", [[], [{"name": "new_tool", "inputSchema": {}}], [{"name": "scan", "inputSchema": None}]])
def test_release_contract_must_match_immutable_names(contract, monkeypatch):
    script = load_script()
    monkeypatch.setattr(script.subprocess, "run", lambda command, **_kw: subprocess.CompletedProcess(command, 0, json.dumps(contract), ""))
    with pytest.raises(ValueError):
        script.export_contract("0.105.0", ["scan"])


def test_registry_workflows_never_use_hosted_card_as_schema_oracle():
    for name in ("surface-freshness.yml", "deployment-freshness.yml", "publish-registries.yml"):
        text = (ROOT / ".github/workflows" / name).read_text()
        assert "scripts/export_release_mcp_contract.py" in text
        assert "--write-tool-contract" not in text
        assert "server-card.json > /tmp/smithery-expected-tool-contract.json" not in text
    publish = (ROOT / ".github/workflows/publish-registries.yml").read_text()
    assert "smithery" not in yaml.safe_load(publish)["jobs"]
    assert "--expected-tool-contract-file /tmp/glama-expected-tool-contract.json" in publish
    deployment = (ROOT / ".github/workflows/deployment-freshness.yml").read_text()
    assert '--compare-tool-contract-files "$EXPECTED_CONTRACT" /tmp/railway-actual-tool-contract.json' in deployment
    assert "--read-only-out /tmp/deployment-expected-read-only-tool-contract.json" in deployment
    assert "--expected-read-only-tool-names-file /tmp/deployment-expected-read-only-tool-names.json" in deployment


@pytest.mark.parametrize("scheme", ["bearer", "oauth2"])
@pytest.mark.parametrize("schema_drift", [False, True])
def test_same_version_deployment_schema_drift_stays_failed(tmp_path, schema_drift, scheme):
    workflow = yaml.safe_load((ROOT / ".github/workflows/deployment-freshness.yml").read_text())
    step = next(step for step in workflow["jobs"]["check"]["steps"] if step.get("id") == "railway")
    script = step["run"]
    read_only = [{"name": "exposure_paths", "inputSchema": {"type": "object", "properties": {}}}]
    full = [*read_only, {"name": "scan", "inputSchema": {"type": "object", "properties": {}}}]
    actual = json.loads(json.dumps(read_only if scheme == "oauth2" else full))
    if schema_drift:
        actual[0]["inputSchema"]["properties"]["cursor"] = {"type": "string"}
    (tmp_path / "deployment-expected-tool-contract.json").write_text(json.dumps(full))
    (tmp_path / "deployment-expected-read-only-tool-contract.json").write_text(json.dumps(read_only))
    card = tmp_path / "card.json"
    authentication = {"required": True, "schemes": [scheme]}
    card.write_text(json.dumps({"serverInfo": {"version": "0.105.0"}, "tools": actual, "authentication": authentication}))
    script = re.sub(r"if RESPONSE=\$\(PYTHONPATH=src .*?\); then", f'if RESPONSE=$(cat "{card}"); then', script, flags=re.S)
    script = script.replace("/tmp/", str(tmp_path) + "/")
    # Replace the one mock response path after redirecting workflow artifacts.
    script = re.sub(r'if RESPONSE=\$\(cat ".*?"\); then', f'if RESPONSE=$(cat "{card}"); then', script)
    output = tmp_path / "outputs"
    result = subprocess.run(
        ["bash", "-c", script], cwd=ROOT, env={**os.environ, "GITHUB_OUTPUT": str(output)}, capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr
    outputs = dict(line.split("=", 1) for line in output.read_text().splitlines())
    assert outputs["probe_failed"] == ("true" if schema_drift else "false")
    assert ("schema drift" in outputs["railway_version"]) == schema_drift


@pytest.mark.parametrize("schema_attribute", ["inputSchema", "input_schema"])
def test_extract_handles_published_and_current_mcp_schema_models(monkeypatch, capsys, schema_attribute):
    """Execute the extraction code against both SDK field spellings."""
    import importlib.metadata
    import sys
    import types

    from pydantic import Field, create_model

    script = load_script()
    tool_model = create_model("Tool", name=(str, ...), **{schema_attribute: (dict, Field(alias="inputSchema"))})
    schema = {"type": "object", "properties": {"cursor": {"type": "string"}}}

    class Server:
        async def list_tools(self):
            return [tool_model(name="scan", inputSchema=schema)]

    package = types.ModuleType("agent_bom")
    package.__version__ = "0.108.4"
    server = types.ModuleType("agent_bom.mcp_server")
    server.create_mcp_server = lambda **_kwargs: Server()
    monkeypatch.setitem(sys.modules, "agent_bom", package)
    monkeypatch.setitem(sys.modules, "agent_bom.mcp_server", server)
    monkeypatch.setattr(importlib.metadata, "version", lambda _name: "0.108.4")
    monkeypatch.setattr(sys, "argv", ["extract", "0.108.4"])
    exec(script.EXTRACT, {})
    assert json.loads(capsys.readouterr().out) == [{"name": "scan", "inputSchema": schema}]
