"""Distribution identity must survive repository transfers without false freshness."""

from __future__ import annotations

import copy
import importlib.util
import io
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def manifest():
    return json.loads((ROOT / "integrations/mcp-registry/server.json").read_text())


def test_repository_namespace_and_packaged_readme_agree(manifest):
    assert manifest["name"] == "io.github.koda-ai-studio/agent-bom"
    assert manifest["repository"]["url"] == "https://github.com/koda-ai-studio/agent-bom"
    for path in ("README.md", "docs/registry/PYPI_README.md"):
        assert f"<!-- mcp-name: {manifest['name']} -->" in (ROOT / path).read_text()


def test_identity_guard_rejects_old_namespace_even_if_readmes_agree(manifest):
    script = load("check_mcp_registry_identity")
    manifest["name"] = "io.github.msaad00/agent-bom"
    with pytest.raises(ValueError, match="namespace"):
        script.validate_identity(manifest, "koda-ai-studio/agent-bom", "mcp-name: io.github.msaad00/agent-bom")


@pytest.mark.parametrize("suffix", ["-other", "/extra", ".other"])
def test_identity_guard_rejects_prefix_only_ownership(manifest, suffix):
    script = load("check_mcp_registry_identity")
    with pytest.raises(ValueError, match="ownership marker"):
        script.validate_identity(manifest, "koda-ai-studio/agent-bom", f"mcp-name: {manifest['name']}{suffix}")


def test_identity_guard_accepts_exact_published_marker(manifest):
    load("check_mcp_registry_identity").validate_identity(manifest, "koda-ai-studio/agent-bom", f"<!-- mcp-name: {manifest['name']} -->")


@pytest.mark.parametrize("published_name,exit_code", [("io.github.msaad00/agent-bom", 1), ("io.github.koda-ai-studio/agent-bom", 0)])
def test_publication_guard_checks_exact_versioned_pypi_metadata(monkeypatch, manifest, published_name, exit_code):
    script = load("check_mcp_registry_identity")
    requested = []

    def fetch(url, **kw):
        requested.append(url)
        return io.BytesIO(
            json.dumps(
                {"info": {"name": "agent-bom", "version": manifest["version"], "description": f"mcp-name: {published_name}"}}
            ).encode()
        )

    monkeypatch.setattr(script.urllib.request, "urlopen", fetch)
    assert script.main(["--published", "--repository", "koda-ai-studio/agent-bom"]) == exit_code
    assert requested == [f"https://pypi.org/pypi/agent-bom/{manifest['version']}/json"]


def registry_response(manifest):
    return {
        "server": copy.deepcopy(manifest),
        "_meta": {"io.modelcontextprotocol.registry/official": {"status": "active", "isLatest": True}},
    }


def test_registry_probe_accepts_semantically_equal_default_flags(monkeypatch, manifest):
    script = load("check_surface_freshness")
    response = registry_response(manifest)
    package = response["server"]["packages"][0]
    for arg in package["packageArguments"]:
        arg.pop("isRepeated", None)
    package["environmentVariables"][0].pop("isRequired", None)
    urls = []

    def fetch(url, **kw):
        urls.append(url)
        return response

    monkeypatch.setattr(script, "_http_json", fetch)
    result = script.probe_mcp_registry(manifest["version"], manifest)
    assert result["status"] == "fresh"
    assert result["installation_contract_matches"] is True
    assert urls == ["https://registry.modelcontextprotocol.io/v0.1/servers/io.github.koda-ai-studio%2Fagent-bom/versions/latest"]


@pytest.mark.parametrize(
    "mutation",
    [
        "version",
        "package_version",
        "name",
        "repository",
        "description",
        "arguments",
        "transport",
        "duplicate_package",
        "inactive",
        "not_latest",
    ],
)
def test_registry_probe_rejects_drift(monkeypatch, manifest, mutation):
    script = load("check_surface_freshness")
    response = registry_response(manifest)
    server = response["server"]
    if mutation in {"version", "name", "description"}:
        server[mutation] = "different"
    elif mutation == "repository":
        server["repository"]["url"] = "https://github.com/msaad00/agent-bom"
    elif mutation == "package_version":
        server["packages"][0]["version"] = "0.1.0"
    elif mutation == "arguments":
        server["packages"][0]["packageArguments"].append({"type": "positional", "value": "--profile=full"})
    elif mutation == "transport":
        server["packages"][0]["transport"] = {"type": "streamable-http"}
    elif mutation == "duplicate_package":
        server["packages"].append(copy.deepcopy(server["packages"][0]))
    else:
        response["_meta"]["io.modelcontextprotocol.registry/official"].update(
            {"status": "deleted"} if mutation == "inactive" else {"isLatest": False}
        )
    monkeypatch.setattr(script, "_http_json", lambda *a, **kw: response)
    result = script.probe_mcp_registry(manifest["version"], manifest)
    assert result["status"] == "stale"
    assert result["error"]


@pytest.mark.parametrize("response", [None, [], {}, {"server": []}, {"server": {"version": "1.0.0"}, "_meta": None}])
def test_registry_probe_malformed_is_unreachable(monkeypatch, manifest, response):
    script = load("check_surface_freshness")
    monkeypatch.setattr(script, "_http_json", lambda *a, **kw: response)
    assert script.probe_mcp_registry(manifest["version"], manifest)["status"] == "unreachable"


def test_registry_probe_network_failure_is_not_fresh(monkeypatch, manifest):
    script = load("check_surface_freshness")

    def fail(*a, **kw):
        raise RuntimeError("HTTP 404")

    monkeypatch.setattr(script, "_http_json", fail)
    result = script.probe_mcp_registry(manifest["version"], manifest)
    assert result["status"] == "unreachable"
    assert result["error"] == "HTTP 404"


def test_registry_probe_rejects_a_manifest_from_a_different_release(monkeypatch, manifest):
    script = load("check_surface_freshness")
    response = registry_response(manifest)
    response["server"]["version"] = "0.1.0"
    response["server"]["packages"][0]["version"] = "0.1.0"
    monkeypatch.setattr(script, "_http_json", lambda *a, **kw: response)
    assert script.probe_mcp_registry("0.1.0", manifest)["status"] == "unreachable"


def test_official_registry_drift_blocks_consolidated_success(monkeypatch, manifest, tmp_path, capsys):
    script = load("check_surface_freshness")
    for probe, name in [("probe_pypi", "PyPI"), ("probe_docker", "Docker"), ("probe_glama", "Glama"), ("probe_smithery", "Smithery")]:
        monkeypatch.setattr(script, probe, lambda *a, _name=name, **kw: {"surface": _name, "status": "fresh"})
    response = registry_response(manifest)
    response["server"]["version"] = "0.1.0"
    monkeypatch.setattr(script, "_http_json", lambda *a, **kw: response)
    assert script.main(["--expected", manifest["version"], "--expected-tool-count", "8", "--fail-on-stale"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["all_required_fresh"] is False
    row = next(row for row in report["surfaces"] if row["surface"] == "MCP Registry")
    assert row["required"] is True


def test_publishing_checks_package_ownership_before_requesting_oidc():
    workflow = (ROOT / ".github/workflows/publish-mcp-registry.yml").read_text()
    assert workflow.index("scripts/check_mcp_registry_identity.py --published") < workflow.index("- name: Get GitHub OIDC token")


def test_freshness_reads_manifest_from_exact_release():
    workflow = (ROOT / ".github/workflows/surface-freshness.yml").read_text()
    assert "${RELEASE_SHA}:integrations/mcp-registry/server.json" in workflow
    assert "--mcp-registry-manifest /tmp/surface-mcp-registry.json" in workflow
