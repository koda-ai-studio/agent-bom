"""Manifest evidence must not invent versions or demote exact pins."""

import pytest

from agent_bom.models import Severity, Vulnerability
from agent_bom.parsers.pypi_resolution import ResolutionResult, ResolvedDistribution
from agent_bom.parsers.python_parsers import parse_pip_packages
from agent_bom.python_agents import scan_python_agents
from agent_bom.scanners.registry_selected_policy import demote_registry_selected


def test_mixed_requirements_keep_exact_pin_findings(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("urllib3==1.26.4\ndjango==3.2.25\nidna>=3.0\n")
    resolved = {
        name: ResolvedDistribution(name, version, constraint, None, 0)
        for name, version, constraint in [("urllib3", "1.26.4", "==1.26.4"), ("django", "3.2.25", "==3.2.25"), ("idna", "3.7", ">=3.0")]
    }
    monkeypatch.setattr("agent_bom.parsers.python_ladder.is_offline", lambda: False)
    monkeypatch.setattr("agent_bom.parsers.python_ladder.resolve_requirements", lambda roots: ResolutionResult(resolved=resolved))
    packages = {p.name: p for p in parse_pip_packages(tmp_path)}
    for pkg in packages.values():
        pkg.vulnerabilities = [Vulnerability(id="CVE-2024-0001", severity=Severity.HIGH, summary="Fixture")]
    demote_registry_selected(list(packages.values()))
    for name in ("urllib3", "django"):
        assert not packages[name].floating_reference
        assert packages[name].vulnerabilities
        assert not packages[name].possibly_affected
    assert packages["idna"].floating_reference
    assert not packages["idna"].vulnerabilities
    assert packages["idna"].possibly_affected


@pytest.mark.parametrize("manifest", ["requirements.txt", "pyproject.toml"])
@pytest.mark.parametrize("constraint", [">=0.0.100", "~=0.0.100", "==0.0.*", "!=0.0.100"])
def test_framework_declaration_does_not_invent_installed_version(tmp_path, manifest, constraint):
    declaration = "langchain" + constraint
    content = declaration if manifest.endswith(".txt") else f'[project]\nname="app"\ndependencies=["{declaration}"]\n'
    (tmp_path / manifest).write_text(content)
    agents, _ = scan_python_agents(str(tmp_path))
    packages = [p for a in agents for s in a.mcp_servers for p in s.packages if p.name == "langchain"]
    assert packages
    assert all(p.version == "unknown" for p in packages)
    assert all(p.purl is None or "@0.0.100" not in p.purl for p in packages)


@pytest.mark.parametrize("lock", ["poetry.lock", "uv.lock"])
def test_independent_exact_requirements_survive_lockfile(tmp_path, lock):
    (tmp_path / lock).write_text('version = 1\n[[package]]\nname = "idna"\nversion = "3.7"\n')
    (tmp_path / "requirements.txt").write_text("urllib3==1.26.4\nidna==3.7\n")
    packages = parse_pip_packages(tmp_path)
    assert sorted((p.name, p.version) for p in packages) == [("idna", "3.7"), ("urllib3", "1.26.4")]
