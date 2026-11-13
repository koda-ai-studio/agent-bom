"""Who gets the source budget: an interactive, ungated scan, or an explicit --quick."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from agent_bom.cli.agents.scan_pipeline import budget_policy
from agent_bom.core.scan_budget import DEFAULT_SOURCE_BUDGET

_CI_VARS = ("CI", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL", "CIRCLECI", "TRAVIS", "TF_BUILD", "BITBUCKET_PIPELINE_UUID", "BUILDKITE")


def _opts(**overrides):
    base = {"full_analysis": False, "quick": False, "output_format": "console"}
    base.update(overrides)
    return SimpleNamespace(**base)


@pytest.fixture
def terminal(monkeypatch):
    for name in _CI_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("AGENT_BOM_AGENT_MODE", raising=False)
    monkeypatch.setattr(budget_policy.sys, "argv", ["agent-bom", "scan"])
    monkeypatch.setattr(budget_policy.sys.stdout, "isatty", lambda: True, raising=False)


def test_interactive_ungated_scan_gets_the_budget(terminal):
    assert budget_policy.scan_source_budget(_opts()) == DEFAULT_SOURCE_BUDGET


@pytest.mark.parametrize("ci_var", _CI_VARS)
def test_any_ci_environment_keeps_full_analysis(terminal, monkeypatch, ci_var):
    monkeypatch.setenv(ci_var, "true")

    assert budget_policy.scan_source_budget(_opts()) is None


def test_piped_output_keeps_full_analysis(terminal, monkeypatch):
    monkeypatch.setattr(budget_policy.sys.stdout, "isatty", lambda: False, raising=False)

    assert budget_policy.scan_source_budget(_opts()) is None


def test_agent_mode_keeps_full_analysis(terminal, monkeypatch):
    monkeypatch.setattr(budget_policy.sys, "argv", ["agent-bom", "scan", "--agent-mode"])

    assert budget_policy.scan_source_budget(_opts()) is None


@pytest.mark.parametrize(
    "gate",
    [
        {"fail_on_severity": "high"},
        {"warn_on_severity": "medium"},
        {"fail_on_kev": True},
        {"fail_on_malicious": True},
        {"fail_if_ai_risk": True},
        {"policy": "policy.yml"},
        {"baseline": "old.json"},
        {"delta_mode": True},
        {"push_url": "https://example.invalid"},
        {"output_format": "sarif"},
        {"output_format": "cyclonedx"},
        {"output_format": "junit"},
    ],
)
def test_gates_and_machine_formats_keep_full_analysis(terminal, gate):
    assert budget_policy.scan_source_budget(_opts(**gate)) is None


def test_quick_opts_in_even_in_ci_with_a_gate(terminal, monkeypatch):
    monkeypatch.setenv("CI", "true")

    assert budget_policy.scan_source_budget(_opts(quick=True, fail_on_severity="high")) == DEFAULT_SOURCE_BUDGET


def test_full_analysis_wins_interactively(terminal):
    assert budget_policy.scan_source_budget(_opts(full_analysis=True)) is None
