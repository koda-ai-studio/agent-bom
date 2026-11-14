"""Eval-suite detection: each harness is read from files, classified and linked, never executed."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from agent_bom.ai_components.eval_suites import scan_eval_suites
from agent_bom.ai_components.framework_agents import scan_framework_agents

_FIXTURES = Path(__file__).parent / "fixtures" / "eval_suites"


def _scan(root: Path) -> tuple[list[dict], dict]:
    agents = [agent.to_dict() for agent in scan_framework_agents(root)]
    result = scan_eval_suites(root, framework_agents=agents)
    return [suite.to_dict() for suite in result.suites], result.coverage


def _agent_id(root: Path, name: str) -> str:
    matches = [agent.stable_id for agent in scan_framework_agents(root) if agent.name == name]
    assert len(matches) == 1, matches
    return matches[0]


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _copy(tmp_path: Path, name: str) -> Path:
    root = tmp_path / name
    shutil.copytree(_FIXTURES / name, root)
    for staged in root.rglob("*.fixture"):
        staged.rename(staged.with_suffix(""))
    return root


def test_promptfoo_redteam_config_is_a_linked_safety_suite_with_results(tmp_path: Path) -> None:
    root = _copy(tmp_path, "promptfoo_redteam")
    suites, coverage = _scan(root)
    assert coverage["status"] == "complete"
    [suite] = suites
    assert suite["harness"] == "promptfoo"
    assert suite["file_path"] == "promptfooconfig.yaml"
    assert suite["purpose"] == "safety"
    assert any("harmful:hate" in item and "excessive-agency" in item for item in suite["purpose_evidence"])
    agent_targets = [target for target in suite["targets"] if target["kind"] == "agent"]
    assert agent_targets and agent_targets[0]["agent_ids"] == [_agent_id(root, "support_agent")]
    assert {"kind": "model", "ref": "openai:gpt-4o-mini"}.items() <= next(t for t in suite["targets"] if t["kind"] == "model").items()
    assert suite["link_status"] == "linked"
    [result] = suite["results"]
    assert result == {
        "source": "promptfoo output file",
        "source_file": "results/promptfoo-results.json",
        "recorded_at": "2026-10-02T14:30:00.000Z",
        "passed": 46,
        "failed": 4,
        "errors": 0,
        "pass_rate": 0.92,
    }


def test_deepeval_safety_metrics_link_through_the_agent_import(tmp_path: Path) -> None:
    root = _copy(tmp_path, "deepeval_safety")
    suites, _ = _scan(root)
    [suite] = suites
    assert suite["harness"] == "deepeval"
    assert suite["purpose"] == "safety"
    assert "PIILeakageMetric" in " ".join(suite["purpose_evidence"]) and "ToxicityMetric" in " ".join(suite["purpose_evidence"])
    assert [target["agent_ids"] for target in suite["targets"] if target["kind"] == "agent"] == [[_agent_id(root, "refund_agent")]]
    # The metric's judge model is not the system under test.
    assert not [target for target in suite["targets"] if target["kind"] == "model"]


def test_ragas_quality_eval_with_no_target_is_unlinked(tmp_path: Path) -> None:
    root = _copy(tmp_path, "uncovered_agent")
    suites, _ = _scan(root)
    [suite] = suites
    assert (suite["harness"], suite["purpose"], suite["link_status"]) == ("ragas", "quality", "unlinked")
    assert suite["targets"] == []


def test_promptfoo_without_redteam_or_safety_asserts_is_quality_and_bare_config_is_unknown(tmp_path: Path) -> None:
    _write(
        tmp_path / "quality" / "promptfooconfig.yaml",
        "providers: [anthropic:messages:claude-sonnet-4-5]\nprompts: ['{{q}}']\n"
        "tests:\n  - vars: {q: hi}\n    assert:\n      - type: contains\n        value: hello\n",
    )
    _write(tmp_path / "bare" / "promptfooconfig.yml", "providers: [openai:gpt-4o]\nprompts: ['{{q}}']\n")
    _write(
        tmp_path / "moderated" / "promptfooconfig.json",
        json.dumps({"providers": ["openai:gpt-4o"], "defaultTest": {"assert": [{"type": "moderation"}]}}),
    )
    assert _scan(tmp_path / "quality")[0][0]["purpose"] == "quality"
    assert _scan(tmp_path / "bare")[0][0]["purpose"] == "unknown"
    assert _scan(tmp_path / "moderated")[0][0]["purpose"] == "safety"
    # A model-only target links the suite to a model, never to an agent.
    model_suite = _scan(tmp_path / "bare")[0][0]
    assert model_suite["link_status"] == "linked"
    assert [target["kind"] for target in model_suite["targets"]] == ["model"]


def test_inspect_task_links_its_model_and_known_safety_benchmark(tmp_path: Path) -> None:
    _write(
        tmp_path / "proj" / "evals" / "harm.py",
        "from inspect_ai import Task, eval, task\n"
        "from inspect_evals.agentharm import agentharm\n\n"
        "@task\n"
        "def harm_suite():\n"
        "    return agentharm()\n\n"
        "eval(harm_suite(), model='openai/gpt-4o')\n",
    )
    _write(
        tmp_path / "proj" / "evals" / "plain.py",
        "from inspect_ai import Task, task\n\n@task\ndef arithmetic():\n    return Task(dataset=[], solver=[], scorer=None)\n",
    )
    suites = {suite["name"]: suite for suite in _scan(tmp_path / "proj")[0]}
    assert suites["harm_suite"]["harness"] == "inspect"
    assert suites["harm_suite"]["purpose"] == "safety"
    assert [t["ref"] for t in suites["harm_suite"]["targets"] if t["kind"] == "model"] == ["openai/gpt-4o"]
    assert suites["arithmetic"]["purpose"] == "unknown"
    assert suites["arithmetic"]["link_status"] == "unlinked"


def test_openai_evals_registry_and_langsmith_dataset_are_detected(tmp_path: Path) -> None:
    _write(
        tmp_path / "proj" / "evals" / "registry" / "evals" / "math.yaml",
        "math:\n  id: math.dev.v0\n  metrics: [accuracy]\nmath.dev.v0:\n  class: evals.elsuite.basic.match:Match\n"
        "  args:\n    samples_jsonl: math/samples.jsonl\n",
    )
    _write(
        tmp_path / "proj" / "app.py",
        "from langgraph.graph import StateGraph\n\nbuilder = StateGraph(dict)\ngraph = builder.compile()\n",
    )
    _write(
        tmp_path / "proj" / "ls_eval.py",
        "from langsmith import Client\nfrom app import graph\n\nclient = Client()\n"
        "client.create_dataset(dataset_name='Support QA')\n\n"
        "def run(inputs):\n    return graph.invoke(inputs)\n\n"
        "client.evaluate(run, data='Support QA', evaluators=[])\n",
    )
    suites = {suite["harness"]: suite for suite in _scan(tmp_path / "proj")[0]}
    assert suites["openai-evals"]["name"] == "math"
    assert suites["openai-evals"]["purpose"] == "quality"
    assert suites["langsmith"]["name"] == "Support QA"
    assert suites["langsmith"]["purpose"] == "unknown"
    assert suites["langsmith"]["link_status"] == "linked"
    assert [t["agent_ids"] for t in suites["langsmith"]["targets"] if t["kind"] == "agent"] == [[_agent_id(tmp_path / "proj", "builder")]]


def test_detection_never_executes_the_scanned_project(tmp_path: Path) -> None:
    marker = tmp_path / "executed"
    _write(
        tmp_path / "proj" / "evil_eval.py",
        f"import pathlib\npathlib.Path({str(marker)!r}).write_text('x')\nfrom deepeval.metrics import BiasMetric\nBiasMetric()\n",
    )
    _write(tmp_path / "proj" / "promptfooconfig.yaml", "providers: [exec:touch /tmp/never]\nredteam: {plugins: [harmful]}\n")
    suites, _ = _scan(tmp_path / "proj")
    assert {suite["harness"] for suite in suites} == {"deepeval", "promptfoo"}
    assert not marker.exists()


@pytest.mark.parametrize("text", ["providers: [", "- just\n- a list\n", "{}", "\x00\x01"])
def test_malformed_promptfoo_config_is_recorded_not_fatal(tmp_path: Path, text: str) -> None:
    _write(tmp_path / "proj" / "promptfooconfig.yaml", text)
    suites, coverage = _scan(tmp_path / "proj")
    assert suites == []
    assert coverage["status"] == "complete"
    assert coverage["files_examined"] == 1


def test_suite_ids_are_stable_and_scoped(tmp_path: Path) -> None:
    root = _copy(tmp_path, "promptfoo_redteam")
    first = _scan(root)[0][0]["stable_id"]
    assert first == _scan(root)[0][0]["stable_id"]
    other = _copy(tmp_path / "other", "promptfoo_redteam")
    assert _scan(other)[0][0]["scope"] == "promptfoo_redteam"


def test_unresolvable_file_target_is_kept_unlinked_with_its_reason(tmp_path: Path) -> None:
    _write(tmp_path / "proj" / "promptfooconfig.yaml", "targets: ['file://missing_provider.py']\nredteam: {plugins: [pii]}\n")
    [suite] = _scan(tmp_path / "proj")[0]
    assert suite["link_status"] == "unlinked"
    [target] = suite["targets"]
    assert target["kind"] == "agent" and target["agent_ids"] == []
    assert "no framework agent" in target["unresolved_reason"]


def test_file_budget_marks_coverage_partial(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import agent_bom.ai_components.eval_suites as module

    monkeypatch.setattr(module, "MAX_FILES_EXAMINED", 1)
    _write(tmp_path / "proj" / "a" / "promptfooconfig.yaml", "providers: [openai:gpt-4o]\nredteam: {plugins: [pii]}\n")
    _write(tmp_path / "proj" / "b" / "promptfooconfig.yaml", "providers: [openai:gpt-4o]\nredteam: {plugins: [pii]}\n")
    _, coverage = _scan(tmp_path / "proj")
    assert coverage["status"] == "partial"
    assert "limit" in coverage["detail"]
