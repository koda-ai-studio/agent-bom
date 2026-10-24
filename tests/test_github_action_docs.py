"""Public GitHub Action docs use the floating major ref and current inputs."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
PAGE = ROOT / "site-docs" / "integrations" / "github-action.md"


def _public_docs() -> list[Path]:
    tracked = subprocess.run(["git", "ls-files", "README.md", "docs", "site-docs"], cwd=ROOT, capture_output=True, text=True, check=True)
    return [ROOT / line for line in tracked.stdout.splitlines() if line.endswith(".md") and "/archive/" not in line]


def test_action_snippets_use_the_floating_major_ref() -> None:
    pinned = []
    for path in _public_docs():
        pinned += [
            f"{path.relative_to(ROOT)}: {ref}"
            for ref in re.findall(r"(?:koda-ai-studio|msaad00)/agent-bom@v\d+\.\d+\.\d+", path.read_text())
        ]
    assert pinned == []


def test_docs_use_current_scan_type_names() -> None:
    stale = [str(path.relative_to(ROOT)) for path in _public_docs() if re.search(r"scan-type:\s*agents\b", path.read_text())]
    assert stale == []


def _yaml_blocks(text: str) -> list[str]:
    return re.findall(r"```ya?ml\n(.*?)```", text, flags=re.S)


def test_action_page_examples_are_valid_and_least_privilege() -> None:
    action_inputs = set(yaml.safe_load((ROOT / "action.yml").read_text())["inputs"])
    text = PAGE.read_text()
    for heading in (
        "## Quick start",
        "## Full pull request gate",
        "## New findings only",
        "## MCP gate",
        "## SBOM artifact",
        "## Other CI systems",
    ):
        assert heading in text, heading
    workflows = [yaml.safe_load(block) for block in _yaml_blocks(text)]
    assert workflows
    for workflow in workflows:
        steps = workflow if isinstance(workflow, list) else [s for job in (workflow.get("jobs") or {}).values() for s in job["steps"]]
        for step in steps:
            if "koda-ai-studio/agent-bom" in str(step.get("uses", "")):
                assert step["uses"] == "koda-ai-studio/agent-bom@v0"
                assert set(step.get("with") or {}) <= action_inputs, step
        if isinstance(workflow, dict) and "jobs" in workflow:
            assert workflow.get("permissions") == {"contents": "read"}, "workflow default must be read-only"
    quick = _yaml_blocks(text)[0].strip().splitlines()
    assert len(quick) <= 3
