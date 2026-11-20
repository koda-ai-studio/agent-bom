"""Workflow and action inputs reach shell steps through env:, never `${{ }}` in run:.

An expression inside `run:` is pasted into the script before the shell parses
it, so a dispatch input such as `1000"; curl … #` runs as code. Passing the
value through `env:` keeps it data. postgres-scale-evidence.yml interpolated
three free-text dispatch inputs this way.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
INPUT_EXPRESSION = re.compile(r"\$\{\{[^}]*\b(?:inputs|github\.event\.inputs)\.")


def _shell_steps():
    for path in sorted((ROOT / ".github/workflows").glob("*.y*ml")):
        workflow = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for job_name, job in (workflow.get("jobs") or {}).items():
            for index, step in enumerate(job.get("steps") or []):
                yield f"{path.name}:{job_name}:{step.get('name', index)}", step
    for path in sorted((ROOT / ".github/actions").rglob("action.y*ml")):
        action = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for index, step in enumerate((action.get("runs") or {}).get("steps") or []):
            yield f"{path.relative_to(ROOT)}:{step.get('name', index)}", step


def test_no_input_expression_is_interpolated_into_a_shell_script() -> None:
    offenders = [name for name, step in _shell_steps() if INPUT_EXPRESSION.search(str(step.get("run", "")))]
    assert offenders == []


def test_the_sweep_sees_workflows_and_composite_actions() -> None:
    names = [name for name, _step in _shell_steps()]
    assert any(name.startswith("postgres-scale-evidence.yml:") for name in names)
    assert any(name.startswith(".github/actions/setup-ui/") for name in names)


def test_the_pattern_matches_the_shapes_it_guards() -> None:
    assert INPUT_EXPRESSION.search("SIZES=\"${{ inputs.sizes || '1000' }}\"")
    assert INPUT_EXPRESSION.search("echo ${{ github.event.inputs.kind }}")
    assert not INPUT_EXPRESSION.search('SIZES="${SIZES:-1000}"')
