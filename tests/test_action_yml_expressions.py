"""action.yml must load on GitHub: no expressions in input metadata, and a composite action cannot read secrets."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ACTION = Path(__file__).resolve().parents[1] / "action.yml"
_EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.S)


def _action() -> dict:
    return yaml.safe_load(ACTION.read_text())


def test_input_descriptions_and_defaults_carry_no_expression_syntax() -> None:
    offenders = [
        f"inputs.{name}.{field}"
        for name, spec in (_action().get("inputs") or {}).items()
        for field in ("description", "default")
        if "${{" in str((spec or {}).get(field) or "")
    ]
    assert offenders == []


def test_no_expression_references_secrets() -> None:
    expressions = [match.group(1).strip() for match in _EXPRESSION.finditer(ACTION.read_text())]
    assert [expr for expr in expressions if re.search(r"\bsecrets\.", expr)] == []
