"""Backend and UI classify every finding type into the same issue class."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from agent_bom import finding_scope
from agent_bom.finding import FindingType

UI_FILE = Path(__file__).resolve().parents[1] / "ui" / "lib" / "finding-issue-type.ts"
_SETS = {
    "VULNERABILITY_TYPES": "_VULNERABILITY_TYPES",
    "MISCONFIGURATION_TYPES": "_MISCONFIGURATION_TYPES",
    "SECRET_TYPES": "_SECRET_TYPES",
    "PII_TYPES": "_PII_TYPES",
    "IDENTITY_TYPES": "_IDENTITY_TYPES",
}


def _ui_set(name: str) -> set[str]:
    match = re.search(rf"const {name} = new Set\(\[(.*?)\]\);", UI_FILE.read_text(), re.S)
    assert match, f"{name} not found in {UI_FILE.name}"
    return set(re.findall(r'"([A-Z_]+)"', match.group(1)))


@pytest.mark.parametrize(("ui_name", "backend_name"), sorted(_SETS.items()))
def test_ui_mirrors_backend_type_sets(ui_name: str, backend_name: str) -> None:
    assert _ui_set(ui_name) == set(getattr(finding_scope, backend_name))


@pytest.mark.parametrize("finding_type", [t.value for t in FindingType])
def test_every_finding_type_has_a_class(finding_type: str) -> None:
    assert finding_scope.finding_class_for_row({"finding_type": finding_type, "source": "MCP_SCAN"}) != "unclassified"
