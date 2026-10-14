"""Every finding type maps to a concrete issue class; the UI reads the backend's ``finding_class``."""

from __future__ import annotations

import pytest

from agent_bom import finding_scope
from agent_bom.finding import FindingType


@pytest.mark.parametrize("finding_type", [t.value for t in FindingType])
def test_every_finding_type_has_a_class(finding_type: str) -> None:
    assert finding_scope.finding_class_for_row({"finding_type": finding_type, "source": "MCP_SCAN"}) != "unclassified"
