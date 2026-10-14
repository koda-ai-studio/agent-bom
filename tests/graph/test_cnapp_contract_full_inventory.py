"""The CNAPP overlay stays inside the relationship contract on a full AWS inventory."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import pytest

from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.types import RelationshipType
from agent_bom.models import AIBOMReport
from agent_bom.output import to_json

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "cloud_characterization" / "aws_inventory.json"


def test_full_aws_inventory_builds_under_strict_contract(caplog: pytest.LogCaptureFixture) -> None:
    inventory = json.loads(FIXTURE.read_text())["single_full"]["result"]
    report = AIBOMReport(agents=[], blast_radii=[], generated_at=datetime(2026, 10, 1, tzinfo=timezone.utc))
    report.cloud_inventory_data = inventory
    payload = to_json(report)

    with caplog.at_level(logging.WARNING):
        graph = build_unified_graph_from_report(payload, scan_id="aws-full", tenant_id="default")

    assert not [record for record in caplog.records if "overlay failed" in record.getMessage()]
    relationships = {edge.relationship for edge in graph.edges}
    assert RelationshipType.STORES in relationships
