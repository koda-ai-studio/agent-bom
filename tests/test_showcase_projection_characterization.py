"""Complete demo projections retain their evidence across module extraction."""

import json
from datetime import datetime, timezone
from pathlib import Path

from agent_bom.demo_estate.showcase_graph import apply_showcase_overlays, build_showcase_graph, demo_identity_records

FIXTURE = Path(__file__).parent / "fixtures" / "showcase_projection.json"


class FrozenDatetime(datetime):
    @classmethod
    def now(cls, tz=None):
        return datetime(2026, 10, 19, 12, tzinfo=timezone.utc)


def _projections(monkeypatch):
    # Patch the actual clock owner on either side of the extraction. No output
    # fields are removed or normalized; observed source timestamps remain data.
    monkeypatch.setitem(demo_identity_records.__globals__, "datetime", FrozenDatetime)
    monkeypatch.setattr("agent_bom.graph.util.datetime", FrozenDatetime)
    monkeypatch.setattr("agent_bom.graph.governance_overlay.datetime", FrozenDatetime)
    projections = {}
    for profile in ("baseline", "current"):
        graph, identities, drift = build_showcase_graph(tenant_id="tenant-a", scan_id="characterization", profile=profile)
        apply_showcase_overlays(graph, tenant_id="tenant-a", identity_store=identities, drift_store=drift)
        assert graph.nodes and graph.edges
        projections[profile] = graph.to_dict()
    return projections


def test_showcase_projection_characterization(monkeypatch):
    assert _projections(monkeypatch) == json.loads(FIXTURE.read_text())
