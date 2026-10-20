"""Every surface counts a framework's findings by one definition: control-tag evidence.

``/v1/findings?framework=<slug>`` is the drill-through behind every framework
count. A row counts for a framework when it carries a control code that
framework's scoring catalog resolves (bulk-ingested rows may also declare the
framework in ``applicable_frameworks``). Selection-table applicability alone
is not compliance evidence, so it never inflates a framework count.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.test_demo_estate_bootstrap import VIEWER, demo_estate_client  # noqa: F401

_FRAMEWORKS = ("soc2", "nist-800-53", "pci-dss", "iso-27001")


def _get(client: TestClient, path: str, **params: object) -> dict:
    response = client.get(path, headers=VIEWER, params=params)
    assert response.status_code == 200, (path, response.text[:400])
    return response.json()


def _drill_total(client: TestClient, slug: str) -> int:
    """Rows the framework drill-through returns, paged to the end (its total is cursor-only)."""
    params: dict[str, object] = {"framework": slug, "limit": 1000}
    seen = 0
    while True:
        page = _get(client, "/v1/findings", **params)
        seen += len(page["findings"])
        if not page.get("next_cursor"):
            return seen
        params = {"framework": slug, "limit": 1000, "cursor": page["next_cursor"]}


def test_hub_posture_framework_counts_match_the_drill_through(demo_estate_client: TestClient) -> None:  # noqa: F811
    posture = _get(demo_estate_client, "/v1/compliance/hub/posture")
    assert posture["framework_count_basis"] == "control_tag_evidence"
    assert posture["totals"]["native"] == _get(demo_estate_client, "/v1/findings", limit=1)["total"]
    for slug in _FRAMEWORKS:
        drill = _drill_total(demo_estate_client, slug)
        assert drill > 0, slug
        assert posture["framework_counts"]["native"].get(slug, 0) == drill, slug
        assert posture["framework_counts"]["combined"].get(slug, 0) == drill, slug


def test_framework_evidence_is_the_drill_through_predicate() -> None:
    from agent_bom.finding_scope import _row_matches_framework, framework_evidence_slugs

    applicable_only = {"applicable_frameworks": ["soc2", "nist-800-53"], "nist_800_53_tags": ["AC-6"]}
    assert framework_evidence_slugs(applicable_only) == {"nist-800-53"}
    bulk = {**applicable_only, "origin": "bulk_ingest"}
    assert framework_evidence_slugs(bulk) == {"soc2", "nist-800-53"}
    for row in (applicable_only, bulk):
        for slug, field in (("soc2", "soc2_tags"), ("nist-800-53", "nist_800_53_tags")):
            matched = _row_matches_framework(row, {"framework_tag_field": field, "framework_slug": slug})
            assert matched is (slug in framework_evidence_slugs(row)), (row, slug)
