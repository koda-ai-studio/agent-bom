"""Findings never wait on a graph rebuild when a previous generation exists, and say so with its time."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from agent_bom.api.finding_reachability import FindingReachabilityProjection, project_persisted_graph_reachability
from agent_bom.api.server import app
from tests.api.test_current_remediation import fixed_read_clock  # noqa: F401
from tests.api.test_finding_reachability_snapshot_join import PagedStore, _path
from tests.api.test_push_replacement_scope import pushed
from tests.api.test_scan_job_sla_history import scan_store  # noqa: F401
from tests.auth_helpers import proxy_headers

AS_OF = "2026-11-14T09:30:00+00:00"


def test_previous_generation_projection_carries_its_time():
    class RefreshingStore(PagedStore):
        def current_view_coverage(self, **_kwargs):
            return {"freshness": "previous_generation", "refresh_status": "building", "as_of": AS_OF}

    rows = [{"finding_id": "occurrence-1", "cve_id": "CVE-2026-00001"}]
    result = project_persisted_graph_reachability(rows, graph_store=RefreshingStore([_path(1)]), tenant_id="t", scan_id=None)  # type: ignore[arg-type]
    assert result.refreshing is True
    assert result.as_of == AS_OF
    assert result.rows[0]["graph_reachable"] is None


def test_current_generation_projection_has_no_freshness_label():
    rows = [{"finding_id": "occurrence-1", "cve_id": "CVE-2026-00001"}]
    result = project_persisted_graph_reachability(rows, graph_store=PagedStore([_path(1)]), tenant_id="t", scan_id=None)  # type: ignore[arg-type]
    assert result.refreshing is False
    assert result.as_of == ""


@pytest.mark.parametrize("path", ["/v1/findings", "/v1/findings?group_occurrences=true&include_facets=true"])
@pytest.mark.parametrize("refreshing", [True, False])
def test_findings_envelope_labels_reachability_from_a_previous_graph(scan_store, monkeypatch, path, refreshing):  # noqa: F811
    from agent_bom.api import finding_page_read

    def projection(rows, **_kwargs):
        return FindingReachabilityProjection(
            [dict(row) for row in rows], truncated=False, refreshing=refreshing, as_of=AS_OF if refreshing else ""
        )

    monkeypatch.setattr(finding_page_read, "project_persisted_graph_reachability", projection)
    scan_store.put(pushed(8, scope="v1:" + "a" * 64))
    with TestClient(app) as client:
        response = client.get(path, headers=proxy_headers(role="analyst", tenant="history-tenant"))
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["findings"]
    if refreshing:
        assert body["graph_freshness"] == {"freshness": "previous_generation", "refresh_status": "building", "as_of": AS_OF}
        assert any("being prepared" in warning for warning in body["warnings"])
    else:
        assert "graph_freshness" not in body
