"""Every finding the API lists points at a node the served graph holds."""

from __future__ import annotations

from starlette.testclient import TestClient

from tests._demo_estate_fixtures import VIEWER

_PAGE = 1000


def _all_findings(client: TestClient) -> list[dict]:
    rows: list[dict] = []
    offset = 0
    while True:
        page = client.get("/v1/findings", headers=VIEWER, params={"limit": _PAGE, "offset": offset}).json()
        batch = page.get("findings") or []
        rows.extend(batch)
        total = int(page.get("total") or 0)
        offset += len(batch)
        if not batch or offset >= total:
            return rows


def test_every_listed_finding_node_id_resolves_in_the_served_graph(shared_demo_estate_client: TestClient) -> None:
    from agent_bom.api import stores as api_stores
    from agent_bom.demo_estate.showcase_graph import SHOWCASE_SCAN_ID, SHOWCASE_TENANT

    findings = _all_findings(shared_demo_estate_client)
    assert len(findings) > 2000, len(findings)
    referenced = {str(row.get(key)) for row in findings for key in ("node_id", "finding_node_id") if row.get(key)}
    assert len(referenced) > 1000

    store = api_stores._get_graph_store()
    resolved = store.resolve_node_aliases(tenant_id=SHOWCASE_TENANT, node_ids=referenced, scan_id=SHOWCASE_SCAN_ID)
    read_ids = {resolved.get(node_id, node_id) for node_id in referenced}
    present = {node.id for node in store.nodes_by_ids(tenant_id=SHOWCASE_TENANT, scan_id=SHOWCASE_SCAN_ID, node_ids=read_ids)}
    missing = sorted(read_ids - present)
    assert not missing, f"{len(missing)} finding node ids missing from the graph, e.g. {missing[:5]}"


def test_retired_demo_ids_resolve_through_the_persisted_alias_table(shared_demo_estate_client: TestClient) -> None:
    from agent_bom.api import stores as api_stores
    from agent_bom.demo_estate.showcase_graph import SHOWCASE_SCAN_ID, SHOWCASE_TENANT

    retired = {
        "organization:northstar-health-ai": "org:enterprise:northstar-health-ai",
        "mc:pii-public": "misconfig:showcase:pii-public",
        "mc:sg-open": "misconfig:showcase:sg-open",
    }
    store = api_stores._get_graph_store()
    resolved = store.resolve_node_aliases(tenant_id=SHOWCASE_TENANT, node_ids=set(retired), scan_id=SHOWCASE_SCAN_ID)
    assert resolved == retired

    impact = shared_demo_estate_client.get(
        "/v1/graph/impact", headers=VIEWER, params={"node": "mc:pii-public", "scan_id": SHOWCASE_SCAN_ID}
    )
    assert impact.status_code == 200, impact.text
    assert impact.json().get("resolved_from") == "mc:pii-public"
