from __future__ import annotations

from fastapi.testclient import TestClient

from tests.test_demo_estate_bootstrap import demo_estate_client  # noqa: F401

# The demo compute lane's side scan names this VM by its workload id; inventory
# canonicalizes it under the account-scoped instance key.
_RETIRED_ID = "cloud_resource:aws:cwpp:instance:i-0de00000000000000"


def test_default_node_read_resolves_a_retired_id(demo_estate_client: TestClient) -> None:  # noqa: F811
    response = demo_estate_client.get(f"/v1/graph/node/{_RETIRED_ID}")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["resolved_from"] == _RETIRED_ID
    assert body["node"]["id"] != _RETIRED_ID
