from __future__ import annotations

import time

from fastapi.testclient import TestClient

# The demo compute lane's side scan names this VM by its workload id; inventory
# canonicalizes it under the account-scoped instance key.
_RETIRED_ID = "cloud_resource:aws:cwpp:instance:i-0de00000000000000"


def test_default_node_read_resolves_a_retired_id(demo_estate_client: TestClient) -> None:
    response = demo_estate_client.get(f"/v1/graph/node/{_RETIRED_ID}")
    # The full demo may need more than the request's bounded build wait. This
    # test owns alias semantics; the first-read suite owns latency budgets.
    for _ in range(30):
        if response.status_code != 503:
            break
        assert response.json()["error"]["details"]["code"] == "current_estate_building", response.text
        assert response.headers["Retry-After"] == "1"
        time.sleep(1)
        response = demo_estate_client.get(f"/v1/graph/node/{_RETIRED_ID}")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["resolved_from"] == _RETIRED_ID
    assert body["node"]["id"] != _RETIRED_ID
