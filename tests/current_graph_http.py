"""Wait for explicit refresh states when asserting post-ingest graph evidence."""

import time


def current_graph_response(client, *, headers=None, params=None, timeout=10):
    deadline = time.monotonic() + timeout
    while True:
        response = client.get("/v1/graph", params=params, headers=headers)
        body = response.json()
        coverage, detail = body.get("collection_coverage"), body.get("detail")
        refreshing = response.status_code == 200 and isinstance(coverage, dict) and coverage.get("freshness") == "previous_generation"
        building = (
            response.status_code == 503
            and isinstance(detail, dict)
            and detail.get("code") in {"current_estate_building", "current_estate_generation_rotating"}
        )
        if not (refreshing or building):
            return response
        assert time.monotonic() < deadline, "current graph did not finish refreshing"
        time.sleep(0.05)
