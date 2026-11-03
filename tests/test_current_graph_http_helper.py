"""Post-ingest polling must not mask missing evidence or genuine API failures."""

from types import SimpleNamespace

import httpx
import pytest

from tests.current_graph_http import current_graph_response


@pytest.mark.parametrize(
    "status,body", [(200, {"collection_coverage": {"status": "unknown"}}), (401, {}), (500, {}), (503, {"detail": "unavailable"})]
)
def test_non_refresh_responses_are_never_retried(status, body):
    response = httpx.Response(status, json=body)
    replies = iter([response])
    assert current_graph_response(SimpleNamespace(get=lambda *a, **kw: next(replies))) is response


def test_explicit_build_and_previous_generation_states_wait_for_current():
    current = httpx.Response(200, json={"nodes": [{"id": "new"}], "collection_coverage": {"status": "partial"}})
    replies = iter(
        [
            httpx.Response(503, json={"detail": {"code": "current_estate_building"}}),
            httpx.Response(200, json={"collection_coverage": {"freshness": "previous_generation"}}),
            current,
        ]
    )
    assert current_graph_response(SimpleNamespace(get=lambda *a, **kw: next(replies))) is current


def test_a_refresh_that_never_finishes_fails_at_the_deadline():
    client = SimpleNamespace(get=lambda *a, **kw: httpx.Response(503, json={"detail": {"code": "current_estate_building"}}))
    with pytest.raises(AssertionError, match="did not finish refreshing"):
        current_graph_response(client, timeout=0)
