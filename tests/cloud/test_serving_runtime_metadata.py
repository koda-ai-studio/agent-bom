"""Runtime metadata that is empty, missing its field, mistyped or not JSON makes the evidence partial.

The inventory records are kept, but a runtime whose documented version source
did not report a version is never ``success`` / ``complete``.
"""

from __future__ import annotations

import pytest

from agent_bom.cloud import discover_from_provider
from agent_bom.cloud.serving_runtimes import probe_endpoint
from tests._serving_runtime_fixtures import SCENARIOS, serving_fixture

_TIMEOUT = 0.5
_NOT_JSON = b"<html>not json</html>"

# runtime -> (metadata route, a body with the version field missing, a body with it mistyped)
_METADATA = {
    "vllm": (("GET", "/version"), {"build": "0.11.0"}, {"version": 11}),
    "llamacpp": (("GET", "/props"), {"model_path": "../models/tiny-q4_k_m.gguf", "total_slots": 1}, {"build_info": ["b6100"]}),
    "triton": (("GET", "/v2"), {"name": "triton", "extensions": []}, {"name": "triton", "version": 2.59}),
}
_BAD = ("empty", "missing", "mistyped", "not_json")


def _routes(runtime: str, case: str) -> dict:
    route, missing, mistyped = _METADATA[runtime]
    body = {"empty": {}, "missing": missing, "mistyped": mistyped, "not_json": _NOT_JSON}[case]
    return {**SCENARIOS[runtime]["success"], route: (200, body, 0.0)}


def _assert_partial_with_inventory(runtime: str, routes: dict, expected: set[str]) -> None:
    with serving_fixture(routes) as url:
        agents, warnings = discover_from_provider("serving", runtime=runtime, endpoint=url, timeout=_TIMEOUT)
    assert {a.metadata["serving_evidence"]["model"]["served_name"] for a in agents} == expected
    assert len(warnings) == 1 and "partial" in warnings[0] and "runtime version not reported" in warnings[0]
    for agent in agents:
        evidence = agent.metadata["serving_evidence"]
        assert evidence["collection"]["status"] == "partial"
        assert evidence["collection"]["completeness"] == "partial"
        assert "runtime version not reported" in evidence["collection"]["detail"]
        assert evidence["runtime"]["version"] is None


_EXPECTED = {
    "vllm": {"qwen2.5-0.5b-instruct"},
    "llamacpp": {"../models/tiny-q4_k_m.gguf"},
    "triton": {"densenet_onnx", "simple"},
    "tgi": {"bigscience/bloom-560m"},
}


@pytest.mark.parametrize("case", _BAD)
@pytest.mark.parametrize("runtime", sorted(_METADATA))
def test_bad_runtime_metadata_is_partial_and_keeps_inventory(runtime, case):
    _assert_partial_with_inventory(runtime, _routes(runtime, case), _EXPECTED[runtime])


@pytest.mark.parametrize("version", [None, 3, "", "  "], ids=["missing", "mistyped", "empty", "blank"])
def test_tgi_info_without_a_version_is_partial_and_keeps_the_model(version):
    info = dict(SCENARIOS["tgi"]["success"][("GET", "/info")][1])
    if version is None:
        info.pop("version")
    else:
        info["version"] = version
    _assert_partial_with_inventory("tgi", {("GET", "/info"): (200, info, 0.0)}, _EXPECTED["tgi"])


@pytest.mark.parametrize("body", [{}, _NOT_JSON], ids=["empty", "not_json"])
def test_tgi_info_that_is_empty_or_not_json_has_no_inventory(body):
    # TGI's /info is both its inventory and its metadata: with no model_id there is nothing to keep.
    with serving_fixture({("GET", "/info"): (200, body, 0.0)}) as url:
        agents, warnings = discover_from_provider("serving", runtime="tgi", endpoint=url, timeout=_TIMEOUT)
    assert agents == [] and len(warnings) == 1 and "incomplete" in warnings[0]


def test_lmstudio_documents_no_metadata_read_and_stays_complete():
    with serving_fixture(SCENARIOS["lmstudio"]["success"]) as url:
        observation = probe_endpoint("lmstudio", url, timeout=_TIMEOUT)
    assert observation.status == "success" and observation.completeness == "complete"
    assert observation.permissions_used == ("lmstudio:GET /api/v0/models",)
    assert observation.runtime_version is None


@pytest.mark.parametrize("runtime", sorted(_EXPECTED))
def test_valid_metadata_is_still_complete(runtime):
    with serving_fixture(SCENARIOS[runtime]["success"]) as url:
        observation = probe_endpoint(runtime, url, timeout=_TIMEOUT)
    assert observation.status == "success" and observation.runtime_version and observation.detail == ""
