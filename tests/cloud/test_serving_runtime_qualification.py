"""Serving-runtime endpoint evidence, qualified per runtime against loopback fixtures.

Every runtime is exercised for success, denied, timeout, partial and unavailable
endpoints. A failed endpoint yields no inventory and an explicit incomplete
warning; it never becomes a successful or local-only result.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from agent_bom.cloud import discover_from_provider
from agent_bom.cloud.serving_runtimes import SERVING_RUNTIMES, probe_endpoint
from tests._serving_runtime_fixtures import SCENARIOS, closed_port_url, serving_fixture

PROBE_RUNTIMES = sorted(SERVING_RUNTIMES)
_TIMEOUT = 0.5

EXPECTED_MODELS = {
    "vllm": {"qwen2.5-0.5b-instruct"},
    "tgi": {"bigscience/bloom-560m"},
    "triton": {"densenet_onnx", "simple"},
    "llamacpp": {"../models/tiny-q4_k_m.gguf"},
    "lmstudio": {"qwen2-vl-7b-instruct", "meta-llama-3.1-8b-instruct"},
}


def test_supported_runtimes_are_the_qualified_set():
    assert set(SERVING_RUNTIMES) == {"vllm", "tgi", "triton", "llamacpp", "lmstudio"}


def test_permission_catalog_covers_every_read_and_matches_the_registry():
    from agent_bom.cloud import _PROVIDER_PERMISSIONS_USED
    from agent_bom.cloud.serving_runtimes import _SERVING_PERMISSIONS

    issued = set()
    for runtime, spec in SERVING_RUNTIMES.items():
        issued.add(f"{runtime}:{spec.method} {spec.path}")
        if spec.metadata_path:
            issued.add(f"{runtime}:GET {spec.metadata_path}")
    assert issued == set(_SERVING_PERMISSIONS)
    assert _PROVIDER_PERMISSIONS_USED["serving"] == tuple(sorted(_SERVING_PERMISSIONS))


def test_a_read_missing_from_the_catalog_is_refused():
    from agent_bom.cloud.serving_runtimes import _declared

    with pytest.raises(ValueError, match="undeclared serving read"):
        _declared("vllm", "DELETE", "/v1/models")


@pytest.mark.parametrize("runtime", PROBE_RUNTIMES)
def test_success_records_every_model_with_separate_identities(runtime):
    with serving_fixture(SCENARIOS[runtime]["success"]) as url:
        agents, warnings = discover_from_provider("serving", runtime=runtime, endpoint=url, timeout=_TIMEOUT)

    assert warnings == []
    assert {a.metadata["serving_evidence"]["model"]["served_name"] for a in agents} == EXPECTED_MODELS[runtime]
    assert len({a.stable_id for a in agents}) == len(agents)
    for agent in agents:
        evidence = agent.metadata["serving_evidence"]
        assert evidence["runtime"]["name"] == runtime
        assert evidence["runtime"]["identity"] == "confirmed"
        assert evidence["endpoint"] == {"url": url, "host": "127.0.0.1", "port": int(url.rsplit(":", 1)[1])}
        collection = evidence["collection"]
        assert collection["status"] == "success"
        assert collection["completeness"] == "complete"
        assert collection["observed_at"]
        assert collection["permissions_used"]
        # Identities the endpoint cannot supply stay explicitly unknown, never merged in.
        for unknown in ("container", "gpu", "calling_agent", "principal"):
            assert evidence["unknown_identities"][unknown] is None
        for unsupported in ("bind_address", "tls", "authentication", "rate_limits", "logging"):
            assert unsupported in collection["not_collected"]
        envelope = agent.discovery_envelope
        assert envelope["scan_mode"] == "runtime_probe"
        assert envelope["discovery_scope"] == [f"{runtime}:endpoint/{url}"]
        assert envelope["permissions_used"] == collection["permissions_used"]


def test_runtime_versions_and_artifact_digests_are_kept_apart():
    with serving_fixture(SCENARIOS["tgi"]["success"]) as url:
        (agent,), _ = discover_from_provider("serving", runtime="tgi", endpoint=url, timeout=_TIMEOUT)
    evidence = agent.metadata["serving_evidence"]
    assert evidence["runtime"]["version"] == "3.3.4"
    assert evidence["model"]["digest"] == "e985a63cdc139290c5f700ff1929f0b5942cced2"
    assert evidence["model"]["artifact_ref"] == "bigscience/bloom-560m"

    with serving_fixture(SCENARIOS["vllm"]["success"]) as url:
        (agent,), _ = discover_from_provider("serving", runtime="vllm", endpoint=url, timeout=_TIMEOUT)
    evidence = agent.metadata["serving_evidence"]
    assert evidence["runtime"]["version"] == "0.11.0"
    assert evidence["model"]["artifact_ref"] == "Qwen/Qwen2.5-0.5B-Instruct"
    assert evidence["model"]["digest"] is None


def test_model_state_is_reported_not_assumed_loaded():
    with serving_fixture(SCENARIOS["triton"]["success"]) as url:
        agents, _ = discover_from_provider("serving", runtime="triton", endpoint=url, timeout=_TIMEOUT)
    states = {a.metadata["serving_evidence"]["model"]["served_name"]: a.metadata["serving_evidence"]["model"]["state"] for a in agents}
    assert states == {"densenet_onnx": "READY", "simple": "UNAVAILABLE"}


def test_same_model_on_two_endpoints_or_runtimes_stays_distinct():
    with serving_fixture(SCENARIOS["vllm"]["success"]) as first, serving_fixture(SCENARIOS["vllm"]["success"]) as second:
        a, _ = discover_from_provider("serving", runtime="vllm", endpoint=first, timeout=_TIMEOUT)
        b, _ = discover_from_provider("serving", runtime="vllm", endpoint=second, timeout=_TIMEOUT)
    assert a[0].stable_id != b[0].stable_id

    with serving_fixture(SCENARIOS["vllm"]["success"]) as url:
        vllm_agents, _ = discover_from_provider("serving", runtime="vllm", endpoint=url, timeout=_TIMEOUT)
        lmstudio_routes = {
            ("GET", "/api/v0/models"): (200, {"object": "list", "data": [{"id": "qwen2.5-0.5b-instruct", "object": "model"}]}, 0.0)
        }
    with serving_fixture(lmstudio_routes) as url:
        lm_agents, _ = discover_from_provider("serving", runtime="lmstudio", endpoint=url, timeout=_TIMEOUT)
    assert vllm_agents[0].stable_id != lm_agents[0].stable_id


@pytest.mark.parametrize("runtime", PROBE_RUNTIMES)
def test_denied_endpoint_is_denied_not_empty(runtime):
    with serving_fixture(SCENARIOS[runtime]["denied"]) as url:
        agents, warnings = discover_from_provider("serving", runtime=runtime, endpoint=url, timeout=_TIMEOUT)
    assert agents == []
    assert len(warnings) == 1
    assert "denied" in warnings[0] and "incomplete" in warnings[0]


@pytest.mark.parametrize("runtime", PROBE_RUNTIMES)
def test_timed_out_endpoint_is_timeout_not_empty(runtime):
    with serving_fixture(SCENARIOS[runtime]["timeout"]) as url:
        agents, warnings = discover_from_provider("serving", runtime=runtime, endpoint=url, timeout=0.2)
    assert agents == []
    assert len(warnings) == 1
    assert "timed out" in warnings[0] and "incomplete" in warnings[0]


@pytest.mark.parametrize("runtime", PROBE_RUNTIMES)
def test_unavailable_endpoint_is_unavailable_not_empty(runtime):
    agents, warnings = discover_from_provider("serving", runtime=runtime, endpoint=closed_port_url(), timeout=_TIMEOUT)
    assert agents == []
    assert len(warnings) == 1
    assert "unavailable" in warnings[0] and "incomplete" in warnings[0]


@pytest.mark.parametrize("runtime", PROBE_RUNTIMES)
def test_wrong_runtime_api_is_unavailable_not_a_verified_empty_inventory(runtime):
    with serving_fixture({}) as url:
        agents, warnings = discover_from_provider("serving", runtime=runtime, endpoint=url, timeout=_TIMEOUT)
    assert agents == []
    assert warnings and "incomplete" in warnings[0]


@pytest.mark.parametrize("runtime", PROBE_RUNTIMES)
def test_partial_collection_keeps_valid_records_and_says_partial(runtime):
    with serving_fixture(SCENARIOS[runtime]["partial"]) as url:
        agents, warnings = discover_from_provider("serving", runtime=runtime, endpoint=url, timeout=_TIMEOUT)
    assert agents, "partial collection keeps the records it could verify"
    assert len(warnings) == 1 and "partial" in warnings[0]
    for agent in agents:
        assert agent.metadata["serving_evidence"]["collection"]["status"] == "partial"
        assert agent.metadata["serving_evidence"]["collection"]["completeness"] == "partial"


def test_failed_remote_probe_never_reads_local_model_files(tmp_path):
    (tmp_path / "tiny.gguf").write_bytes(b"GGUF")
    with patch("agent_bom.model_files.scan_model_files") as local_scan:
        agents, warnings = discover_from_provider("serving", runtime="llamacpp", endpoint=closed_port_url(), timeout=_TIMEOUT)
    assert agents == [] and warnings
    local_scan.assert_not_called()


@pytest.mark.parametrize(
    "endpoint",
    ["http://user:secret@127.0.0.1:8000", "file:///etc/passwd", "http://169.254.169.254/latest", "not a url"],
)
def test_unsafe_endpoints_are_refused_before_any_request(endpoint):
    with patch("httpx.Client.request") as request:
        observation = probe_endpoint("vllm", endpoint, timeout=_TIMEOUT)
    request.assert_not_called()
    assert observation.status == "unavailable"
    assert "secret" not in observation.detail


def test_redirect_is_not_followed():
    with serving_fixture({("GET", "/v1/models"): (302, {}, 0.0)}) as url:
        observation = probe_endpoint("vllm", url, timeout=_TIMEOUT)
    assert observation.status == "unavailable"


def test_package_detection_is_not_endpoint_evidence(tmp_path):
    from pathlib import Path

    from agent_bom.ai_components.models import AIComponentType
    from agent_bom.ai_components.scanner import scan_source

    (tmp_path / "serve.py").write_text("import vllm\n")
    report = scan_source(tmp_path)
    (component,) = [c for c in report.components if c.name == "vllm"]
    assert component.component_type is AIComponentType.INFERENCE_SERVER
    assert not hasattr(component, "endpoint") and not hasattr(component, "serving_evidence")

    # Endpoint evidence is produced only by the two endpoint probes; views only read or copy it.
    src = Path(__file__).resolve().parents[2] / "src" / "agent_bom"
    producer = '"serving_evidence": serving_evidence('
    writers = sorted(str(p.relative_to(src)) for p in src.rglob("*.py") if producer in p.read_text(encoding="utf-8"))
    assert writers == ["cloud/ollama.py", "cloud/serving_runtimes.py"]


def test_unknown_runtime_is_rejected():
    with pytest.raises(ValueError):
        discover_from_provider("serving", runtime="mystery", endpoint="http://127.0.0.1:1", timeout=_TIMEOUT)


def test_repeat_probe_detects_model_change():
    first_routes = SCENARIOS["vllm"]["success"]
    changed = dict(first_routes)
    changed[("GET", "/v1/models")] = (
        200,
        {"object": "list", "data": [{"id": "qwen2.5-1.5b-instruct", "object": "model", "owned_by": "vllm"}]},
        0.0,
    )
    with serving_fixture(first_routes) as url:
        before = probe_endpoint("vllm", url, timeout=_TIMEOUT)
    with serving_fixture(changed) as url:
        after = probe_endpoint("vllm", url, timeout=_TIMEOUT)
    assert {m.served_name for m in before.models} != {m.served_name for m in after.models}


def test_undeclared_owner_is_reported_as_declared_runtime_only():
    routes = {("GET", "/v1/models"): (200, {"object": "list", "data": [{"id": "m", "object": "model", "owned_by": "someone"}]}, 0.0)}
    with serving_fixture(routes) as url:
        observation = probe_endpoint("vllm", url, timeout=_TIMEOUT)
    assert observation.status in {"success", "partial"}
    assert observation.runtime_identity == "declared"
