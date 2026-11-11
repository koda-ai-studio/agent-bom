"""Ollama endpoint outcomes against a loopback fixture of ``GET /api/tags``."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from agent_bom.cloud.ollama import discover
from tests._serving_runtime_fixtures import SCENARIOS, closed_port_url, serving_fixture


@pytest.fixture(autouse=True)
def _no_ambient_host(monkeypatch, tmp_path):
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    local = tmp_path / "library" / "unrelated-local-model"
    local.mkdir(parents=True)
    (local / "latest").write_text("{}")
    with patch("agent_bom.cloud.ollama._MANIFEST_DIR", tmp_path):
        yield


def test_tags_of_one_model_are_separate_artifacts_with_digests():
    with serving_fixture(SCENARIOS["ollama"]["success"]) as url:
        agents, warnings = discover(host=url)
    assert warnings == []
    assert len(agents) == 2
    assert len({a.stable_id for a in agents}) == 2
    digests = {a.metadata["serving_evidence"]["model"]["served_name"]: a.metadata["serving_evidence"]["model"]["digest"] for a in agents}
    assert digests == {"llama3.2:1b": "a" * 64, "llama3.2:3b": "b" * 64}
    for agent in agents:
        evidence = agent.metadata["serving_evidence"]
        assert evidence["runtime"]["name"] == "ollama"
        assert evidence["endpoint"]["url"] == url
        assert evidence["collection"]["status"] == "success"
        assert evidence["collection"]["observed_at"]
        # /api/tags lists downloaded models; it does not say which are loaded.
        assert evidence["model"]["state"] is None


@pytest.mark.parametrize(
    ("outcome", "word"),
    [("denied", "denied"), ("timeout", "timed out")],
)
def test_configured_endpoint_failure_names_the_outcome_and_skips_manifests(outcome, word):
    with serving_fixture(SCENARIOS["ollama"][outcome]) as url, patch("agent_bom.cloud.ollama._discover_from_manifests") as manifests:
        agents, warnings = discover(host=url, timeout=0.2)
    assert agents == []
    assert len(warnings) == 1 and word in warnings[0] and "incomplete" in warnings[0]
    manifests.assert_not_called()


def test_configured_unavailable_endpoint_skips_manifests():
    # The retrying fallback client is bypassed only to keep the refused-port case fast.
    with patch("agent_bom.cloud.ollama._discover_from_manifests") as manifests, patch("agent_bom.http_client.sync_get", return_value=None):
        agents, warnings = discover(host=closed_port_url(), timeout=0.5)
    assert agents == []
    assert len(warnings) == 1 and "unavailable" in warnings[0]
    manifests.assert_not_called()


def test_partial_inventory_keeps_valid_models_and_says_partial():
    with serving_fixture(SCENARIOS["ollama"]["partial"]) as url:
        agents, warnings = discover(host=url)
    assert [a.metadata["serving_evidence"]["model"]["served_name"] for a in agents] == ["llama3.2:1b"]
    assert len(warnings) == 1 and "partial" in warnings[0]
    assert agents[0].metadata["serving_evidence"]["collection"]["completeness"] == "partial"


def test_default_endpoint_failure_labels_manifest_inventory_as_local_only():
    with (
        patch("agent_bom.cloud.ollama._DEFAULT_OLLAMA_HOST", closed_port_url()),
        patch("agent_bom.http_client.sync_get", return_value=None),
    ):
        agents, warnings = discover(timeout=0.5)
    assert [a.source for a in agents] == ["ollama-manifest"]
    assert agents[0].discovery_envelope["scan_mode"] == "local_only"
    assert "serving_evidence" not in agents[0].metadata
    assert warnings and "unavailable" in warnings[0]
