"""Ollama inventory must retain the selected collection boundary."""

from unittest.mock import patch

import pytest

from agent_bom.cloud import discover_from_provider, ollama
from agent_bom.cloud.ollama import discover


@pytest.mark.parametrize("host", ["http://localhost:11434", "https://models.example.test"])
def test_api_inventory_has_endpoint_scoped_envelope(host):
    with patch("agent_bom.cloud.ollama._discover_via_api", return_value=[{"name": "tiny:latest"}]):
        agents, warnings = discover_from_provider("ollama", host=host)
    assert not warnings
    assert len(agents) == 1
    envelope = agents[0].discovery_envelope
    assert envelope is not None
    assert envelope["scan_mode"] == "runtime_probe"
    assert envelope["discovery_scope"] == [f"ollama:host/{host}"]
    assert envelope["permissions_used"] == ["ollama:GET /api/tags"]
    assert envelope["captured_at"]


@pytest.mark.parametrize("from_env", [False, True])
def test_failed_selected_endpoint_never_reads_local_manifests(tmp_path, monkeypatch, from_env):
    local_model = tmp_path / "library" / "unrelated-local-model"
    local_model.mkdir(parents=True)
    (local_model / "latest").write_text("{}")
    host = "https://models.example.test"
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    if from_env:
        monkeypatch.setenv("OLLAMA_HOST", host)
    with (
        patch("agent_bom.cloud.ollama._discover_via_api", return_value=None),
        patch("agent_bom.cloud.ollama._MANIFEST_DIR", tmp_path),
        patch("agent_bom.cloud.ollama._discover_from_manifests", wraps=ollama._discover_from_manifests) as manifests,
    ):
        agents, warnings = discover(host=None if from_env else host)
    assert agents == []
    assert warnings and "incomplete" in warnings[0].lower()
    manifests.assert_not_called()


def test_default_manifest_fallback_reports_its_actual_scope(tmp_path, monkeypatch):
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    model = tmp_path / "library" / "tiny"
    model.mkdir(parents=True)
    (model / "latest").write_text("{}")
    with (
        patch("agent_bom.cloud.ollama._discover_via_api", return_value=None),
        patch("agent_bom.cloud.ollama._MANIFEST_DIR", tmp_path),
    ):
        agents, warnings = discover()
    assert len(agents) == 1
    assert warnings and "manifest" in warnings[0].lower()
    envelope = agents[0].discovery_envelope
    assert envelope["scan_mode"] == "local_only"
    assert envelope["discovery_scope"] == [f"ollama:manifest_dir/{tmp_path}"]
    assert envelope["permissions_used"] == ["filesystem:read manifests"]


def test_empty_successful_api_does_not_fall_back(tmp_path):
    with (
        patch("agent_bom.cloud.ollama._discover_via_api", return_value=[]),
        patch("agent_bom.cloud.ollama._discover_from_manifests") as manifests,
    ):
        agents, warnings = discover(host="https://models.example.test")
    assert agents == []
    assert warnings == []
    manifests.assert_not_called()


def test_connection_failure_preserves_default_manifest_fallback(tmp_path, monkeypatch):
    import httpx

    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    model = tmp_path / "library" / "tiny"
    model.mkdir(parents=True)
    (model / "latest").write_text("{}")
    with (
        patch("httpx.get", side_effect=httpx.ConnectError("fixture endpoint unavailable")),
        patch("agent_bom.http_client.sync_get", return_value=None),
        patch("agent_bom.cloud.ollama._MANIFEST_DIR", tmp_path),
    ):
        agents, warnings = discover()
    assert len(agents) == 1 and agents[0].source == "ollama-manifest"
    assert warnings


@pytest.mark.parametrize("payload", [{}, [], {"models": None}, {"models": "invalid"}, {"models": [None]}])
def test_invalid_api_inventory_is_incomplete_instead_of_verified_empty(payload):
    from unittest.mock import MagicMock

    response = MagicMock(status_code=200)
    response.json.return_value = payload
    with patch("httpx.get", return_value=response), patch("agent_bom.http_client.sync_get", return_value=response):
        assert ollama._discover_via_api("http://localhost:11434") is None
