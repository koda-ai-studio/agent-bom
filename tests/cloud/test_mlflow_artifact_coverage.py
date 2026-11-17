"""MLflow dependency evidence comes from artifact bytes, not local filenames."""

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from agent_bom.cloud import mlflow_provider as provider


class ProviderError(Exception):
    def __init__(self, code):
        self.error_code = code
        super().__init__("private-provider-marker")


def model_client(monkeypatch):
    client = MagicMock()
    model = SimpleNamespace(
        name="fixture-model", latest_versions=[SimpleNamespace(version="1", current_stage="", run_id="fixture-run", source="")]
    )
    client.search_registered_models.return_value = [model]
    client.search_experiments.return_value = []
    monkeypatch.setitem(sys.modules, "mlflow", SimpleNamespace(MlflowClient=lambda **kw: client))
    return client


def artifact_listing(client, files):
    def listing(run_id, path=None):
        if path is None:
            return [SimpleNamespace(path="model", is_dir=True)]
        return [SimpleNamespace(path=f"model/{name}", is_dir=False, file_size=len(content)) for name, content in files.items()]

    client.list_artifacts.side_effect = listing


def test_downloaded_file_contents_become_packages(monkeypatch, tmp_path):
    client = model_client(monkeypatch)
    files = {"requirements.txt": b"numpy==1.26.4\n", "conda.yaml": b"dependencies:\n  - pip:\n    - pandas==2.2.3\n"}
    artifact_listing(client, files)
    destinations = []

    def download(run_id, path, dst_path=None):
        destination = Path(dst_path) if dst_path else tmp_path
        destinations.append(destination)
        local = destination / Path(path).name
        local.write_bytes(files[Path(path).name])
        return str(local)

    client.download_artifacts.side_effect = download
    agents, warnings = provider.discover(tracking_uri="https://tracking.example.test")
    assert [(p.name, p.version) for p in agents[0].mcp_servers[0].packages] == [("numpy", "1.26.4"), ("pandas", "2.2.3")]
    assert warnings == []
    assert destinations and all(not path.exists() for path in destinations)


@pytest.mark.parametrize(
    "code,status",
    [
        ("PERMISSION_DENIED", "denied"),
        ("UNAUTHENTICATED", "denied"),
        ("REQUEST_LIMIT_EXCEEDED", "throttled"),
        ("RESOURCE_EXHAUSTED", "throttled"),
        ("INTERNAL_ERROR", "unavailable"),
    ],
)
def test_artifact_denial_retains_model_with_incomplete_coverage(monkeypatch, code, status):
    client = model_client(monkeypatch)
    client.list_artifacts.side_effect = ProviderError(code)
    agents, warnings = provider.discover(tracking_uri="https://tracking.example.test")
    assert [a.name for a in agents] == ["mlflow-model:fixture-model"]
    assert agents[0].mcp_servers[0].packages == []
    assert any(w.startswith(f"mlflow:artifacts:{status}:") for w in warnings)
    assert "private-provider-marker" not in str(warnings)


def test_explicit_empty_artifacts_have_no_warning(monkeypatch):
    client = model_client(monkeypatch)
    client.list_artifacts.return_value = []
    agents, warnings = provider.discover(tracking_uri="https://tracking.example.test")
    assert len(agents) == 1
    assert warnings == []
    client.download_artifacts.assert_not_called()


@pytest.mark.parametrize("code,status", [("PERMISSION_DENIED", "denied"), ("REQUEST_LIMIT_EXCEEDED", "throttled")])
def test_failed_model_list_is_typed_and_not_empty_success(monkeypatch, code, status):
    client = model_client(monkeypatch)
    client.search_registered_models.side_effect = ProviderError(code)
    agents, warnings = provider.discover(tracking_uri="https://tracking.example.test")
    assert agents == []
    assert warnings[0].startswith(f"mlflow:models:{status}:")
    assert "private-provider-marker" not in str(warnings)


@pytest.mark.parametrize("failure", ["outside", "symlink", "oversized", "invalid_utf8", "directory"])
def test_unsafe_download_is_incomplete_and_cleaned(monkeypatch, tmp_path, failure):
    client = model_client(monkeypatch)
    artifact_listing(client, {"requirements.txt": b"safe==1\n"})
    destinations = []
    outside = tmp_path / "private.txt"
    outside.write_text("private-package==9\n")

    def download(run_id, path, dst_path=None):
        destination = Path(dst_path)
        destinations.append(destination)
        local = destination / "requirements.txt"
        if failure == "outside":
            return str(outside)
        if failure == "symlink":
            local.symlink_to(outside)
        elif failure == "oversized":
            local.write_bytes(b"x" * (1024 * 1024 + 1))
        elif failure == "invalid_utf8":
            local.write_bytes(b"\xff")
        else:
            local.mkdir()
        return str(local)

    client.download_artifacts.side_effect = download
    agents, warnings = provider.discover("https://tracking.example.test")
    assert len(agents) == 1
    assert agents[0].mcp_servers[0].packages == []
    assert warnings and warnings[0].startswith("mlflow:artifacts:unavailable:")
    assert str(outside) not in str(warnings)
    assert outside.read_text() == "private-package==9\n"
    assert destinations and all(not path.exists() for path in destinations)


def test_manifest_failure_preserves_other_packages(monkeypatch):
    client = model_client(monkeypatch)
    artifact_listing(client, {"requirements.txt": b"numpy==1.26.4\n", "conda.yaml": b"broken"})

    def download(run_id, path, dst_path=None):
        if path.endswith("conda.yaml"):
            raise ProviderError("PERMISSION_DENIED")
        local = Path(dst_path) / "requirements.txt"
        local.write_text("numpy==1.26.4\n")
        return str(local)

    client.download_artifacts.side_effect = download
    agents, warnings = provider.discover("https://tracking.example.test")
    assert [p.name for p in agents[0].mcp_servers[0].packages] == ["numpy"]
    assert warnings[0].startswith("mlflow:artifacts:denied:")


def test_declared_oversized_manifest_is_not_downloaded(monkeypatch):
    client = model_client(monkeypatch)
    client.list_artifacts.side_effect = [
        [SimpleNamespace(path="model", is_dir=True)],
        [SimpleNamespace(path="model/requirements.txt", is_dir=False, file_size=1024 * 1024 + 1)],
    ]
    agents, warnings = provider.discover("https://tracking.example.test")
    assert len(agents) == 1
    assert warnings[0].startswith("mlflow:artifacts:unavailable:")
    client.download_artifacts.assert_not_called()


def test_run_failure_preserves_experiment(monkeypatch):
    client = model_client(monkeypatch)
    client.list_artifacts.return_value = []
    client.search_experiments.return_value = [SimpleNamespace(experiment_id="7", name="training")]
    client.search_runs.side_effect = ProviderError("PERMISSION_DENIED")
    agents, warnings = provider.discover("https://tracking.example.test")
    assert [a.name for a in agents] == ["mlflow-model:fixture-model", "mlflow-exp:training"]
    assert warnings[0].startswith("mlflow:runs:denied:")
    assert "private-provider-marker" not in str(warnings)


def test_missing_optional_manifests_are_not_downloaded(monkeypatch):
    client = model_client(monkeypatch)
    artifact_listing(client, {"unrelated.txt": b"not a dependency manifest"})
    agents, warnings = provider.discover("https://tracking.example.test")
    assert len(agents) == 1
    assert warnings == []
    client.download_artifacts.assert_not_called()


def test_failed_child_listing_is_incomplete(monkeypatch):
    client = model_client(monkeypatch)
    client.list_artifacts.side_effect = [[SimpleNamespace(path="model", is_dir=True)], ProviderError("PERMISSION_DENIED")]
    agents, warnings = provider.discover("https://tracking.example.test")
    assert len(agents) == 1
    assert warnings[0].startswith("mlflow:artifacts:denied:")
    client.download_artifacts.assert_not_called()


def test_malformed_yaml_is_incomplete_and_cleaned(monkeypatch):
    client = model_client(monkeypatch)
    artifact_listing(client, {"conda.yaml": b"dependencies: ["})
    destinations = []

    def download(run_id, path, dst_path=None):
        destination = Path(dst_path)
        destinations.append(destination)
        local = destination / "conda.yaml"
        local.write_text("dependencies: [")
        return str(local)

    client.download_artifacts.side_effect = download
    agents, warnings = provider.discover("https://tracking.example.test")
    assert len(agents) == 1
    assert warnings[0].startswith("mlflow:artifacts:unavailable:")
    assert all(not path.exists() for path in destinations)
