"""GCP read failures remain distinct from successful empty inventory."""

from types import ModuleType, SimpleNamespace
from unittest.mock import MagicMock

import pytest

from agent_bom.cloud import gcp
from tests._sdk_stub_helpers import patch_sdk_namespace


class GoogleAPIError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__("private provider response")


class GoogleAuthError(Exception):
    pass


class DefaultCredentialsError(GoogleAuthError):
    pass


class RefreshError(GoogleAuthError):
    pass


SERVICES = [
    ("aiplatform_v1", "EndpointServiceClient", "list_endpoints", "_discover_vertex_ai", "Vertex AI"),
    ("functions_v2", "FunctionServiceClient", "list_functions", "_discover_cloud_functions", "Cloud Functions"),
    ("container_v1", "ClusterManagerClient", "list_clusters", "_discover_gke_clusters", "GKE"),
    ("run_v2", "ServicesClient", "list_services", "_discover_cloud_run", "Cloud Run"),
]


@pytest.fixture(params=SERVICES, ids=[s[0] for s in SERVICES])
def service(request):
    module, constructor, method, helper, label = request.param
    names = ["google", "google.cloud", "google.api_core", "google.api_core.exceptions", "google.auth", "google.auth.exceptions"]
    names += ["google.cloud.aiplatform", f"google.cloud.{module}"]
    modules = {name: ModuleType(name) for name in names}
    for name, value in modules.items():
        if "." in name:
            parent, child = name.rsplit(".", 1)
            setattr(modules[parent], child, value)
    modules["google.api_core.exceptions"].GoogleAPIError = GoogleAPIError
    modules["google.auth.exceptions"].GoogleAuthError = GoogleAuthError
    modules["google.auth.exceptions"].DefaultCredentialsError = DefaultCredentialsError
    modules["google.auth.exceptions"].RefreshError = RefreshError
    client = MagicMock()
    setattr(modules[f"google.cloud.{module}"], constructor, MagicMock(return_value=client))
    with patch_sdk_namespace(modules, "google"):
        yield getattr(gcp, helper), getattr(client, method), label


@pytest.mark.parametrize("code,status", [(401, "denied"), (403, "denied"), (429, "throttled"), (503, "unavailable")])
def test_read_failure_is_classified(service, code, status):
    discover, read, label = service
    read.side_effect = GoogleAPIError(code)
    agents, warnings = discover("project", "us-central1")
    assert agents == []
    assert len(warnings) == 1
    assert warnings[0].startswith(f"gcp:{label}:{status}:")
    assert "Assessment incomplete" in warnings[0]
    assert "private provider response" not in warnings[0]


@pytest.mark.parametrize("error", [DefaultCredentialsError, RefreshError])
def test_auth_failure_is_denied(service, error):
    discover, read, label = service
    read.side_effect = error("private credential path")
    assert discover("project", "us-central1")[1][0].startswith(f"gcp:{label}:denied:")


def test_empty_success_has_no_warning(service):
    discover, read, label = service
    read.return_value = SimpleNamespace(clusters=[]) if label == "GKE" else []
    assert discover("project", "us-central1") == ([], [])


def test_unexpected_programming_failure_propagates(service):
    discover, read, _ = service
    read.side_effect = RuntimeError("implementation bug")
    with pytest.raises(RuntimeError, match="implementation bug"):
        discover("project", "us-central1")


def test_later_page_failure_retains_inventory(service):
    discover, read, label = service
    record = {
        "Vertex AI": SimpleNamespace(name="projects/p/locations/r/endpoints/e", display_name="e", deployed_models=[]),
        "Cloud Functions": SimpleNamespace(name="projects/p/locations/r/functions/f"),
        "GKE": SimpleNamespace(name="cluster", endpoint="127.0.0.1"),
        "Cloud Run": SimpleNamespace(
            name="projects/p/locations/r/services/s", template=SimpleNamespace(containers=[SimpleNamespace(image="example/app:1")])
        ),
    }[label]

    def pages():
        yield record
        raise GoogleAPIError(429)

    read.return_value = SimpleNamespace(clusters=pages()) if label == "GKE" else pages()
    agents, warnings = discover("project", "us-central1")
    assert len(agents) == 1
    assert warnings[0].startswith(f"gcp:{label}:throttled:")


def test_auth_transport_failure_is_unavailable(service):
    discover, read, label = service
    read.side_effect = GoogleAuthError("private transport failure")
    assert discover("project", "us-central1")[1][0].startswith(f"gcp:{label}:unavailable:")


def test_dispatcher_reports_failure_and_continues(service, monkeypatch):
    discover, _, label = service
    calls = []
    for _, _, _, helper, _ in SERVICES:

        def empty(helper=helper):
            def run(*args):
                calls.append(helper)
                if helper == discover.__name__:
                    raise GoogleAPIError(403)
                return [], []

            return run

        monkeypatch.setattr(gcp, helper, empty())
    agents, warnings = gcp.discover("project", "us-central1")
    assert agents == []
    assert len(calls) == 4
    assert len(warnings) == 1
    assert warnings[0].startswith(f"gcp:{label}:denied:")


def test_structured_disabled_api_remains_notice(service):
    from agent_bom.cloud.normalization import ServiceNotInUse

    discover, read, _ = service
    error = GoogleAPIError(403)
    error.reason = "SERVICE_DISABLED"
    read.side_effect = error
    agents, warnings = discover("project", "us-central1")
    assert agents == []
    assert isinstance(warnings[0], ServiceNotInUse)


def test_disabled_text_cannot_hide_denial(service):
    from agent_bom.cloud.normalization import ServiceNotInUse

    discover, read, label = service
    error = GoogleAPIError(403)
    error.args = ("SERVICE_DISABLED",)
    read.side_effect = error
    warnings = discover("project", "us-central1")[1]
    assert not isinstance(warnings[0], ServiceNotInUse)
    assert warnings[0].startswith(f"gcp:{label}:denied:")
