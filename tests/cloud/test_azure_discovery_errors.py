"""Azure read failures retain inventory and remain distinguishable from empty."""

import sys
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock

import pytest

from agent_bom.cloud import azure


class AzureReadError(Exception):
    def __init__(self, code):
        super().__init__("fixture private response content")
        self.status_code = code
        self.response = SimpleNamespace(status_code=code)


class AzureAuthenticationError(AzureReadError):
    pass


@pytest.fixture(autouse=True)
def sdk_errors(monkeypatch):
    module = ModuleType("azure.core.exceptions")
    module.AzureError = AzureReadError
    module.ClientAuthenticationError = AzureAuthenticationError
    monkeypatch.setitem(sys.modules, "azure.core.exceptions", module)


def install(monkeypatch, path, **members):
    module = ModuleType(path)
    module.__dict__.update(members)
    monkeypatch.setitem(sys.modules, path, module)


def page_then_error(item, code):
    yield item
    raise AzureReadError(code)


@pytest.mark.parametrize("code,status", [(403, "denied"), (429, "throttled"), (503, "unavailable")])
@pytest.mark.parametrize("partial", [False, True])
def test_container_apps_read_status_and_partial_inventory(monkeypatch, code, status, partial):
    app = SimpleNamespace(
        name="observed", id="app-id", template=SimpleNamespace(containers=[SimpleNamespace(name="main", image="example/app:1")])
    )
    listing = Mock()
    if partial:
        listing.return_value = page_then_error(app, code)
    else:
        listing.side_effect = AzureReadError(code)
    client = SimpleNamespace(container_apps=SimpleNamespace(list_by_subscription=listing))
    install(monkeypatch, "azure.mgmt.appcontainers", ContainerAppsAPIClient=lambda *_: client)
    agents, warnings = azure._discover_container_apps(object(), "subscription", None)
    assert len(agents) == int(partial)
    assert len(warnings) == 1
    assert warnings[0].startswith(f"azure:container-apps:{status}:")
    assert "Assessment incomplete" in warnings[0]
    assert "fixture private response content" not in warnings[0]


def test_empty_container_apps_is_success_without_warning(monkeypatch):
    client = SimpleNamespace(container_apps=SimpleNamespace(list_by_subscription=lambda: iter(())))
    install(monkeypatch, "azure.mgmt.appcontainers", ContainerAppsAPIClient=lambda *_: client)
    assert azure._discover_container_apps(object(), "subscription", None) == ([], [])


def test_foundry_keeps_workspace_before_later_page_denial(monkeypatch):
    workspace = SimpleNamespace(name="observed", id="/subscriptions/sub/resourceGroups/rg/providers/workspaces/observed", location="west")
    client = SimpleNamespace(resources=SimpleNamespace(list=lambda **_: page_then_error(workspace, 403)))
    install(monkeypatch, "azure.ai.projects", AIProjectClient=object)
    install(monkeypatch, "azure.mgmt.resource.resources", ResourceManagementClient=lambda *_: client)
    agents, warnings = azure._discover_ai_foundry(object(), "sub", None)
    assert [agent.name for agent in agents] == ["azure-ai-foundry:observed"]
    assert warnings[0].startswith("azure:ai-foundry:denied:")


def test_unexpected_programming_error_is_not_empty_inventory(monkeypatch):
    install(monkeypatch, "azure.mgmt.appcontainers", ContainerAppsAPIClient=Mock(side_effect=RuntimeError("fixture bug")))
    with pytest.raises(RuntimeError, match="fixture bug"):
        azure._discover_container_apps(object(), "sub", None)


SERVICES = [
    (
        "_discover_container_apps",
        "azure.mgmt.appcontainers",
        "ContainerAppsAPIClient",
        "container_apps",
        "list_by_subscription",
        "container-apps",
    ),
    ("_discover_ai_foundry", "azure.mgmt.resource.resources", "ResourceManagementClient", "resources", "list", "ai-foundry"),
    (
        "_discover_openai_deployments",
        "azure.mgmt.cognitiveservices",
        "CognitiveServicesManagementClient",
        "accounts",
        "list",
        "cognitive-services",
    ),
    ("_discover_azure_functions", "azure.mgmt.web", "WebSiteManagementClient", "web_apps", "list", "functions"),
    (
        "_discover_container_instances",
        "azure.mgmt.containerinstance",
        "ContainerInstanceManagementClient",
        "container_groups",
        "list",
        "container-instances",
    ),
    (
        "_discover_ml_endpoints",
        "azure.mgmt.machinelearningservices",
        "MachineLearningServicesMgmtClient",
        "workspaces",
        "list_by_subscription",
        "ml-workspaces",
    ),
]


@pytest.mark.parametrize("service", SERVICES, ids=lambda service: service[-1])
@pytest.mark.parametrize("code,status", [(None, None), (403, "denied"), (429, "throttled")])
def test_each_service_distinguishes_empty_denied_and_throttled(monkeypatch, service, code, status):
    function, module, constructor, operations, listing, resource = service
    read = Mock(return_value=[])
    if code is not None:
        read.side_effect = AzureReadError(code)
    client = SimpleNamespace(**{operations: SimpleNamespace(**{listing: read})})
    install(monkeypatch, module, **{constructor: lambda *_: client})
    install(monkeypatch, "azure.ai.projects", AIProjectClient=object)
    install(monkeypatch, "azure.ai.ml", MLClient=object)
    args = [object(), "sub"] + ([None] if function in ("_discover_container_apps", "_discover_ai_foundry") else [])
    agents, warnings = getattr(azure, function)(*args)
    assert agents == []
    if code is None:
        assert warnings == []
    else:
        assert len(warnings) == 1
        assert warnings[0].startswith(f"azure:{resource}:{status}:")
        assert "fixture private response content" not in warnings[0]


def test_ml_retains_endpoint_and_deployments_when_child_page_throttles(monkeypatch):
    workspace = SimpleNamespace(name="workspace", id="/subscriptions/sub/resourceGroups/rg/providers/workspaces/workspace")
    endpoint = SimpleNamespace(name="endpoint")
    deployment = SimpleNamespace(name="first", model="model-v1", instance_type="small")
    management = SimpleNamespace(workspaces=SimpleNamespace(list_by_subscription=lambda: [workspace]))
    ml = SimpleNamespace(
        online_endpoints=SimpleNamespace(list=lambda: [endpoint]),
        online_deployments=SimpleNamespace(list=lambda **_: page_then_error(deployment, 429)),
    )
    install(monkeypatch, "azure.mgmt.machinelearningservices", MachineLearningServicesMgmtClient=lambda *_: management)
    install(monkeypatch, "azure.ai.ml", MLClient=lambda **_: ml)
    agents, warnings = azure._discover_ml_endpoints(object(), "sub")
    assert len(agents) == 1
    assert agents[0].metadata["deployments"] == [{"deployment": "first", "model": "model-v1", "instance_type": "small"}]
    assert warnings[0].startswith("azure:ml-deployments:throttled:")


def test_function_config_denial_does_not_hide_observed_function(monkeypatch):
    app = SimpleNamespace(name="function", kind="functionapp", id="/subscriptions/sub/resourceGroups/rg/providers/sites/function")
    operations = SimpleNamespace(list=lambda: [app], get_configuration=Mock(side_effect=AzureReadError(403)))
    install(monkeypatch, "azure.mgmt.web", WebSiteManagementClient=lambda *_: SimpleNamespace(web_apps=operations))
    monkeypatch.setattr("agent_bom.cloud.serverless_zip.extract_azure_function_packages", lambda *_: [])
    agents, warnings = azure._discover_azure_functions(object(), "sub")
    assert len(agents) == 1
    assert warnings[0].startswith("azure:function-site-config:denied:")


def test_authentication_error_without_http_response_is_denied(monkeypatch):
    install(monkeypatch, "azure.identity", DefaultAzureCredential=Mock(side_effect=AzureAuthenticationError(None)))
    agents, warnings = azure.discover(subscription_id="sub")
    assert agents == []
    assert "azure:authentication:denied:" in warnings[0]
    assert "fixture private response content" not in warnings[0]
