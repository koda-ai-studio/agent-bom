"""One malformed Azure record must not erase the records listed after it."""

import sys
from types import ModuleType, SimpleNamespace

import pytest

from agent_bom.cloud import azure


class AzureReadError(Exception):
    def __init__(self, code=500):
        super().__init__("private-marker")
        self.status_code = code


@pytest.fixture(autouse=True)
def sdk(monkeypatch):
    install(monkeypatch, "azure.core.exceptions", AzureError=AzureReadError, ClientAuthenticationError=AzureReadError)


def install(monkeypatch, path, **members):
    module = ModuleType(path)
    module.__dict__.update(members)
    monkeypatch.setitem(sys.modules, path, module)


def rid(kind, name):
    return f"/subscriptions/s/resourceGroups/rg/providers/{kind}/{name}"


def app(name, containers):
    return SimpleNamespace(
        name=name,
        id=rid("Microsoft.App/containerApps", name),
        template=SimpleNamespace(containers=containers),
        location="x",
        system_data=None,
        identity=None,
    )


def good_app(name):
    return app(name, [SimpleNamespace(name="c", image="img:1")])


def container_apps(monkeypatch, apps):
    client = SimpleNamespace(container_apps=SimpleNamespace(list_by_subscription=lambda: iter(apps)))
    install(monkeypatch, "azure.mgmt.appcontainers", ContainerAppsAPIClient=lambda *_: client)
    return azure._discover_container_apps(object(), "s", None)


def assert_one_warning(warnings, resource):
    assert len(warnings) == 1, warnings
    assert warnings[0].startswith(f"azure:{resource}:unavailable:")
    assert "private-marker" not in warnings[0]


@pytest.mark.parametrize(
    "bad",
    [
        app("bad", 5),
        app("bad", [SimpleNamespace(name=None, image=7)]),
        app({"n": "private-marker"}, [SimpleNamespace(name="c", image="img:1")]),
    ],
)
def test_container_app_malformed_middle_record(monkeypatch, bad):
    agents, warnings = container_apps(monkeypatch, [good_app("a"), bad, good_app("c")])
    assert [a.name for a in agents] == ["azure-container-app:a", "azure-container-app:c"]
    assert_one_warning(warnings, "container-apps")


def test_multi_container_app_is_one_identity_with_one_server_per_container(monkeypatch):
    agents, warnings = container_apps(
        monkeypatch, [app("multi", [SimpleNamespace(name="c1", image="i1:1"), SimpleNamespace(name="c2", image="i2:1")])]
    )
    assert warnings == []
    assert len(agents) == 1
    assert len({a.stable_id for a in agents}) == 1
    assert [(s.name, s.args) for s in agents[0].mcp_servers] == [("container:c1", ["run", "i1:1"]), ("container:c2", ["run", "i2:1"])]


def test_app_without_images_is_not_an_agent(monkeypatch):
    agents, warnings = container_apps(monkeypatch, [app("empty", [SimpleNamespace(name="c", image="")])])
    assert (agents, warnings) == ([], [])


def test_ai_foundry_malformed_middle_record(monkeypatch):
    install(monkeypatch, "azure.ai.projects", AIProjectClient=object)
    resources = [
        SimpleNamespace(name="w1", id=rid("ws", "w1"), location="x"),
        SimpleNamespace(name=["private-marker"], id=rid("ws", "w2")),
        SimpleNamespace(name="w3", id=rid("ws", "w3"), location="x"),
    ]
    client = SimpleNamespace(resources=SimpleNamespace(list=lambda filter: iter(resources)))
    install(monkeypatch, "azure.mgmt.resource.resources", ResourceManagementClient=lambda *_: client)
    agents, warnings = azure._discover_ai_foundry(object(), "s", None)
    assert [a.name for a in agents] == ["azure-ai-foundry:w1", "azure-ai-foundry:w3"]
    assert_one_warning(warnings, "ai-foundry")


def test_container_instances_malformed_middle_group(monkeypatch):
    def group(name, containers):
        return SimpleNamespace(name=name, id=rid("Microsoft.ContainerInstance/containerGroups", name), location="x", containers=containers)

    groups = [
        group("g1", [SimpleNamespace(name="c", image="i:1")]),
        group("g2", [SimpleNamespace(name="c", image={"private-marker": 1})]),
        group("g3", [SimpleNamespace(name="c", image="i:3")]),
    ]
    client = SimpleNamespace(container_groups=SimpleNamespace(list=lambda: iter(groups)))
    install(monkeypatch, "azure.mgmt.containerinstance", ContainerInstanceManagementClient=lambda *_: client)
    agents, warnings = azure._discover_container_instances(object(), "s")
    assert [a.name for a in agents] == ["azure-aci:g1/c", "azure-aci:g3/c"]
    assert_one_warning(warnings, "container-instances")


def test_openai_malformed_deployment_keeps_siblings(monkeypatch):
    account = SimpleNamespace(kind="OpenAI", name="acct", id=rid("Microsoft.CognitiveServices/accounts", "acct"), location="eastus")
    model = SimpleNamespace(name="gpt-4o", version="1")
    deployments = [
        SimpleNamespace(name="d1", id=None, properties=SimpleNamespace(model=model), sku=None),
        SimpleNamespace(name={"private-marker": 1}, id=None, properties=None, sku=None),
        SimpleNamespace(name="d3", id=None, properties=SimpleNamespace(model=model), sku=None),
    ]
    client = SimpleNamespace(
        accounts=SimpleNamespace(list=lambda: iter([account])), deployments=SimpleNamespace(list=lambda *_: iter(deployments))
    )
    install(monkeypatch, "azure.mgmt.cognitiveservices", CognitiveServicesManagementClient=lambda *_: client)
    agents, warnings = azure._discover_openai_deployments(object(), "s")
    assert [a.name for a in agents] == ["azure-openai:acct/d1", "azure-openai:acct/d3"]
    assert_one_warning(warnings, "openai-deployments")
