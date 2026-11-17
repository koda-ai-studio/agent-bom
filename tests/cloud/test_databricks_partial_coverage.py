"""Later SDK-page failures must not discard already discovered assets."""

from types import SimpleNamespace

import pytest

from agent_bom.cloud import databricks
from agent_bom.models import Package


class DeniedError(Exception):
    pass


@pytest.mark.parametrize("resource", ["clusters", "serving_endpoints"])
@pytest.mark.parametrize("failure", [DeniedError, RuntimeError])
def test_later_page_failure_retains_prior_inventory(monkeypatch, resource, failure):
    cluster = SimpleNamespace(cluster_id="fixture-cluster", cluster_name="fixture", state="RUNNING")
    endpoint = SimpleNamespace(name="fixture-endpoint", state=SimpleNamespace(ready=SimpleNamespace(value="READY")))

    def pages():
        yield cluster if resource == "clusters" else endpoint
        raise failure("fixture-sensitive-provider-message")

    ws = SimpleNamespace(**{resource: SimpleNamespace(list=pages)})
    monkeypatch.setattr(databricks, "databricks_node_gpu_counts", lambda _ws: {})
    monkeypatch.setattr(
        databricks, "_get_cluster_packages", lambda *_args: [Package(name="fixture-package", version="1", ecosystem="pypi")]
    )
    monkeypatch.setattr(databricks, "databricks_gpu_profile", lambda *_args: None)
    collect = databricks._discover_cluster_agents if resource == "clusters" else databricks._discover_serving_agents
    warnings = []
    agents = collect(ws, "https://fixture.cloud.databricks.com", warnings, DeniedError)
    assert len(agents) == 1
    assert agents[0].source == "databricks"
    assert warnings
    assert not any("fixture-sensitive-provider-message" in warning for warning in warnings)
