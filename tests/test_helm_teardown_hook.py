"""`helm uninstall` runs a cleanup hook; its Role must hold exactly what the hook calls."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from agent_bom.deploy_k8s_cleanup import CleanupOperation, build_cleanup_operations, execute_cleanup

CHART = Path(__file__).resolve().parents[1] / "deploy/helm/agent-bom"
NAMESPACE = "abom-test"
helm_required = pytest.mark.skipif(shutil.which("helm") is None, reason="helm not installed")


def _hook_documents(*extra: str) -> list[dict]:
    rendered = subprocess.run(  # noqa: S603, S607 - fixed binary, test-owned arguments
        ["helm", "template", "release", str(CHART), "--namespace", NAMESPACE, *extra],
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    ).stdout
    documents = [document for document in yaml.safe_load_all(rendered) if document]
    return [document for document in documents if "teardown-hook" in str(document["metadata"].get("labels", {}))]


def _role_rules(*extra: str) -> list[dict]:
    return next(document for document in _hook_documents(*extra) if document["kind"] == "Role")["rules"]


def _role_grants(*extra: str) -> dict[tuple[str, str], set[str]]:
    grants: dict[tuple[str, str], set[str]] = {}
    for rule in _role_rules(*extra):
        for group in rule["apiGroups"]:
            for resource in rule["resources"]:
                grants.setdefault((group, resource), set()).update(rule["verbs"])
    return grants


def _required_grant(operation: CleanupOperation) -> tuple[tuple[str, str], str]:
    parts = operation.api_path.strip("/").split("/")
    group = "" if parts[0] == "api" else parts[1]
    namespace_index = parts.index("namespaces")
    resource = parts[namespace_index + 2]
    return (group, resource), "deletecollection" if operation.target == "collection" else "delete"


def _hook_args(document: dict) -> list[str]:
    return document["spec"]["template"]["spec"]["containers"][0]["command"]


@helm_required
@pytest.mark.parametrize(("extra", "targets"), [((), []), (("--set", "teardownHooks.extraTargetSecrets[0]=generated"), ["generated"])])
def test_role_grants_exactly_what_the_cleanup_operations_call(extra: tuple[str, ...], targets: list[str]) -> None:
    required: dict[tuple[str, str], set[str]] = {}
    for operation in build_cleanup_operations(namespace=NAMESPACE, label_selector="a=b", target_secrets=targets):
        resource, verb = _required_grant(operation)
        required.setdefault(resource, set()).add(verb)

    assert _role_grants(*extra) == required
    assert required[("batch", "jobs")] == {"deletecollection"}


@helm_required
def test_secret_access_is_absent_by_default_and_named_when_needed() -> None:
    assert not any("secrets" in rule["resources"] for rule in _role_rules())

    rules = [rule for rule in _role_rules("--set", "teardownHooks.extraTargetSecrets[0]=generated") if "secrets" in rule["resources"]]
    assert rules == [{"apiGroups": [""], "resources": ["secrets"], "resourceNames": ["generated"], "verbs": ["delete"]}]


@helm_required
def test_role_grants_no_wildcards() -> None:
    grants = _role_grants()

    assert all("*" not in verbs and "*" not in resource for resource, verbs in grants.items())


@helm_required
def test_hooks_do_not_select_their_own_job() -> None:
    jobs = [document for document in _hook_documents() if document["kind"] == "Job"]

    assert {job["metadata"]["annotations"]["helm.sh/hook"] for job in jobs} == {"pre-delete", "post-delete"}
    for job in jobs:
        args = _hook_args(job)
        selector = args[args.index("--label-selector") + 1]
        assert "app.kubernetes.io/component!=teardown-hook" in selector.split(",")
        assert job["metadata"]["labels"]["app.kubernetes.io/component"] == "teardown-hook"


def test_collection_deletes_also_remove_the_pods_of_deleted_jobs(monkeypatch: pytest.MonkeyPatch) -> None:
    """batch/v1 Jobs orphan their pods unless the delete asks for propagation."""
    calls: list[tuple[str, dict[str, str] | None]] = []

    def record(_method: str, path: str, query: dict[str, str] | None = None) -> tuple[int, str]:
        calls.append((path, query))
        return 200, "{}"

    monkeypatch.setattr("agent_bom.deploy_k8s_cleanup._request", record)
    operations = build_cleanup_operations(namespace=NAMESPACE, label_selector="a=b", target_secrets=["generated"])

    assert execute_cleanup(operations) == 0

    by_path = dict(calls)
    job_query = by_path[f"/apis/batch/v1/namespaces/{NAMESPACE}/jobs"]
    assert job_query == {"labelSelector": "a=b", "propagationPolicy": "Background"}
    assert by_path[f"/api/v1/namespaces/{NAMESPACE}/secrets/generated"] is None
