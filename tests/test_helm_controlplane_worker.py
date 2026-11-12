"""Structural contract for the optional control-plane scan/ingest worker Deployment."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from tests._helm_render import ATTESTED_API

ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "deploy/helm/agent-bom"
pytestmark = pytest.mark.skipif(shutil.which("helm") is None, reason="helm not installed")

_POSTGRES = {
    "enabled": True,
    "appSecretRef": {"name": "test-db"},
    "maintenanceSecretRef": {"name": "test-maintenance"},
    "adminSecretRef": {"name": "test-admin"},
}


def _render(control_plane: dict | None = None, *, postgres: bool = True, pdb: bool = True) -> subprocess.CompletedProcess[str]:
    values: dict = {"controlPlane": {"enabled": True, **(control_plane or {})}, "pdb": {"enabled": pdb}}
    values["controlPlane"]["api"] = {**ATTESTED_API, **values["controlPlane"].get("api", {})}
    if postgres:
        values["controlPlane"]["postgresSecrets"] = _POSTGRES
    return subprocess.run(
        ["helm", "template", "worker-split", str(CHART), "--values", "-"],
        input=yaml.safe_dump(values),
        text=True,
        capture_output=True,
        check=False,
    )


def _objects(result: subprocess.CompletedProcess[str]) -> list[dict]:
    assert result.returncode == 0, result.stderr
    return [doc for doc in yaml.safe_load_all(result.stdout) if doc]


def _find(objects: list[dict], kind: str, name: str) -> dict | None:
    return next((doc for doc in objects if doc["kind"] == kind and doc["metadata"]["name"] == name), None)


def _container(deployment: dict) -> dict:
    containers = deployment["spec"]["template"]["spec"]["containers"]
    assert len(containers) == 1, containers
    return containers[0]


def _env(deployment: dict) -> dict[str, dict]:
    return {entry["name"]: entry for entry in _container(deployment)["env"]}


def _value(env: dict[str, dict], name: str) -> str | None:
    entry = env.get(name)
    return None if entry is None else entry.get("value")


def _worker(**overrides) -> dict:
    return {"worker": {"enabled": True, **overrides}}


def test_worker_disabled_renders_nothing_new_and_leaves_api_role_unset():
    objects = _objects(_render())
    names = {(doc["kind"], doc["metadata"]["name"]) for doc in objects}
    assert not any(name.endswith("-worker") for _, name in names), names
    api = _find(objects, "Deployment", "agent-bom-api")
    assert api is not None
    env = _env(api)
    assert "AGENT_BOM_API_ROLE" not in env
    assert "AGENT_BOM_DISTRIBUTED_SCANS" not in env


def test_worker_enabled_splits_roles_and_shares_the_api_pod_contract():
    objects = _objects(_render(_worker(replicas=3)))
    api = _find(objects, "Deployment", "agent-bom-api")
    worker = _find(objects, "Deployment", "agent-bom-worker")
    assert api is not None and worker is not None

    api_env, worker_env = _env(api), _env(worker)
    assert _value(api_env, "AGENT_BOM_API_ROLE") == "api"
    assert _value(worker_env, "AGENT_BOM_API_ROLE") == "worker"
    assert _value(api_env, "AGENT_BOM_DISTRIBUTED_SCANS") == "1"
    assert _value(worker_env, "AGENT_BOM_DISTRIBUTED_SCANS") == "1"

    # Every process sharing the database counts toward shared-state guards.
    assert _value(api_env, "AGENT_BOM_CONTROL_PLANE_REPLICAS") == "5"
    assert _value(worker_env, "AGENT_BOM_CONTROL_PLANE_REPLICAS") == "5"

    # Same Postgres identities (claims run on the maintenance role).
    for name in ("AGENT_BOM_POSTGRES_URL", "AGENT_BOM_POSTGRES_MAINTENANCE_URL"):
        assert worker_env[name]["valueFrom"] == api_env[name]["valueFrom"], name

    # Everything except role-specific env matches the API pod.
    shared = set(api_env) - {"AGENT_BOM_API_ROLE"}
    assert shared <= set(worker_env)
    for name in shared - {"AGENT_BOM_CONTROL_PLANE_REPLICAS"}:
        assert worker_env[name] == api_env[name], name

    api_pod, worker_pod = api["spec"]["template"]["spec"], worker["spec"]["template"]["spec"]
    for key in ("serviceAccountName", "automountServiceAccountToken", "securityContext", "volumes"):
        assert worker_pod.get(key) == api_pod.get(key), key
    api_c, worker_c = _container(api), _container(worker)
    for key in ("image", "args", "securityContext", "volumeMounts", "ports", "readinessProbe", "livenessProbe"):
        assert worker_c.get(key) == api_c.get(key), key

    assert worker["spec"]["replicas"] == 3
    labels = worker["spec"]["template"]["metadata"]["labels"]
    assert labels["app.kubernetes.io/component"] == "worker"
    assert worker["spec"]["selector"]["matchLabels"]["app.kubernetes.io/component"] == "worker"


def test_no_service_routes_to_worker_pods():
    objects = _objects(_render(_worker()))
    worker = _find(objects, "Deployment", "agent-bom-worker")
    assert worker is not None
    pod_labels = worker["spec"]["template"]["metadata"]["labels"]
    services = [doc for doc in objects if doc["kind"] == "Service"]
    assert services, "expected the API and UI Services to render"
    for service in services:
        selector = service["spec"].get("selector") or {}
        assert selector, service["metadata"]["name"]
        assert not all(pod_labels.get(k) == v for k, v in selector.items()), service["metadata"]["name"]


def test_worker_network_policy_admits_no_peer_traffic_by_default():
    objects = _objects(_render(_worker()))
    policy = _find(objects, "NetworkPolicy", "agent-bom-worker")
    assert policy is not None
    assert policy["spec"]["podSelector"]["matchLabels"]["app.kubernetes.io/component"] == "worker"
    assert policy["spec"]["policyTypes"] == ["Ingress"]
    assert policy["spec"].get("ingress", []) == []


def test_worker_pdb_and_hpa_render_for_scaled_workers():
    objects = _objects(_render(_worker(replicas=2, autoscaling={"enabled": True, "minReplicas": 2, "maxReplicas": 8})))
    pdb = _find(objects, "PodDisruptionBudget", "agent-bom-worker")
    assert pdb is not None
    assert pdb["spec"]["selector"]["matchLabels"]["app.kubernetes.io/component"] == "worker"
    hpa = _find(objects, "HorizontalPodAutoscaler", "agent-bom-worker")
    assert hpa is not None
    assert hpa["spec"]["scaleTargetRef"]["name"] == "agent-bom-worker"
    assert hpa["spec"]["maxReplicas"] == 8
    assert _find(objects, "ScaledObject", "agent-bom-worker") is None
    worker = _find(objects, "Deployment", "agent-bom-worker")
    assert _value(_env(worker), "AGENT_BOM_CONTROL_PLANE_REPLICAS") == "10"


def test_single_worker_has_no_pdb():
    objects = _objects(_render(_worker(replicas=1)))
    assert _find(objects, "PodDisruptionBudget", "agent-bom-worker") is None


def test_worker_keda_scales_on_the_claimable_queue_depth():
    from agent_bom.api.postgres_job_store import PostgresJobStore

    objects = _objects(
        _render(
            _worker(
                autoscaling={
                    "enabled": True,
                    "minReplicas": 1,
                    "maxReplicas": 10,
                    "keda": {"enabled": True, "authenticationRef": {"name": "worker-queue-auth"}},
                }
            )
        )
    )
    assert _find(objects, "HorizontalPodAutoscaler", "agent-bom-worker") is None
    scaled = _find(objects, "ScaledObject", "agent-bom-worker")
    assert scaled is not None
    assert scaled["spec"]["scaleTargetRef"]["name"] == "agent-bom-worker"
    (trigger,) = scaled["spec"]["triggers"]
    assert trigger["type"] == "postgresql"
    assert trigger["authenticationRef"] == {"name": "worker-queue-auth", "kind": "TriggerAuthentication"}
    query = " ".join(trigger["metadata"]["query"].split())
    assert "FROM scan_dispatch_queue" in query
    assert "status = 'pending'" in query
    # Same lease-expiry predicate the claim loop uses, so the scaler counts exactly
    # what a worker can claim (lease_expires_at is ISO text, not timestamptz).
    assert " ".join(PostgresJobStore._NOW_ISO.split()) in query
    assert re.fullmatch(r"\d+(\.\d+)?", trigger["metadata"]["targetQueryValue"])


def test_worker_keda_requires_trigger_authentication():
    result = _render(_worker(autoscaling={"enabled": True, "keda": {"enabled": True}}))
    assert result.returncode != 0
    assert "authenticationRef.name" in result.stderr


def test_worker_requires_split_postgres_secrets():
    result = _render(_worker(), postgres=False)
    assert result.returncode != 0
    assert "controlPlane.worker.enabled requires controlPlane.postgresSecrets.enabled" in result.stderr


@pytest.mark.parametrize("name", ["AGENT_BOM_API_ROLE", "AGENT_BOM_DISTRIBUTED_SCANS"])
def test_role_env_cannot_be_overridden_when_split(name: str):
    worker_override = _render(_worker(extraEnv=[{"name": name, "value": "all"}]))
    assert worker_override.returncode != 0
    assert name in worker_override.stderr
    api_override = _render({**_worker(), "api": {"env": [{"name": name, "value": "all"}]}})
    assert api_override.returncode != 0
    assert name in api_override.stderr


def test_worker_scheduling_and_resources_override_independently():
    objects = _objects(
        _render(
            _worker(
                nodeSelector={"pool": "scan"},
                tolerations=[{"key": "scan", "operator": "Exists", "effect": "NoSchedule"}],
                resources={"requests": {"memory": "1Gi", "cpu": "250m"}, "limits": {"memory": "4Gi", "cpu": "2"}},
                extraEnv=[{"name": "AGENT_BOM_SCAN_WORKERS", "value": "4"}],
            )
        )
    )
    worker = _find(objects, "Deployment", "agent-bom-worker")
    api = _find(objects, "Deployment", "agent-bom-api")
    pod = worker["spec"]["template"]["spec"]
    assert pod["nodeSelector"] == {"pool": "scan"}
    assert pod["tolerations"][0]["key"] == "scan"
    assert "nodeSelector" not in api["spec"]["template"]["spec"]
    assert _container(worker)["resources"]["limits"]["memory"] == "4Gi"
    assert _value(_env(worker), "AGENT_BOM_SCAN_WORKERS") == "4"
    assert "AGENT_BOM_SCAN_WORKERS" not in _env(api)
