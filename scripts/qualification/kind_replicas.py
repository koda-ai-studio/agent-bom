#!/usr/bin/env python3
"""Install the chart with several API replicas on one Postgres in a local kind cluster, for ``replicas.py``.

The load balancer is the API Service as a NodePort, mapped to a loopback port on
the host, so kube-proxy spreads connections over the replicas. Postgres 16 runs
in the cluster and is migrated by the chart's own Alembic hook. Everything the
Postgres profile documents is supplied: the app, maintenance and admin Secrets,
an API key, the audit HMAC key and trusted-proxy attestation with a pinned
issuer (a clustered API refuses a non-loopback listener without it). Values are
generated per run and never printed.

    python scripts/qualification/kind_replicas.py up --image agent-bom:local --replicas 3
    python scripts/qualification/replicas.py --base-url http://127.0.0.1:28422 --context kind-agent-bom-replicas --api-key-file FILE
    python scripts/qualification/kind_replicas.py down

Two settings differ from a production install and are reported as such:
``controlPlane.postgres.verification.enabled=false`` (the in-cluster Postgres
has no TLS, which the verification hook correctly refuses) and an extra
NetworkPolicy rule admitting the node and pod ranges, because the chart's policy
admits only the ingress-nginx namespace and a NodePort is not an ingress.
"""

from __future__ import annotations

import argparse
import base64
import json
import secrets
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import REPO_ROOT  # noqa: E402

CHART = REPO_ROOT / "deploy" / "helm" / "agent-bom"
NODE_PORT = 30422
POSTGRES = {
    "apiVersion": "apps/v1",
    "kind": "Deployment",
    "metadata": {"name": "postgres"},
    "spec": {
        "replicas": 1,
        "selector": {"matchLabels": {"app": "qualification-postgres"}},
        "template": {
            "metadata": {"labels": {"app": "qualification-postgres"}},
            "spec": {
                "containers": [
                    {
                        "name": "postgres",
                        "image": "postgres:16-alpine",
                        "args": ["-c", "max_connections=200"],
                        "env": [
                            {"name": "POSTGRES_USER", "value": "agent_bom"},
                            {"name": "POSTGRES_DB", "value": "agent_bom"},
                            {
                                "name": "POSTGRES_PASSWORD",
                                "valueFrom": {"secretKeyRef": {"name": "qualification-postgres", "key": "password"}},
                            },
                        ],
                        "readinessProbe": {"exec": {"command": ["pg_isready", "-U", "agent_bom", "-d", "agent_bom"]}, "periodSeconds": 2},
                    }
                ]
            },
        },
    },
}


def kind_config(host_port: int) -> dict[str, Any]:
    mapping = {"containerPort": NODE_PORT, "hostPort": host_port, "listenAddress": "127.0.0.1"}
    return {"kind": "Cluster", "apiVersion": "kind.x-k8s.io/v1alpha4", "nodes": [{"role": "control-plane", "extraPortMappings": [mapping]}]}


def chart_values(repository: str, tag: str, replicas: int) -> dict[str, Any]:
    env = [
        {"name": "AGENT_BOM_API_LOCAL_PATH_SCANS", "value": "disabled"},
        {"name": "AGENT_BOM_REQUIRE_SHARED_RATE_LIMIT", "value": "1"},
        {"name": "AGENT_BOM_REQUIRE_SHARED_SCIM_STORE", "value": "1"},
        {"name": "AGENT_BOM_REQUIRE_AUDIT_HMAC", "value": "1"},
        {"name": "AGENT_BOM_SKIP_UPDATE_CHECK", "value": "1"},
    ]
    references = {
        name: {"name": f"agent-bom-control-plane-{suffix}"}
        for name, suffix in (("appSecretRef", "db"), ("maintenanceSecretRef", "maintenance"), ("adminSecretRef", "admin"))
    }
    return {
        "image": {"repository": repository, "tag": tag, "pullPolicy": "Never"},
        "scanner": {"enabled": False},
        "controlPlane": {
            "enabled": True,
            "postgres": {"verification": {"enabled": False}},
            # The kind node and pod ranges reach the NodePort; admitted to the API port only.
            "networkPolicy": {"ingressCIDRs": ["172.16.0.0/12", "10.244.0.0/16"]},
            "postgresSecrets": {"enabled": True, **references},
            "api": {
                "replicas": replicas,
                "service": {"type": "NodePort"},
                "envFrom": [{"secretRef": {"name": "agent-bom-control-plane-auth"}}],
                "listenerAttestation": {"fromSecret": True},
                "env": env,
            },
            "ui": {"enabled": False},
        },
    }


def secret_documents(namespace: str, passwords: dict[str, str], api_key: str) -> list[dict[str, Any]]:
    def secret(name: str, data: dict[str, str]) -> dict[str, Any]:
        return {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": name, "namespace": namespace},
            "type": "Opaque",
            "stringData": data,
        }

    def url(role: str, password: str) -> str:
        return f"postgresql://{role}:{password}@postgres:5432/agent_bom"

    return [
        secret("qualification-postgres", {"password": passwords["admin"]}),
        secret("agent-bom-control-plane-db", {"AGENT_BOM_POSTGRES_URL": url("agent_bom_app", passwords["app"])}),
        secret(
            "agent-bom-control-plane-maintenance",
            {"AGENT_BOM_POSTGRES_MAINTENANCE_URL": url("agent_bom_maintenance", passwords["maintenance"])},
        ),
        secret("agent-bom-control-plane-admin", {"ALEMBIC_DATABASE_URL": url("agent_bom", passwords["admin"])}),
        secret(
            "agent-bom-control-plane-auth",
            {
                "AGENT_BOM_API_KEYS": f"{api_key}:admin",
                "AGENT_BOM_AUDIT_HMAC_KEY": secrets.token_hex(32),
                "AGENT_BOM_BROWSER_SESSION_SIGNING_KEY": secrets.token_hex(32),
                "AGENT_BOM_CONNECTIONS_KEY": base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
                "AGENT_BOM_TRUST_PROXY_AUTH": "1",
                "AGENT_BOM_TRUST_PROXY_AUTH_SECRET": secrets.token_hex(32),
                "AGENT_BOM_TRUST_PROXY_AUTH_ISSUER": "qualification",
            },
        ),
    ]


def run(*command: str, stdin: str | None = None, timeout: float = 900) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(command, input=stdin, capture_output=True, text=True, timeout=timeout)  # noqa: S603
    if completed.returncode != 0:
        raise RuntimeError(f"{' '.join(command[:4])} failed: {completed.stderr[-800:]}")
    return completed


def up(args: argparse.Namespace) -> None:
    context = f"kind-{args.cluster}"
    kubectl = ("kubectl", "--context", context, "-n", args.namespace)
    with tempfile.TemporaryDirectory(prefix="kind-replicas-") as tmp:
        config = Path(tmp) / "kind.json"
        config.write_text(json.dumps(kind_config(args.host_port)), encoding="utf-8")
        run("kind", "create", "cluster", "--name", args.cluster, "--config", str(config), "--wait", "180s")
        archive = Path(tmp) / "image.tar"
        # A single-platform archive: `kind load docker-image` fails on multi-platform containerd-store images.
        run("docker", "save", "--platform", f"linux/{args.platform}", "-o", str(archive), args.image)
        run("kind", "load", "image-archive", str(archive), "--name", args.cluster)
    passwords = {role: secrets.token_hex(16) for role in ("admin", "app", "maintenance")}
    api_key = secrets.token_hex(24)
    args.api_key_file.write_text(api_key, encoding="utf-8")
    args.api_key_file.chmod(0o600)
    run("kubectl", "--context", context, "create", "namespace", args.namespace)
    for document in [*secret_documents(args.namespace, passwords, api_key), POSTGRES]:
        run(*kubectl, "apply", "-f", "-", stdin=json.dumps(document))
    service = {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": "postgres"},
        "spec": {"selector": {"app": "qualification-postgres"}, "ports": [{"port": 5432}]},
    }
    run(*kubectl, "apply", "-f", "-", stdin=json.dumps(service))
    run(*kubectl, "rollout", "status", "deploy/postgres", "--timeout=300s")
    time.sleep(3)
    settings = (
        f"ALTER DATABASE agent_bom SET init.app_password = '{passwords['app']}';"
        f"ALTER DATABASE agent_bom SET init.maintenance_password = '{passwords['maintenance']}';"
    )
    run(*kubectl, "exec", "deploy/postgres", "--", "psql", "-U", "agent_bom", "-d", "agent_bom", "-qc", settings)
    repository, _, tag = args.image.rpartition(":")
    values = Path(args.api_key_file.parent) / "kind-replicas-values.json"
    values.write_text(json.dumps(chart_values(repository, tag, args.replicas)), encoding="utf-8")
    run(
        "helm",
        "--kube-context",
        context,
        "upgrade",
        "--install",
        "agent-bom",
        str(CHART),
        "-n",
        args.namespace,
        "-f",
        str(values),
        "--wait",
        "--timeout",
        "10m",
    )
    patch = json.dumps([{"op": "replace", "path": "/spec/ports/0/nodePort", "value": NODE_PORT}])
    run(*kubectl, "patch", "svc", "agent-bom-api", "--type", "json", "-p", patch)
    print(f"load balancer: http://127.0.0.1:{args.host_port}  context: {context}  api key file: {args.api_key_file}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("action", choices=("up", "down"))
    parser.add_argument("--cluster", default="agent-bom-replicas")
    parser.add_argument("--namespace", default="agent-bom")
    parser.add_argument("--image", default="agent-bom:local", help="API image built from this checkout")
    parser.add_argument(
        "--platform",
        default="arm64"
        if subprocess.run(["uname", "-m"], capture_output=True, text=True).stdout.strip() in {"arm64", "aarch64"}
        else "amd64",
    )
    parser.add_argument("--replicas", type=int, default=3)
    parser.add_argument("--host-port", type=int, default=28422)
    parser.add_argument("--api-key-file", type=Path, default=Path(tempfile.gettempdir()) / "agent-bom-replicas-api-key")
    args = parser.parse_args()
    if args.action == "down":
        subprocess.run(["kind", "delete", "cluster", "--name", args.cluster], check=False)  # noqa: S603, S607
        args.api_key_file.unlink(missing_ok=True)
        return 0
    up(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
