"""Pinned profiles, inventory fixture and mocked upstream for the workflow resource harness.

The fixture is ``scripts/generate_graph_benchmark_estate.py`` at seed 2145. Its
estate is turned into a schema-valid ``--inventory`` file, so the real CLI
collects, scans and enriches it. Every upstream advisory or registry call is
answered by :class:`MockUpstream`, which records counts and bytes. Nothing in
this module reaches the network.
"""

from __future__ import annotations

import json
import threading
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import httpx

ESTATE_SOURCE = "scripts/generate_graph_benchmark_estate.py"
ESTATE_SEED = 2145
# The inventory schema accepts these ecosystems; the estate also emits OCI
# image references, which an inventory cannot carry and are left out.
INVENTORY_ECOSYSTEMS = frozenset({"npm", "pypi", "go", "maven"})
_AGENT_TYPES = {"vscode": "vscode-copilot"}


@dataclass(frozen=True)
class WorkflowProfile:
    """One reproducible workload: fixture size, concurrency and the resource envelope it must fit."""

    name: str
    description: str
    agents: int
    seed: int
    vulnerable_package_rate: float
    store: str
    api_replicas: int
    concurrent_pushes: int
    query_repeats: int
    cpu_limit: float
    memory_limit_mib: int

    def as_dict(self) -> dict[str, Any]:
        return {**asdict(self), "source": ESTATE_SOURCE}


PROFILES: dict[str, WorkflowProfile] = {
    profile.name: profile
    for profile in (
        WorkflowProfile(
            name="ci-budget",
            description="PR regression budget: smallest estate that still yields findings, graph paths and an export",
            agents=12,
            seed=ESTATE_SEED,
            vulnerable_package_rate=0.08,
            store="sqlite",
            api_replicas=1,
            concurrent_pushes=1,
            query_repeats=8,
            cpu_limit=2.0,
            memory_limit_mib=2048,
        ),
        WorkflowProfile(
            name="small-self-hosted",
            description="One API process on SQLite, sized to the pilot Helm request (2 CPU, 2 GiB limit)",
            agents=200,
            seed=ESTATE_SEED,
            vulnerable_package_rate=0.08,
            store="sqlite",
            api_replicas=1,
            concurrent_pushes=1,
            query_repeats=30,
            cpu_limit=2.0,
            memory_limit_mib=2048,
        ),
        WorkflowProfile(
            name="small-self-hosted-postgres",
            description="Same workload as small-self-hosted against a private Postgres 16 cluster",
            agents=200,
            seed=ESTATE_SEED,
            vulnerable_package_rate=0.08,
            store="postgres",
            api_replicas=1,
            concurrent_pushes=1,
            query_repeats=30,
            cpu_limit=2.0,
            memory_limit_mib=2048,
        ),
        WorkflowProfile(
            name="large-push-sqlite",
            description="One 1,000-agent push on SQLite, measured against the same 2 GiB pilot limit",
            agents=1000,
            seed=ESTATE_SEED,
            vulnerable_package_rate=0.08,
            store="sqlite",
            api_replicas=1,
            concurrent_pushes=1,
            query_repeats=5,
            cpu_limit=2.0,
            memory_limit_mib=2048,
        ),
        WorkflowProfile(
            name="multi-replica-local",
            description="Two API processes sharing one Postgres, each pushing its own estate concurrently",
            agents=200,
            seed=ESTATE_SEED,
            vulnerable_package_rate=0.08,
            store="postgres",
            api_replicas=2,
            concurrent_pushes=2,
            query_repeats=30,
            cpu_limit=2.0,
            memory_limit_mib=2048,
        ),
    )
}


def _inventory_server(server: dict[str, Any]) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "name": server["name"],
        "transport": server["transport"],
        "env": {name: "redacted-placeholder" for name in server.get("credential_env_vars", [])},
        "tools": [{"name": tool["name"]} for tool in server.get("tools", [])],
        "packages": [
            {"name": package["name"], "version": package["version"], "ecosystem": package["ecosystem"]}
            for package in server.get("packages", [])
            if package["ecosystem"] in INVENTORY_ECOSYSTEMS
        ],
    }
    if server.get("url"):
        entry["url"] = server["url"]
    else:
        entry["command"] = "npx"
    return entry


def inventory_from_estate(report: dict[str, Any]) -> dict[str, Any]:
    """Return an ``--inventory`` document carrying the estate's agents, servers, tools and packages."""
    return {
        "schema_version": "1",
        "source": "workflow-resource-benchmark",
        "agents": [
            {
                "name": agent["name"],
                "agent_type": _AGENT_TYPES.get(agent["type"], agent["type"]),
                "source": agent.get("source", "operator-push"),
                "mcp_servers": [_inventory_server(server) for server in agent["mcp_servers"]],
            }
            for agent in report["agents"]
        ],
    }


WORKFLOW_PUSH_SOURCE_ID = "workflow-benchmark-host"
# The operator's inventory file. Every phase scans a copy, but the push scope models
# one host re-running one command, so a later push replaces the earlier one.
WORKFLOW_INVENTORY_TARGET = Path("/srv/agent-bom/inventory.json")


def cli_push_body(
    report_bytes: bytes, inventory_target: Path = WORKFLOW_INVENTORY_TARGET, *, source_id: str = WORKFLOW_PUSH_SOURCE_ID
) -> bytes:
    """The body ``agent-bom agents --inventory PATH --no-discover --push-url`` sends for this report.

    The CLI sanitizes the report, adds the endpoint ``source_id`` and the
    ``target_scope`` it hashes from the inventory path and collection options, so
    a later push of the same inventory path replaces this one. The content
    idempotency key the CLI also adds is left out: the harness sets keys per push.
    """
    from types import SimpleNamespace

    from agent_bom.evidence.push_scope import cli_target_scope
    from agent_bom.push import sanitize_results

    scope = cli_target_scope(SimpleNamespace(inventory=str(inventory_target), no_discover=True))
    body = sanitize_results({**json.loads(report_bytes), "target_scope": scope}, source_id=source_id)
    body.pop("idempotency_key", None)
    return json.dumps(body).encode()


def vulnerable_versions(report: dict[str, Any]) -> dict[tuple[str, str], str]:
    """Map each vulnerable ``(package, version)`` the estate declares to its advisory id."""
    return {(row["package_name"], row["package_version"]): row["vulnerability_id"] for row in report["blast_radius"]}


def expected_findings(report: dict[str, Any], inventory: dict[str, Any]) -> set[tuple[str, str, str]]:
    """The ``(advisory, package, version)`` set a correct scan of ``inventory`` must report."""
    vulnerable = vulnerable_versions(report)
    present = {
        (package["name"], package["version"])
        for agent in inventory["agents"]
        for server in agent["mcp_servers"]
        for package in server["packages"]
    }
    return {(vuln_id, name, version) for (name, version), vuln_id in vulnerable.items() if (name, version) in present}


_OSV_ECOSYSTEM = {"npm": "npm", "pypi": "PyPI", "go": "Go", "maven": "Maven"}


class MockUpstream:
    """``httpx.MockTransport`` handler standing in for OSV, registries and advisory feeds.

    OSV answers the estate's declared vulnerable versions with one advisory each and
    serves its detail record. Every other host returns 404, the answer for an unknown
    package. ``fail_first_batches`` returns 503 to the first OSV batch calls so the
    client retry path runs.
    """

    def __init__(self, *, vulnerable: dict[tuple[str, str], str], fail_first_batches: int = 0) -> None:
        self._vulnerable = vulnerable
        self._fail_remaining = fail_first_batches
        self._details: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._by_host: Counter[str] = Counter()
        self._by_endpoint: Counter[str] = Counter()
        self._requests = 0
        self._request_bytes = 0
        self._response_bytes = 0
        self._injected = 0

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self)

    def __call__(self, request: httpx.Request) -> httpx.Response:
        response = self._answer(request)
        with self._lock:
            self._requests += 1
            self._by_host[request.url.host] += 1
            self._by_endpoint[_endpoint(request)] += 1
            self._request_bytes += len(request.content or b"")
            self._response_bytes += len(response.content)
        return response

    def _answer(self, request: httpx.Request) -> httpx.Response:
        if request.url.host != "api.osv.dev":
            return httpx.Response(404, json={"error": "not found"})
        path = request.url.path
        if path.endswith("/querybatch"):
            with self._lock:
                if self._fail_remaining > 0:
                    self._fail_remaining -= 1
                    self._injected += 1
                    return httpx.Response(503, json={"error": "injected"})
            queries = json.loads(request.content or b"{}").get("queries", [])
            return httpx.Response(200, json={"results": [self._batch_row(query) for query in queries]})
        if path.startswith("/v1/vulns/"):
            detail = self._details.get(path.rsplit("/", 1)[-1])
            return httpx.Response(200, json=detail) if detail else httpx.Response(404, json={"error": "not found"})
        return httpx.Response(404, json={"error": "not found"})

    def _batch_row(self, query: dict[str, Any]) -> dict[str, Any]:
        package = query.get("package", {})
        name, ecosystem, version = package.get("name", ""), package.get("ecosystem", ""), query.get("version", "")
        # Go module versions are queried with their canonical "v" prefix.
        vuln_id = self._vulnerable.get((name, version)) or self._vulnerable.get((name, version.removeprefix("v")))
        if not vuln_id:
            return {}
        with self._lock:
            self._details.setdefault(vuln_id, _osv_record(vuln_id, name, ecosystem, version))
        return {"vulns": [{"id": vuln_id, "modified": "2026-10-01T00:00:00Z"}]}

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "requests": self._requests,
                "by_host": dict(sorted(self._by_host.items())),
                "by_endpoint": dict(sorted(self._by_endpoint.items())),
                "request_bytes": self._request_bytes,
                "response_bytes": self._response_bytes,
                "injected_failures": self._injected,
            }


def _endpoint(request: httpx.Request) -> str:
    path = request.url.path
    if request.url.host == "api.osv.dev":
        return "osv:" + ("querybatch" if path.endswith("/querybatch") else "vuln-detail" if "/vulns/" in path else path)
    return f"{request.url.host}:{request.method}"


def _osv_record(vuln_id: str, name: str, ecosystem: str, version: str) -> dict[str, Any]:
    return {
        "id": vuln_id,
        "summary": f"Synthetic advisory for {name} {version}",
        "details": "Deterministic workflow-benchmark advisory.",
        "aliases": [],
        "modified": "2026-10-01T00:00:00Z",
        "published": "2026-09-01T00:00:00Z",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "affected": [
            {
                "package": {"name": name, "ecosystem": _OSV_ECOSYSTEM.get(ecosystem.lower(), ecosystem)},
                "versions": [version],
                "ranges": [{"type": "SEMVER" if ecosystem == "Go" else "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "999.0.0"}]}],
            }
        ],
        "references": [{"type": "WEB", "url": f"https://example.invalid/advisories/{vuln_id}"}],
    }
