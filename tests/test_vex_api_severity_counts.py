"""A pushed scan's VEX-suppressed finding stays out of the exec counts nav badges and the overview read."""

from __future__ import annotations

from starlette.testclient import TestClient

from agent_bom.api.server import app
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()


def setup_function() -> None:
    from agent_bom.api.server import set_job_store
    from agent_bom.api.store import InMemoryJobStore

    set_job_store(InMemoryJobStore())


def _row(cve: str, **extra: object) -> dict[str, object]:
    return {
        "vulnerability_id": cve,
        "severity": "critical",
        "cvss_score": 9.8,
        "package": "langchain@0.0.150",
        "affected_servers": ["srv"],
        "affected_agents": ["agent"],
        "risk_score": 9.0,
        **extra,
    }


def test_operator_vex_suppressed_finding_leaves_posture_counts_and_overview() -> None:
    client = TestClient(app)
    headers = proxy_headers(role="admin", tenant="tenant-vex-counts")
    report = {
        "source_id": "vex-unit",
        "blast_radius": [
            _row(
                "CVE-2023-36258",
                vex_status="not_affected",
                vex_source="operator",
                vex_justification="vulnerable_code_not_in_execute_path",
            ),
            _row("CVE-2023-29374"),
        ],
    }
    assert client.post("/v1/results/push", json=report, headers=headers).status_code == 201

    counts = client.get("/v1/posture/counts", headers=headers).json()
    assert counts["critical"] == 1, counts
    headline = client.get("/v1/overview", headers=headers).json()["headline"]
    assert headline["critical"] == 1, headline
