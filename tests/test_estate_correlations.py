"""Tests for GET /v1/estate/correlations."""

from __future__ import annotations

from starlette.testclient import TestClient

from agent_bom.api.server import JobStatus, _get_store, app
from agent_bom.api.store import InMemoryJobStore
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

_AUTH_HEADERS = proxy_headers(tenant="default")


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()


def _clear_jobs() -> None:
    from agent_bom.api.server import set_job_store

    set_job_store(InMemoryJobStore())


def _add_agents_job(
    *, job_id: str = "scan-estate", agents: list[dict], target: str | None = None, result_scan_id: str | None = None
) -> None:
    from agent_bom.api.server import ScanJob, ScanRequest

    job = ScanJob(
        job_id=job_id,
        tenant_id="default",
        created_at="2026-07-04T10:00:00Z",
        request=ScanRequest(),
    )
    job.status = JobStatus.DONE
    job.completed_at = "2026-07-04T10:05:00Z"
    job.result = {"agents": agents, **({"scan_id": result_scan_id} if result_scan_id else {})}
    if target:
        job.target = {"path": target}
    _get_store().put(job)


def test_estate_correlations_empty_without_scans() -> None:
    _clear_jobs()
    client = TestClient(app)
    resp = client.get("/v1/estate/correlations", headers=_AUTH_HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert data["schema_version"] == "estate.correlations.v1"
    assert data["count"] == 0
    assert data["matches"] == []


def test_estate_correlations_returns_bedrock_match() -> None:
    _clear_jobs()
    model = "anthropic.claude-3-5-sonnet-20241022-v2:0"
    arn = "arn:aws:bedrock:us-east-1:111122223333:agent/AGENTID01"
    _add_agents_job(
        agents=[
            {
                "name": "cursor-dev",
                "agent_type": "cursor",
                "config_path": "/home/dev/.cursor/mcp.json",
                "version": "0.42.0",
                "metadata": {},
                "mcp_servers": [
                    {
                        "name": "bedrock-mcp",
                        "env": {
                            "AWS_ACCOUNT_ID": "111122223333",
                            "AWS_REGION": "us-east-1",
                            "BEDROCK_MODEL_ID": model,
                        },
                    }
                ],
            },
            {
                "name": "bedrock:prod-agent",
                "agent_type": "custom",
                "config_path": arn,
                "source": "aws-bedrock",
                "version": model,
                "metadata": {
                    "cloud_origin": {
                        "provider": "aws",
                        "service": "bedrock",
                        "resource_type": "agent",
                        "resource_id": arn,
                        "resource_name": "prod-agent",
                        "location": "us-east-1",
                        "scope": {"account_id": "111122223333"},
                    }
                },
                "mcp_servers": [],
            },
        ],
    )
    client = TestClient(app)
    resp = client.get("/v1/estate/correlations", headers=_AUTH_HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert data["scan_id"] == "current-estate"
    assert data["source_scan_ids"] == ["scan-estate"]
    assert data["count"] >= 1
    assert data["high_confidence_count"] >= 1
    match = data["matches"][0]
    assert match["local_agent_name"] == "cursor-dev"
    assert match["cloud_provider"] == "aws"
    assert match["confidence"] == "high"


def test_estate_correlations_unknown_scan_is_404() -> None:
    _clear_jobs()
    client = TestClient(app)
    resp = client.get("/v1/estate/correlations?scan_id=missing", headers=_AUTH_HEADERS)
    assert resp.status_code == 404


def _bedrock_agents() -> tuple[dict, dict]:
    model = "anthropic.claude-3-5-sonnet-20241022-v2:0"
    arn = "arn:aws:bedrock:us-east-1:111122223333:agent/AGENTID01"
    local = {
        "name": "cursor-dev",
        "agent_type": "cursor",
        "config_path": "/home/dev/.cursor/mcp.json",
        "version": "0.42.0",
        "metadata": {},
        "mcp_servers": [
            {
                "name": "bedrock-mcp",
                "env": {"AWS_ACCOUNT_ID": "111122223333", "AWS_REGION": "us-east-1", "BEDROCK_MODEL_ID": model, "BEDROCK_AGENT_ARN": arn},
            }
        ],
    }
    cloud = {
        "name": "bedrock:prod-agent",
        "agent_type": "custom",
        "config_path": arn,
        "source": "aws-bedrock",
        "version": model,
        "metadata": {
            "cloud_origin": {
                "provider": "aws",
                "service": "bedrock",
                "resource_type": "agent",
                "resource_id": arn,
                "resource_name": "prod-agent",
                "location": "us-east-1",
                "scope": {"account_id": "111122223333"},
            }
        },
        "mcp_servers": [],
    }
    return local, cloud


def test_default_reads_the_current_estate_across_scan_targets() -> None:
    """The laptop scan and the cloud scan are separate current jobs; the newest alone matches nothing."""
    _clear_jobs()
    local, cloud = _bedrock_agents()
    _add_agents_job(job_id="scan-laptop", agents=[local], target="laptop")
    _add_agents_job(job_id="scan-cloud", agents=[cloud], target="aws-account")
    client = TestClient(app)
    data = client.get("/v1/estate/correlations", headers=_AUTH_HEADERS).json()
    assert data["scan_id"] == "current-estate"
    assert sorted(data["source_scan_ids"]) == ["scan-cloud", "scan-laptop"]
    assert data["high_confidence_count"] >= 1
    assert data["matches"][0]["local_agent_name"] == "cursor-dev"
    explicit = client.get("/v1/estate/correlations", headers=_AUTH_HEADERS, params={"scan_id": "scan-cloud"}).json()
    assert explicit["scan_id"] == "scan-cloud" and explicit["count"] == 0


def test_current_estate_and_graph_snapshot_ids_resolve_instead_of_404() -> None:
    _clear_jobs()
    local, cloud = _bedrock_agents()
    _add_agents_job(job_id="demo-job", agents=[local, cloud], result_scan_id="showcase")
    client = TestClient(app)
    for scan_id in ("current-estate", "current-estate:0123456789abcdef0123456789abcdef"):
        data = client.get("/v1/estate/correlations", headers=_AUTH_HEADERS, params={"scan_id": scan_id}).json()
        assert data["scan_id"] == "current-estate" and data["count"] >= 1
    showcase = client.get("/v1/estate/correlations", headers=_AUTH_HEADERS, params={"scan_id": "showcase"})
    assert showcase.status_code == 200
    assert showcase.json()["scan_id"] == "demo-job" and showcase.json()["count"] >= 1
