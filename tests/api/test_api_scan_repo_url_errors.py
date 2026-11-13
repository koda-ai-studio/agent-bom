"""A rejected repo_url is a 4xx with its own safe reason, and a clone failure names the cause."""

from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager

import pytest
from starlette.testclient import TestClient

from agent_bom.api import server as api_server
from agent_bom.api.auth import KeyStore, get_key_store, set_key_store
from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.pipeline import _run_scan_sync
from agent_bom.api.server import app


@pytest.fixture
def admin_client(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    original_store = get_key_store()
    set_key_store(KeyStore())
    monkeypatch.setattr(api_server, "_env_api_keys_seeded", False)
    monkeypatch.setattr(api_server, "_runtime_api_key_seeded", False)
    monkeypatch.setenv("AGENT_BOM_ALLOW_UNAUTHENTICATED_API", "1")
    monkeypatch.delenv("AGENT_BOM_API_KEY", raising=False)
    monkeypatch.delenv("AGENT_BOM_API_KEYS", raising=False)
    monkeypatch.delenv("AGENT_BOM_DEMO_ESTATE", raising=False)
    monkeypatch.setenv("AGENT_BOM_NO_AUTH_ROLE", "admin")
    monkeypatch.setattr("agent_bom.config.DEMO_ESTATE", False)
    api_server.configure_api(api_key=None, allow_unauthenticated=True)
    try:
        with TestClient(app) as client:
            yield client
    finally:
        set_key_store(original_store)
        monkeypatch.setattr(api_server, "_env_api_keys_seeded", False)
        monkeypatch.setattr(api_server, "_runtime_api_key_seeded", False)
        api_server.configure_api(api_key=None)


@pytest.mark.parametrize(
    ("repo_url", "reason"),
    [
        ("file:///etc", "scheme 'file' is not allowed"),
        ("git@github.com:org/repo.git", "must be a full http(s) URL"),
        ("https://user:hunter2@github.com/org/repo", "must not embed credentials"),
    ],
)
def test_post_scan_rejects_unsafe_repo_url_with_its_reason(admin_client: TestClient, repo_url: str, reason: str) -> None:
    response = admin_client.post("/v1/scan", json={"repo_url": repo_url})

    assert response.status_code == 422, response.text
    assert reason in response.text
    assert "internal error" not in response.text.lower()
    assert "hunter2" not in response.text


def test_clone_failure_reports_the_repo_reason_and_logs_a_warning(monkeypatch: pytest.MonkeyPatch, caplog) -> None:
    from agent_bom.repo_scan import RepoScanError

    @contextmanager
    def failing_clone(repo_url: str, *, token_env: str = "", branch: str | None = None):
        raise RepoScanError("clone failed: remote: Repository not found.")
        yield  # pragma: no cover

    monkeypatch.setattr("agent_bom.repo_scan.clone_repository", failing_clone)
    job = ScanJob(
        job_id="repo-clone-fail",
        created_at="2026-01-01T00:00:00Z",
        request=ScanRequest(repo_url="https://github.com/org/missing", no_scan=True),
    )

    with caplog.at_level(logging.WARNING, logger="agent_bom.api.pipeline"):
        _run_scan_sync(job)

    assert job.status == JobStatus.FAILED
    assert job.error is not None
    assert "Repository not found" in job.error
    assert "internal error" not in job.error.lower()
    assert any("Repository not found" in record.getMessage() for record in caplog.records)
