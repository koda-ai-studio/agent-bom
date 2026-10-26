"""An unknown browser URL outside /v1 is a 404 page, not a JSON authorization error."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("fastapi", reason="fastapi not installed")

from fastapi.testclient import TestClient

from agent_bom.api import dashboard_not_found
from agent_bom.api.server import app


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


def test_unknown_page_serves_the_dashboard_404(client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "404.html").write_text("<!doctype html><title>Page not found</title><h1>This page could not be found</h1>")
    monkeypatch.setattr(dashboard_not_found, "dashboard_dist_dir", lambda: tmp_path)
    response = client.get("/definitely-not-a-page")
    assert response.status_code == 404
    assert response.headers["content-type"].startswith("text/html")
    assert "This page could not be found" in response.text
    assert "authorization policy" not in response.text
    assert client.head("/definitely-not-a-page").status_code == 404


def test_unknown_page_without_a_bundle_is_a_plain_404(client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dashboard_not_found, "dashboard_dist_dir", lambda: tmp_path / "absent")
    response = client.get("/definitely-not-a-page")
    assert response.status_code == 404
    assert "authorization policy" not in response.text


def test_api_and_write_requests_keep_the_fail_closed_policy_answer(client: TestClient) -> None:
    assert client.post("/definitely-not-a-page").status_code == 403
    unknown_api = client.get("/v1/definitely-not-an-endpoint")
    assert unknown_api.status_code in {403, 404}
    assert unknown_api.headers["content-type"].startswith("application/json")
