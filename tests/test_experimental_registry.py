"""One experimental-feature registry; trace features are off until opted in."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner
from starlette.testclient import TestClient

from agent_bom.core import experimental
from agent_bom.storage.tiers import BACKEND_TIERS, StorageTier
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

ROOT = Path(__file__).resolve().parents[1]


def _load_generator():
    name = "generate_experimental_docs"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / "generate_experimental_docs.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_every_entry_has_an_existing_doc_and_unique_id() -> None:
    ids = [feature.id for feature in experimental.EXPERIMENTAL_FEATURES]
    assert len(ids) == len(set(ids))
    for feature in experimental.EXPERIMENTAL_FEATURES:
        assert (ROOT / feature.doc).is_file(), f"{feature.id}: {feature.doc} missing"
        assert feature.surfaces and set(feature.surfaces) <= {"cli", "api", "mcp", "ui"}
        assert feature.title and feature.enabled_by


def test_traces_off_by_default_and_enabled_by_the_single_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(experimental.EXPERIMENTAL_ENV, raising=False)
    assert experimental.is_enabled("traces") is False
    monkeypatch.setenv(experimental.EXPERIMENTAL_ENV, "other, Traces ")
    assert experimental.is_enabled("traces") is True
    monkeypatch.setenv(experimental.EXPERIMENTAL_ENV, "all")
    assert experimental.is_enabled("traces") is True
    assert experimental.is_enabled("consequence-assessment") is True
    message = experimental.disabled_message("traces")
    assert "experimental" in message and "AGENT_BOM_EXPERIMENTAL=traces" in message


def test_storage_tiers_read_experimental_backends_from_registry() -> None:
    experimental_backends = {b for b, tier in BACKEND_TIERS.items() if tier is StorageTier.EXPERIMENTAL}
    assert experimental_backends == {"snowflake", "neptune"}


def test_generated_doc_is_current_and_lists_every_feature() -> None:
    gen = _load_generator()
    assert gen.main(["--check"]) == 0
    text = (ROOT / "docs" / "EXPERIMENTAL.md").read_text(encoding="utf-8")
    for feature in experimental.EXPERIMENTAL_FEATURES:
        assert f"`{feature.id}`" in text


def test_check_mode_fails_on_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    gen = _load_generator()
    stale = tmp_path / "EXPERIMENTAL.md"
    stale.write_text("stale\n", encoding="utf-8")
    monkeypatch.setattr(gen, "DOC_FILE", stale)
    assert gen.main(["--check"]) == 1


def test_doctor_json_lists_experimental_features(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.cli._doctor import _experimental_checks

    monkeypatch.delenv(experimental.EXPERIMENTAL_ENV, raising=False)
    rows = {label: value for label, value, _ in _experimental_checks()}
    assert set(rows) == {feature.id for feature in experimental.EXPERIMENTAL_FEATURES}
    assert rows["traces"].startswith("disabled — enable with AGENT_BOM_EXPERIMENTAL=traces")


def test_doctor_human_output_has_experimental_section(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.cli._doctor import doctor_cmd

    monkeypatch.delenv(experimental.EXPERIMENTAL_ENV, raising=False)
    result = CliRunner().invoke(doctor_cmd, ["--offline"])
    assert "Experimental features" in result.output
    assert "AGENT_BOM_EXPERIMENTAL=traces" in result.output


@pytest.fixture
def client():
    from agent_bom.api.server import app, set_job_store
    from agent_bom.api.store import InMemoryJobStore

    enable_trusted_proxy_env()
    set_job_store(InMemoryJobStore())
    try:
        yield TestClient(app)
    finally:
        disable_trusted_proxy_env()


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("get", "/v1/traces/connectors", None),
        ("post", "/v1/traces/connectors/langfuse/pull", {"limit": 1}),
        ("post", "/v1/traces/attack-paths", {"resourceSpans": []}),
        ("post", "/v1/traces/connectors/langfuse/collect", {"connection_id": "c1"}),
        ("get", "/v1/traces/connectors/langfuse/collection?connection_id=c1", None),
    ],
)
def test_trace_routes_answer_disabled_not_empty(client, monkeypatch: pytest.MonkeyPatch, method: str, path: str, body) -> None:
    monkeypatch.delenv(experimental.EXPERIMENTAL_ENV, raising=False)
    headers = proxy_headers(role="admin", tenant="tenant-a")
    response = getattr(client, method)(path, headers=headers, **({"json": body} if body is not None else {}))
    assert response.status_code == 404, response.text
    assert "AGENT_BOM_EXPERIMENTAL=traces" in json.dumps(response.json())


def test_trace_connectors_list_works_when_enabled(client, enable_experimental_traces) -> None:
    response = client.get("/v1/traces/connectors", headers=proxy_headers(role="admin", tenant="tenant-a"))
    assert response.status_code == 200
    assert response.json()["schema_version"] == "observability.trace_connectors.v1"


def test_system_health_reports_experimental_state(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(experimental.EXPERIMENTAL_ENV, raising=False)
    payload = client.get("/v1/system/health", headers=proxy_headers(role="admin", tenant="tenant-a")).json()
    by_id = {item["id"]: item for item in payload["experimental_features"]}
    assert by_id["traces"]["enabled"] is False and by_id["traces"]["flag_gated"] is True
    assert by_id["storage-snowflake"]["enabled"] is None, "an opt-in the flag does not control is not reported as on"
    monkeypatch.setenv(experimental.EXPERIMENTAL_ENV, "traces")
    payload = client.get("/v1/system/health", headers=proxy_headers(role="admin", tenant="tenant-a")).json()
    assert {item["id"]: item for item in payload["experimental_features"]}["traces"]["enabled"] is True


def test_graph_overlay_skips_trace_events_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.api.trace_collection.trace_evidence import emit_shadow_findings, with_trace_events

    monkeypatch.delenv(experimental.EXPERIMENTAL_ENV, raising=False)
    report = {"scan_id": "s1"}
    assert with_trace_events(report, "tenant-a") is report
    assert emit_shadow_findings(object(), "tenant-a", None) == 0  # type: ignore[arg-type]


@pytest.mark.asyncio
@pytest.mark.parametrize("enabled,status_code", [(False, 404), (True, 200)])
async def test_feature_gate_does_not_wait_for_storage_workers(monkeypatch, enabled, status_code):
    import asyncio
    import threading

    import anyio.to_thread
    import httpx
    from fastapi import FastAPI

    from agent_bom.api.experimental_gate import require_experimental

    monkeypatch.setenv("AGENT_BOM_EXPERIMENTAL", "traces" if enabled else "")
    app = FastAPI()
    calls = []

    @app.get("/feature", dependencies=[require_experimental("traces")])
    async def feature():
        calls.append("served")
        return {"enabled": True}

    limiter = anyio.to_thread.current_default_thread_limiter()
    before = limiter.total_tokens
    limiter.total_tokens = 1
    entered, release = threading.Event(), threading.Event()

    def occupied():
        entered.set()
        assert release.wait(10)

    worker = asyncio.create_task(anyio.to_thread.run_sync(occupied))
    try:
        assert await asyncio.to_thread(entered.wait, 2)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://test") as client:
            response = await asyncio.wait_for(client.get("/feature"), 1)
        assert response.status_code == status_code
        assert calls == (["served"] if enabled else [])
    finally:
        release.set()
        await worker
        limiter.total_tokens = before
