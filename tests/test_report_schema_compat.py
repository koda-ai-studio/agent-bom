"""Report schema 2.0 compatibility: CLI output, push in both directions, and the trust boundary."""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
from click.testing import CliRunner
from starlette.testclient import TestClient

from agent_bom.api.server import app, set_job_store
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import _get_store, _get_trend_store, set_trend_store
from agent_bom.baseline import InMemoryTrendStore
from agent_bom.output.report_packing import (
    REPORT_SCHEMA_V1,
    REPORT_SCHEMA_V2,
    UNTRUSTED_MAX_EXPANDED_BYTES,
    expand_report,
    pack_report,
)
from agent_bom.push import RESULT_PUSH_JSONB_CEILING_BYTES, negotiate_push_report_format


def _scan(out: Path, *extra: str) -> dict:
    from agent_bom.cli import main

    result = CliRunner().invoke(
        main,
        ["scan", "--offline", "--no-auto-update-db", "--quiet", "--demo", "--format", "json", "--output", str(out), *extra],
        catch_exceptions=False,
    )
    assert out.is_file(), result.output
    return json.loads(out.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def reports(tmp_path_factory) -> tuple[dict, dict]:
    root = tmp_path_factory.mktemp("report-schema")
    return _scan(root / "legacy.json"), _scan(root / "v2.json", "--report-format", "v2")


_DEMO_DIR = re.compile(r"agent-bom-demo-dir-[A-Za-z0-9_]+")


def _without_run_identity(doc: dict) -> dict:
    """Two scans differ only in when they ran; compare everything else."""
    volatile = {"generated_at", "scan_id", "scan_run", "scan_performance", "first_seen", "sla_due_at", "observed_at", "observed_at_unix"}

    def strip(value):
        if isinstance(value, dict):
            return {_DEMO_DIR.sub("<demo>", key): strip(child) for key, child in value.items() if key not in volatile}
        if isinstance(value, list):
            return [strip(child) for child in value]
        return _DEMO_DIR.sub("<demo>", value) if isinstance(value, str) else value

    return strip(doc)


def test_cli_writes_schema_one_by_default_and_two_on_request(reports, tmp_path: Path) -> None:
    legacy, packed = reports
    alias = _scan(tmp_path / "alias.json", "--report-format", "legacy")

    assert alias["schema_version"] == REPORT_SCHEMA_V1 and "packing" not in alias

    assert legacy["schema_version"] == REPORT_SCHEMA_V1 and "packing" not in legacy
    assert packed["schema_version"] == REPORT_SCHEMA_V2 and packed["packing"]["transforms"]
    assert all("controls" not in row for row in packed["findings"])
    assert len(json.dumps(packed, indent=2)) < len(json.dumps(legacy, indent=2))


def test_exported_v2_expands_to_the_exported_legacy_report(tmp_path: Path) -> None:
    """One report through the redacting file writer in both formats: redaction and packing commute."""
    from agent_bom.output.json_fmt import export_json, to_json
    from tests.test_report_packing import _report

    report = _report()
    report_json = to_json(report)
    export_json(report, str(tmp_path / "legacy.json"), report_json=report_json, report_format="legacy")
    export_json(report, str(tmp_path / "v2.json"), report_json=report_json, report_format="v2")
    legacy = json.loads((tmp_path / "legacy.json").read_text(encoding="utf-8"))
    packed = json.loads((tmp_path / "v2.json").read_text(encoding="utf-8"))

    assert packed["schema_version"] == REPORT_SCHEMA_V2
    assert expand_report(packed) == legacy
    assert pack_report(legacy) == packed


def test_cli_v2_report_expands_to_a_complete_legacy_report(reports) -> None:
    legacy, packed = reports
    restored = expand_report(packed)

    assert set(restored) == set(legacy)
    assert len(restored["findings"]) == len(legacy["findings"])
    assert {row["finding_type"] for row in restored["findings"]} == {row["finding_type"] for row in legacy["findings"]}
    assert sum(len(row.get("controls") or []) for row in restored["findings"]) == sum(
        len(row.get("controls") or []) for row in legacy["findings"]
    )


# ── push: old client -> new server, new client -> new server, bounds ──────────


@pytest.fixture
def server():
    original_trends = _get_trend_store()
    set_trend_store(InMemoryTrendStore())
    set_job_store(InMemoryJobStore())
    try:
        yield TestClient(app)
    finally:
        set_trend_store(original_trends)


def _stored_result(client: TestClient, payload: dict) -> dict:
    response = client.post("/v1/results/push", json=payload)
    assert response.status_code == 201, response.text
    job = _get_store().get(response.json()["job_id"], "default")
    assert job is not None
    return job.result


def test_server_stores_the_same_result_for_a_v1_and_a_v2_push(server, reports) -> None:
    legacy, _ = reports
    old_client = {**copy.deepcopy(legacy), "source_id": "laptop-a", "scan_id": "push-v1"}
    new_client = {**pack_report(copy.deepcopy(legacy)), "source_id": "laptop-a", "scan_id": "push-v2"}

    stored_v1 = _stored_result(server, old_client)
    stored_v2 = _stored_result(server, new_client)

    assert stored_v2["schema_version"] == REPORT_SCHEMA_V1
    assert "packing" not in stored_v2 and "compliance_controls" not in stored_v2
    same = {"scan_id": "x", "graph_persistence": {**stored_v1["graph_persistence"], "scan_id": "x"}}
    assert {**stored_v2, **same} == {**stored_v1, **same}


def test_server_rejects_a_v2_push_with_a_dangling_reference(server, reports) -> None:
    legacy, _ = reports
    payload = pack_report(copy.deepcopy(legacy))
    payload["findings"][0]["control_refs"] = ["iso_27001:A.0:deadbeef"]

    response = server.post("/v1/results/push", json=payload)

    assert response.status_code == 422
    assert "unknown compliance control" in response.text


def test_server_refuses_a_v2_push_that_expands_past_the_storage_ceiling(server, reports) -> None:
    legacy, _ = reports
    payload = pack_report(copy.deepcopy(legacy))
    ref = payload["findings"][0]["control_refs"][0]
    payload["findings"][0]["control_refs"] = [ref] * 20_000

    with patch("agent_bom.api.push_receive.UNTRUSTED_MAX_EXPANDED_BYTES", 2_000_000):
        response = server.post("/v1/results/push", json=payload)

    assert response.status_code == 413
    assert "expands beyond" in response.text


def test_expansion_ceiling_matches_the_push_storage_ceiling() -> None:
    assert UNTRUSTED_MAX_EXPANDED_BYTES == RESULT_PUSH_JSONB_CEILING_BYTES


def test_version_endpoint_advertises_report_schemas(server) -> None:
    body = server.get("/version").json()
    assert body["report_schema_versions"] == [REPORT_SCHEMA_V1, REPORT_SCHEMA_V2]


class _VersionClient:
    def __init__(self, response: httpx.Response | Exception, seen: list[str]) -> None:
        self.response, self.seen = response, seen

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc) -> None:
        return None

    async def get(self, url: str, headers=None):
        self.seen.append(url)
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        pytest.param(httpx.Response(200, json={"version": "0.115.0", "report_schema_versions": ["1.0", "2.0"]}), "v2", id="new-server"),
        pytest.param(httpx.Response(200, json={"version": "0.114.0", "api_version": "v1"}), "legacy", id="old-server"),
        pytest.param(httpx.Response(404, text="not found"), "legacy", id="no-version-route"),
        pytest.param(httpx.ConnectError("refused"), "legacy", id="unreachable"),
    ],
)
def test_client_pushes_schema_two_only_to_a_server_that_lists_it(response, expected) -> None:
    seen: list[str] = []
    with (
        patch("agent_bom.http_client.create_client", return_value=_VersionClient(response, seen)),
        patch("agent_bom.push._validate_push_destination_url"),
    ):
        assert negotiate_push_report_format("https://cp.example.com/prefix/v1/results/push", "key") == expected
    assert seen == ["https://cp.example.com/prefix/version"]


def test_legacy_flag_never_probes_and_pushes_schema_one() -> None:
    with patch("agent_bom.http_client.create_client", side_effect=AssertionError("no probe")):
        assert negotiate_push_report_format("https://cp.example.com/v1/results/push", requested="legacy") == "legacy"


@pytest.mark.parametrize(
    ("version_body", "expected_schema"),
    [
        pytest.param({"version": "0.114.0", "api_version": "v1"}, REPORT_SCHEMA_V1, id="old-server-gets-1.0"),
        pytest.param({"version": "0.115.0", "report_schema_versions": ["1.0", "2.0"]}, REPORT_SCHEMA_V2, id="new-server-gets-2.0"),
    ],
)
def test_scan_push_sends_the_schema_the_server_accepts(version_body, expected_schema) -> None:
    from rich.console import Console

    from agent_bom.cli.agents._context import ScanContext
    from agent_bom.cli.agents._post import _push_report
    from tests.test_report_packing import _report

    sent: list[dict] = []

    def fake_push(push_url, results, api_key=None):
        sent.append(results)
        return True

    with (
        patch("agent_bom.http_client.create_client", return_value=_VersionClient(httpx.Response(200, json=version_body), [])),
        patch("agent_bom.push.push_results", side_effect=fake_push),
        patch("agent_bom.push._validate_push_destination_url"),
    ):
        assert _push_report(ScanContext(con=Console(quiet=True)), _report(), "https://cp.example.com", "key", quiet=True)

    assert sent[0]["schema_version"] == expected_schema
    restored = expand_report(sent[0])
    assert any(row.get("controls") for row in restored["findings"])
