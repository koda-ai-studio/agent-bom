"""Serialization and projection contracts recorded before domain extraction.

Update only for an intended contract change with
``AGENT_BOM_UPDATE_DOMAIN_GOLDENS=1 pytest tests/test_domain_split_characterization.py``.
The scan, discovery, proxy, AST and OCI characterization suites cover the
side-effecting entry points; this fixture covers shared models and projections.
"""

from __future__ import annotations

import dataclasses
import hashlib
import importlib
import json
import os
import runpy
from pathlib import Path

import pytest

FIXTURE = Path(__file__).parent / "fixtures" / "domain_contracts.json"


def test_published_schema_catalog_includes_lazy_domain_models():
    root = Path(__file__).resolve().parents[1]
    generator = runpy.run_path(str(root / "scripts" / "generate_v1_schemas.py"))
    published = json.loads((root / "docs" / "schemas" / "v1" / "index.json").read_text())
    classes = generator["_public_models"]()
    assert [model.__name__ for model in classes] == [model["name"] for model in published["models"]]
    for model in classes:
        expected = json.loads((root / "docs" / "schemas" / "v1" / f"{model.__name__}.json").read_text())
        assert model.model_json_schema(mode="serialization") == expected


def _assert_golden(name, actual):
    actual = json.loads(json.dumps(actual, sort_keys=True, default=str))
    golden = json.loads(FIXTURE.read_text()) if FIXTURE.exists() else {}
    if os.environ.get("AGENT_BOM_UPDATE_DOMAIN_GOLDENS") == "1":
        golden[name] = actual
        FIXTURE.write_text(json.dumps(golden, indent=2, sort_keys=True) + "\n")
    assert actual == golden[name]


def test_model_schema_contracts():
    from agent_bom.api.models import ScanJob, ScanRequest
    from agent_bom.models import Agent, AIBOMReport, BlastRadius, MCPServer, MCPTool, Package, Vulnerability

    models = [ScanJob, ScanRequest, Agent, AIBOMReport, BlastRadius, MCPServer, MCPTool, Package, Vulnerability]
    actual = {}
    for model in models:
        if dataclasses.is_dataclass(model):
            actual[model.__name__] = {"fields": [field.name for field in dataclasses.fields(model)]}
            continue
        schema = model.model_json_schema()
        actual[model.__name__] = {
            "fields": list(model.model_fields),
            "schema_sha256": hashlib.sha256(json.dumps(schema, sort_keys=True).encode()).hexdigest(),
        }
    _assert_golden("model_schemas", actual)


def test_finding_projections():
    from agent_bom.finding import cloud_cis_check_to_finding, iac_finding_to_finding, secret_dict_to_finding

    actual = {
        "cloud": [
            cloud_cis_check_to_finding(
                {"check_id": "1.1", "title": "Root MFA", "status": status, "severity": "high", "resource": "account-a"},
                "aws",
            ).to_dict()
            for status in ["FAIL", "ERROR", "PASS"]
        ],
        "iac": iac_finding_to_finding(
            {"rule_id": "TF-001", "title": "Public bucket", "severity": "high", "file": "main.tf", "line": 7}
        ).to_dict(),
        "secret": secret_dict_to_finding(
            {"rule_id": "token", "severity": "high", "file": "app.py", "line": 8, "value": "sample-redacted-value"}
        ).to_dict(),
    }
    _assert_golden("finding_projections", actual)


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_hub_pagination_contract(kind, tmp_path):
    from agent_bom.api.compliance_hub_store import InMemoryComplianceHubStore, SQLiteComplianceHubStore

    store = InMemoryComplianceHubStore() if kind == "memory" else SQLiteComplianceHubStore(str(tmp_path / "hub.db"))
    rows = [
        {
            "id": f"finding-{i}",
            "source": "fixture",
            "origin": "bulk_ingest",
            "scan_id": "scan-a",
            "severity": severity,
            "effective_reach_score": i * 3.0,
            "cvss_score": float(i),
            "status": "resolved" if i == 1 else "open",
            "created_at": "2026-01-01T00:00:00Z",
        }
        for i, severity in enumerate(["low", "high", "critical", "medium"])
    ]
    store.add("tenant-a", rows)
    store.add("tenant-b", [{**rows[0], "id": "other-tenant"}])
    actual = {}
    for severity in [None, "critical", "low", "high"]:
        page, total = store.list_page("tenant-a", limit=2, sort="effective_reach", severity=severity)
        actual[str(severity)] = {"ids": [row["id"] for row in page], "total": total}
    actual["severity"] = store.severity_breakdown("tenant-a")
    _assert_golden(f"hub_{kind}", actual)


def test_runtime_and_connection_projections():
    proxy = importlib.import_module("agent_bom.api.routes.proxy")
    connections = importlib.import_module("agent_bom.api.routes.cloud_connections")
    alerts = [
        {
            "ts": "2026-01-01T00:00:00Z",
            "detector": "policy",
            "severity": "high",
            "decision": "deny",
            "message": "blocked",
            "details": {"action": "blocked"},
        },
        {"ts": "2026-01-02T00:00:00Z", "detector": "redact", "severity": "low", "decision": "allow"},
    ]
    _assert_golden(
        "runtime_and_connections",
        {
            "alerts": proxy._summarize_proxy_alerts(alerts),
            "authorization": proxy._authorization_trace(allowed_tool_calls=3, blocked_tool_calls=2, alerts=alerts),
            "scope": [connections._validate_inventory_scope(value) for value in [None, "account", "organization"]],
            "mode": [connections._validate_scan_mode(value) for value in [None, "full", "continuous"]],
            "regions": connections._validate_regions([" us-east-1 ", "eu-west-1"]),
        },
    )
